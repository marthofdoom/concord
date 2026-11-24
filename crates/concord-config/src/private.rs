//! Files holding credentials: readable only by their owner, replaced atomically.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::ConfigError;

/// Far more than any estate needs; stops a wrong path reading something huge.
const MAX_FILE: u64 = 1 << 20;

/// The text of a credential file, refused unless it is a regular file with no
/// access for group or others, owned by root or the user running this.
pub fn read_private(path: &Path) -> Result<Zeroizing<String>, ConfigError> {
    let read_err = |source| ConfigError::Read {
        path: path.to_path_buf(),
        source,
    };
    let refuse = |reason: &str| ConfigError::SecretsFile {
        path: path.to_path_buf(),
        reason: reason.to_string(),
    };

    // Opened once, and everything after is asked of the descriptor: checking
    // the path and then opening it would let the file be swapped in between.
    let file = open(path).map_err(read_err)?;
    let meta = file.metadata().map_err(read_err)?;
    if !meta.is_file() {
        return Err(refuse("not a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        // The owner can rewrite the file or reopen its mode, so it has to be
        // someone who could act as this process anyway.
        // SAFETY: geteuid has no preconditions and cannot fail.
        let euid = unsafe { libc::geteuid() };
        if !trusted_owner(meta.uid(), euid) {
            return Err(refuse(if euid == 0 {
                "owned by another user; run this as that user, e.g. su -s /bin/sh concord -c '...'"
            } else {
                "owned by neither root nor the user running Concord"
            }));
        }
        let mode = meta.permissions().mode() & 0o7777;
        // All three bits, not just read: whoever can write it picks the token.
        if mode & 0o077 != 0 {
            return Err(refuse(&format!(
                "mode {mode:04o} gives access to group or others; use chmod 600"
            )));
        }
    }
    if meta.len() > MAX_FILE {
        return Err(refuse("too large to be a secrets file"));
    }

    // Reserved up front so the buffer is not reallocated as it fills, leaving
    // copies that are never wiped.
    let capacity = usize::try_from(meta.len()).unwrap_or(0).saturating_add(1);
    let mut text = Zeroizing::new(String::with_capacity(capacity));
    file.take(MAX_FILE)
        .read_to_string(&mut text)
        .map_err(read_err)?;
    Ok(text)
}

/// Replaces `path` with `text`, mode 0600, in one step: a reader sees the old
/// file or the new one. Refused as root where [`unsafe_for_root`] says so.
pub fn write_private(path: &Path, text: &str) -> std::io::Result<()> {
    // Through a symlink, so that renaming does not replace the link itself.
    let path = match path.canonicalize() {
        Ok(p) => p,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => path.to_path_buf(),
        Err(e) => return Err(e),
    };
    let dir = parent(&path);
    if let Some(why) = unsafe_for_root(&path) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            why,
        ));
    }
    // Created 0600 under an unpredictable name.
    let mut tmp = tempfile::NamedTempFile::new_in(&dir)?;
    tmp.write_all(text.as_bytes())?;
    tmp.as_file().sync_all()?;
    tmp.persist(&path).map_err(|e| e.error)?;
    File::open(&dir)?.sync_all()
}

/// Why root must not change `path`, or `None`. In a directory someone else
/// controls, that user can put a symlink where root is about to read or write;
/// and a file root left there would be one the service account cannot read. So
/// root does not act for the account, it becomes the account.
pub fn unsafe_for_root(path: &Path) -> Option<String> {
    #[cfg(unix)]
    {
        // SAFETY: geteuid has no preconditions and cannot fail.
        if unsafe { libc::geteuid() } == 0 {
            return unsafe_dir(&parent(path));
        }
    }
    let _ = path;
    None
}

/// Every directory on the way counts: whoever can rename one decides what the
/// path below it means.
#[cfg(unix)]
pub(crate) fn unsafe_dir(dir: &Path) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    let real = match dir.canonicalize() {
        Ok(d) => d,
        Err(e) => return Some(format!("{}: {e}", dir.display())),
    };
    for (i, d) in real.ancestors().enumerate() {
        let Ok(m) = d.symlink_metadata() else {
            return Some(format!("cannot inspect {}", d.display()));
        };
        // A sticky directory keeps others from renaming what root owns in it,
        // but not from adding names, which matters only in the last one.
        let shared = m.mode() & 0o022 != 0 && (i == 0 || m.mode() & 0o1000 == 0);
        if m.uid() != 0 || shared {
            return Some(format!(
                "{} can be changed by users other than root; run this as the account Concord \
                 runs as, e.g. su -s /bin/sh concord -c '...'",
                d.display()
            ));
        }
    }
    None
}

/// Excludes other writers of files beside `path` until dropped. Locks the
/// directory, because the file itself is replaced on every write.
pub struct DirLock(#[allow(dead_code)] File);

pub fn lock_beside(path: &Path) -> std::io::Result<DirLock> {
    let dir = File::open(parent(path))?;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        // SAFETY: the descriptor is open for the whole call.
        if unsafe { libc::flock(dir.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(DirLock(dir))
}

fn parent(path: &Path) -> PathBuf {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

#[cfg(unix)]
pub(crate) fn trusted_owner(owner: u32, euid: u32) -> bool {
    owner == euid || owner == 0
}

fn open(path: &Path) -> std::io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Opening a FIFO would otherwise block before it can be refused.
        opts.custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY);
    }
    opts.open(path)
}
