//! Login: one shared passphrase, server-side sessions, a failed-login limit.
//!
//! The source address cannot be the boundary on its own. Everything that
//! leaves the PVE host through vmbr0 arrives as the host's own address, the nested nodes
//! included unless host-guard is installed, so a control needs
//! proof that the operator is the one asking.
//!
//! The passphrase is kept only as its SHA-256 digest. A candidate is hashed
//! and the two digests compared in constant time, so neither the content nor
//! the length of the passphrase shows in the timing.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

pub const COOKIE: &str = "nestview_session";

/// Shorter than this is refused at load: the deploy generates 32 random
/// bytes, so a short file means the wrong file.
const MIN_PASSPHRASE: usize = 16;
/// Longer than this is not hashed at all; the login form caps it too.
pub const MAX_PASSPHRASE: usize = 1024;

/// Failed logins allowed per window, across all clients. Per-address limits
/// mean nothing here: every client the CT accepts has the host's address.
const FAIL_LIMIT: usize = 5;
const FAIL_WINDOW: Duration = Duration::from_secs(60);

/// Live sessions kept. A login beyond this evicts the oldest.
const MAX_SESSIONS: usize = 32;

/// The SHA-256 of the passphrase. No Serialize, and Debug is redacted.
pub struct Passphrase([u8; 32]);

impl fmt::Debug for Passphrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Passphrase(<redacted>)")
    }
}

impl Passphrase {
    /// The file's one line, without its trailing newline. Errors say what was
    /// wrong, never what was there.
    pub fn from_text(text: &str) -> Result<Passphrase, &'static str> {
        let line = text.strip_suffix('\n').unwrap_or(text);
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.contains(['\n', '\r']) {
            return Err("expected exactly one line");
        }
        if line.len() < MIN_PASSPHRASE {
            return Err("passphrase is shorter than 16 bytes");
        }
        if line.len() > MAX_PASSPHRASE {
            return Err("passphrase is longer than 1024 bytes");
        }
        Ok(Passphrase(Sha256::digest(line.as_bytes()).into()))
    }

    pub fn matches(&self, candidate: &str) -> bool {
        if candidate.len() > MAX_PASSPHRASE {
            return false;
        }
        let d: [u8; 32] = Sha256::digest(candidate.as_bytes()).into();
        bool::from(d.ct_eq(&self.0))
    }
}

/// Reads the passphrase credential, with the same mode rule as the token
/// ([`crate::config::read_secret_file`]): systemd's `LoadCredential=` writes
/// it 0400 plus a read ACL for the service user, which stats as 0440.
pub fn load_passphrase(path: &Path) -> anyhow::Result<Passphrase> {
    let mut text = crate::config::read_secret_file(path, "passphrase")?;
    let r = Passphrase::from_text(&text);
    text.zeroize();
    r.map_err(|why| anyhow::anyhow!("passphrase file {}: {why}", path.display()))
}

/// Server-side sessions. The cookie carries 32 random bytes; the map is keyed
/// by their SHA-256, so the lookup's timing says nothing about live ids.
pub struct Sessions {
    ttl: Duration,
    live: Mutex<HashMap<[u8; 32], Instant>>,
    failures: Mutex<VecDeque<Instant>>,
}

pub enum Login {
    /// The new session id, for the cookie.
    Ok(String),
    Wrong,
    /// Too many failures in the window; the passphrase was not checked.
    Limited,
}

impl Sessions {
    pub fn new(ttl: Duration) -> Self {
        Sessions {
            ttl,
            live: Mutex::new(HashMap::new()),
            failures: Mutex::new(VecDeque::new()),
        }
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    pub fn login(&self, pass: &Passphrase, candidate: &str) -> anyhow::Result<Login> {
        let now = Instant::now();
        {
            // One lock across the check, the compare and the push. Dropped
            // between them, N parallel wrong logins would all
            // pass the check before any pushed, and one window would admit as
            // many guesses as can be sent at once. The compare is one SHA-256
            // and nothing here awaits, so a sync mutex held this long is fine.
            let mut f = lock(&self.failures);
            while f
                .front()
                .is_some_and(|t| now.duration_since(*t) >= FAIL_WINDOW)
            {
                f.pop_front();
            }
            if f.len() >= FAIL_LIMIT {
                return Ok(Login::Limited);
            }
            if !pass.matches(candidate) {
                f.push_back(now);
                return Ok(Login::Wrong);
            }
        }
        let mut raw = [0u8; 32];
        getrandom::getrandom(&mut raw)
            .map_err(|e| anyhow::anyhow!("no randomness for a session id: {e}"))?;
        let id = hex(&raw);
        let mut live = lock(&self.live);
        live.retain(|_, exp| *exp > now);
        if live.len() >= MAX_SESSIONS {
            if let Some(oldest) = live.iter().min_by_key(|(_, exp)| **exp).map(|(k, _)| *k) {
                live.remove(&oldest);
            }
        }
        live.insert(key(&id), now + self.ttl);
        Ok(Login::Ok(id))
    }

    pub fn valid(&self, id: &str) -> bool {
        let mut live = lock(&self.live);
        let k = key(id);
        match live.get(&k) {
            Some(exp) if *exp > Instant::now() => true,
            Some(_) => {
                live.remove(&k);
                false
            }
            None => false,
        }
    }

    pub fn logout(&self, id: &str) {
        lock(&self.live).remove(&key(id));
    }
}

fn key(id: &str) -> [u8; 32] {
    Sha256::digest(id.as_bytes()).into()
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

pub fn hex(b: &[u8]) -> String {
    use std::fmt::Write;
    b.iter()
        .fold(String::with_capacity(b.len() * 2), |mut s, x| {
            let _ = write!(s, "{x:02x}");
            s
        })
}

/// The session id from a `Cookie` header, if it has one of ours.
pub fn session_from_cookie(header: &str) -> Option<&str> {
    header.split(';').find_map(|c| {
        let (k, v) = c.trim().split_once('=')?;
        (k == COOKIE).then_some(v)
    })
}

pub fn set_cookie(id: &str, ttl: Duration) -> String {
    // No `Secure`: the UI is plain HTTP inside the LAN. HttpOnly keeps it from
    // script, SameSite=Strict from every cross-site request.
    format!(
        "{COOKIE}={id}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}",
        ttl.as_secs()
    )
}

pub fn clear_cookie() -> String {
    format!("{COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")
}

#[cfg(test)]
mod tests {
    use super::*;

    pub const PASS: &str = "correct horse battery staple 42";

    #[test]
    fn passphrase_is_hashed_and_redacted() {
        let p = Passphrase::from_text(&format!("{PASS}\n")).unwrap();
        assert!(p.matches(PASS));
        assert!(!p.matches("correct horse battery staple 4"));
        assert!(!p.matches(&format!("{PASS}\n")));
        assert!(!p.matches(""));
        assert!(!format!("{p:?}").contains(PASS));
        for bad in ["short", "", &format!("{PASS}\n{PASS}"), &"x".repeat(2000)] {
            let e = Passphrase::from_text(bad).unwrap_err();
            assert!(!e.contains(PASS));
        }
    }

    #[test]
    fn passphrase_file_errors_never_quote_it() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("nestview-pass-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("passphrase");
        let chmod =
            |m| std::fs::set_permissions(&path, std::fs::Permissions::from_mode(m)).unwrap();
        std::fs::write(&path, format!("{PASS}\n")).unwrap();
        // Other-readable is refused (group read is not: see read_secret_file).
        chmod(0o604);
        let e = load_passphrase(&path).unwrap_err();
        assert!(e.to_string().contains("has mode 604"), "{e}");
        assert!(!format!("{e} {e:?}").contains(PASS));

        chmod(0o600);
        std::fs::write(&path, format!("{PASS}\n{PASS}\n")).unwrap();
        chmod(0o400);
        let e = load_passphrase(&path).unwrap_err();
        assert!(!format!("{e} {e:?}").contains(PASS));

        chmod(0o600);
        std::fs::write(&path, format!("{PASS}\n")).unwrap();
        // As systemd delivers it to a User= service on tmpfs.
        chmod(0o440);
        let p = load_passphrase(&path).unwrap();
        assert!(p.matches(PASS));
        assert!(!format!("{p:?}").contains(PASS));
        chmod(0o600);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn sessions_expire_and_log_out() {
        let p = Passphrase::from_text(PASS).unwrap();
        let s = Sessions::new(Duration::from_secs(60));
        let Login::Ok(id) = s.login(&p, PASS).unwrap() else {
            panic!("login failed")
        };
        assert_eq!(id.len(), 64);
        assert!(s.valid(&id));
        assert!(!s.valid("00"));
        s.logout(&id);
        assert!(!s.valid(&id));

        let s = Sessions::new(Duration::ZERO);
        let Login::Ok(id) = s.login(&p, PASS).unwrap() else {
            panic!("login failed")
        };
        assert!(!s.valid(&id), "a session past its expiry is refused");
    }

    #[test]
    fn failed_logins_are_limited() {
        let p = Passphrase::from_text(PASS).unwrap();
        let s = Sessions::new(Duration::from_secs(60));
        for _ in 0..FAIL_LIMIT {
            assert!(matches!(s.login(&p, "wrong").unwrap(), Login::Wrong));
        }
        // Even the right passphrase is not checked once the limit is hit.
        assert!(matches!(s.login(&p, PASS).unwrap(), Login::Limited));
    }

    /// Wrong logins sent at once still get at most FAIL_LIMIT
    /// compares per window.
    #[test]
    fn failed_login_limit_holds_under_concurrency() {
        let p = std::sync::Arc::new(Passphrase::from_text(PASS).unwrap());
        let s = std::sync::Arc::new(Sessions::new(Duration::from_secs(60)));
        let n = 64;
        let gate = std::sync::Arc::new(std::sync::Barrier::new(n));
        let handles: Vec<_> = (0..n)
            .map(|_| {
                let (p, s, gate) = (p.clone(), s.clone(), gate.clone());
                std::thread::spawn(move || {
                    gate.wait();
                    s.login(&p, "wrong").unwrap()
                })
            })
            .collect();
        let wrong = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|r| matches!(r, Login::Wrong))
            .count();
        assert_eq!(wrong, FAIL_LIMIT, "only FAIL_LIMIT guesses were compared");
        assert!(matches!(s.login(&p, PASS).unwrap(), Login::Limited));
    }

    #[test]
    fn cookie_parsing() {
        assert_eq!(
            session_from_cookie("a=b; nestview_session=abc; c=d"),
            Some("abc")
        );
        assert_eq!(session_from_cookie("nestview_sessionx=abc"), None);
        let c = set_cookie("abc", Duration::from_secs(10));
        assert!(
            c.contains("HttpOnly") && c.contains("SameSite=Strict") && c.contains("Max-Age=10")
        );
    }
}
