//! Scans this repository for anything that names a real estate.
//!
//! ```text
//! cargo run -p concord-pve --locked --features capture --example leakscan -- [--commit REV | --text FILE] [--allow FILE]... [--show]
//! ```
//!
//! Default: every tracked file, as it is in the working tree. With `--commit`:
//! every file of that commit, plus the commit object itself (author, committer,
//! message). With `--text`: that one file, as commit metadata (for tag objects
//! and the like). The generic patterns always apply; set `CONCORD_ESTATE_DIGESTS` to
//! add your own names.
//!
//! Legitimate hits are listed in `leakscan-allow.txt` at the repository root,
//! and in any `--allow` file: `PATH<TAB>TOKEN` per line, where
//! PATH is a file, a directory ending in `/`, `*`, or `<commit>` for commit
//! metadata, and TOKEN is the exact (lowercase) match. There are no
//! wildcards in TOKEN. Reports name the place and the rule, not the match; `--show`
//! adds the match, for local use.

use std::process::{Command, ExitCode};

use concord_pve::LeakScanner;

const ALLOW_FILE: &str = "leakscan-allow.txt";
/// What commit metadata is called in reports and allowlists.
const COMMIT: &str = "<commit>";

type Res<T> = Result<T, String>;

fn git(args: &[&str]) -> Res<Vec<u8>> {
    let out = Command::new("git")
        .args(args)
        .output()
        .map_err(|e| format!("cannot run git: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(out.stdout)
}

struct Allow(Vec<(String, String)>);

impl Allow {
    fn load(&mut self, name: &str, text: &str) -> Res<()> {
        for (n, line) in text.lines().enumerate() {
            if line.trim().is_empty() || line.starts_with('#') {
                continue;
            }
            match line.split('\t').collect::<Vec<_>>().as_slice() {
                [path, token] if !path.is_empty() && !token.is_empty() => {
                    self.0.push((path.to_string(), token.to_ascii_lowercase()));
                }
                _ => return Err(format!("{name}:{}: expected PATH<TAB>TOKEN", n + 1)),
            }
        }
        Ok(())
    }

    fn permits(&self, path: &str, token: &str) -> bool {
        self.0.iter().any(|(p, t)| {
            t == token
                && (p == path
                    || (p == "*" && path != COMMIT)
                    || (p.ends_with('/') && path.starts_with(p.as_str())))
        })
    }
}

fn run() -> Res<bool> {
    let mut commit = None;
    let mut text_file = None;
    let mut show = false;
    let mut allow_files = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--commit" => commit = Some(args.next().ok_or("--commit needs a revision")?),
            "--allow" => allow_files.push(args.next().ok_or("--allow needs a file")?),
            "--text" => text_file = Some(args.next().ok_or("--text needs a file")?),
            "--show" => show = true,
            other => return Err(format!("unknown argument {other}")),
        }
    }
    let scanner = LeakScanner::from_env()?;
    let top =
        String::from_utf8(git(&["rev-parse", "--show-toplevel"])?).map_err(|e| e.to_string())?;
    // --allow paths are the caller's; read them before moving to the top.
    let mut allow = Allow(Vec::new());
    for f in &allow_files {
        let text = std::fs::read_to_string(f).map_err(|e| format!("{f}: {e}"))?;
        allow.load(f, &text)?;
    }
    let text_body = match &text_file {
        Some(_) if commit.is_some() => return Err("--text and --commit exclude each other".into()),
        Some(f) => Some(std::fs::read(f).map_err(|e| format!("{f}: {e}"))?),
        None => None,
    };
    std::env::set_current_dir(top.trim_end()).map_err(|e| e.to_string())?;

    // (name, contents) of everything to scan.
    let mut items: Vec<(String, Vec<u8>)> = Vec::new();
    match (&commit, text_body) {
        (_, Some(body)) => items.push((COMMIT.to_string(), body)),
        (None, None) => {
            for name in git(&["ls-files", "-z"])?.split(|b| *b == 0) {
                if name.is_empty() {
                    continue;
                }
                let name = String::from_utf8(name.to_vec()).map_err(|e| e.to_string())?;
                let meta = std::fs::symlink_metadata(&name).map_err(|e| format!("{name}: {e}"))?;
                let body = if meta.file_type().is_symlink() {
                    let t = std::fs::read_link(&name).map_err(|e| format!("{name}: {e}"))?;
                    t.to_string_lossy().into_owned().into_bytes()
                } else {
                    std::fs::read(&name).map_err(|e| format!("{name}: {e}"))?
                };
                items.push((name, body));
            }
        }
        (Some(rev), None) => {
            let rev = format!("{rev}^{{commit}}");
            items.push((COMMIT.to_string(), git(&["cat-file", "commit", &rev])?));
            for line in git(&["ls-tree", "-r", "-z", &rev])?.split(|b| *b == 0) {
                if line.is_empty() {
                    continue;
                }
                let line = String::from_utf8(line.to_vec()).map_err(|e| e.to_string())?;
                let (head, name) = line.split_once('\t').ok_or("unexpected ls-tree output")?;
                let f: Vec<&str> = head.split(' ').collect();
                let [_, "blob", id] = f.as_slice() else {
                    return Err(format!("{name}: not a plain file"));
                };
                items.push((name.to_string(), git(&["cat-file", "blob", id])?));
            }
        }
    }
    let allow_text = match &commit {
        None => std::fs::read_to_string(ALLOW_FILE).map_err(|e| format!("{ALLOW_FILE}: {e}"))?,
        Some(_) => items
            .iter()
            .find(|(n, _)| n == ALLOW_FILE)
            .map(|(_, b)| String::from_utf8_lossy(b).into_owned())
            .ok_or(format!("{ALLOW_FILE} is not in the commit"))?,
    };
    allow.load(ALLOW_FILE, &allow_text)?;

    let mut bad = 0;
    for (name, body) in &items {
        // Lossy, so a binary file is scanned for its text too.
        let text = String::from_utf8_lossy(body);
        for l in scanner.scan(name) {
            if !allow.permits(name, &l.token) {
                bad += 1;
                println!("{name}: file name: {}", l.rule);
            }
        }
        for l in scanner.scan(&text) {
            // The allowlist quotes what it allows.
            if name == ALLOW_FILE && allow.0.iter().any(|(_, t)| *t == l.token) {
                continue;
            }
            if !allow.permits(name, &l.token) {
                bad += 1;
                let line = text.as_bytes()[..l.offset]
                    .iter()
                    .filter(|b| **b == b'\n')
                    .count()
                    + 1;
                let what = if show {
                    format!(" [{}]", l.token)
                } else {
                    String::new()
                };
                println!("{name}:{line}: {}{what}", l.rule);
            }
        }
    }
    println!(
        "leakscan: {} item(s) scanned, {bad} hit(s) not allowed",
        items.len()
    );
    Ok(bad == 0)
}

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("leakscan: {e}");
            ExitCode::FAILURE
        }
    }
}
