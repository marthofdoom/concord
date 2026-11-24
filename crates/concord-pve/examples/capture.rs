//! Records a PVE host's read-only API responses as sanitised fixtures.
//!
//! ```text
//! cargo run -p concord-pve --example capture -- \
//!     --host HOST[:8006] --token-file FILE --fingerprint AA:BB:... \
//!     --out crates/concord-pve/tests/fixtures
//! ```
//!
//! The token file holds one line, `USER@REALM!TOKENID=SECRET`. Use a token
//! with PVEAuditor only; the capture issues GET and nothing else, but a
//! read-only token makes that true on the host side too.

use std::path::PathBuf;
use std::time::Duration;

use concord_pve::{
    capture_all, write_set, ApiToken, CaptureLimits, Fingerprint, HttpPveClient, ReadOnly, Secret,
};

fn arg(args: &[String], name: &str) -> Result<String, String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
        .ok_or_else(|| format!("missing {name}"))
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let host = arg(&args, "--host")?;
    let host = if host.contains(':') {
        host
    } else {
        format!("{host}:8006")
    };
    let fingerprint: Fingerprint = arg(&args, "--fingerprint")?.parse()?;
    let out = PathBuf::from(arg(&args, "--out")?);

    // The secret goes straight into `Secret`, which prints as <redacted>.
    // Zeroised on drop: `Secret` wipes its copy, so this line must too.
    let raw = zeroize::Zeroizing::new(std::fs::read_to_string(arg(&args, "--token-file")?)?);
    let raw = raw.trim();
    let bad = "token file is not USER@REALM!ID=SECRET";
    let (id, secret) = raw.split_once('=').ok_or(bad)?;
    let (user, token_id) = id.split_once('!').ok_or(bad)?;
    let token = ApiToken::new(user, token_id, Secret::new(secret));

    let client = HttpPveClient::new(
        format!("https://{host}").parse()?,
        token,
        fingerprint,
        Duration::from_secs(30),
    )?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let entries = rt.block_on(capture_all(
        &ReadOnly::new(&client),
        CaptureLimits::default(),
    ))?;
    let n = entries.len();
    let dir = write_set(&out, entries)?;
    println!("wrote {n} endpoints to {}", dir.display());
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("capture: {e}");
        std::process::exit(1);
    }
}
