//! `concordctl`: a thin client for the Concord API. It never talks to PVE.

use std::fmt::Write as _;
use std::io::Write;
use std::time::Duration;

use clap::{Parser, Subcommand};
use concord_inventory::{Conflict, EstateSnapshot, Guest, HostSummary};
use serde::Deserialize;
use serde_json::Value;

const DEFAULT_SERVER: &str = "http://127.0.0.1:8010";

#[derive(Parser, Debug)]
#[command(
    name = "concordctl",
    version,
    about = "Command-line client for the Concord API"
)]
pub struct Cli {
    /// Concord API base URL.
    #[arg(long, env = "CONCORD_SERVER", default_value = DEFAULT_SERVER, global = true)]
    pub server: String,
    /// Print the API's JSON body instead of a table.
    #[arg(long, global = true)]
    pub json: bool,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// The server's version.
    Version,
    /// Every host and whether it is reachable.
    Hosts,
    /// Guests across the estate.
    Guests {
        #[arg(long)]
        host: Option<String>,
        /// `qemu` or `lxc`.
        #[arg(long)]
        kind: Option<String>,
        #[arg(long)]
        status: Option<String>,
    },
    /// One guest, including its config.
    Guest { host: String, vmid: u32 },
    /// The whole inventory snapshot.
    Estate,
}

#[derive(Debug, thiserror::Error)]
pub enum CtlError {
    #[error("cannot reach {server}: {reason}")]
    Connect { server: String, reason: String },
    /// The server answered with an error; `message` is its `error` field.
    #[error("server returned {status}: {message}")]
    Server { status: u16, message: String },
    #[error("unexpected response: {0}")]
    Decode(String),
    #[error("output failed: {0}")]
    Output(String),
}

/// Strips control characters: guest names and tags are chosen by whoever can
/// create a guest, and must not be able to drive the operator's terminal.
///
/// Bidi overrides are removed too: they reorder what follows, so a name could
/// make a table row read differently from what it contains.
pub fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() || is_bidi(c) { '?' } else { c })
        .collect()
}

fn is_bidi(c: char) -> bool {
    matches!(c, '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// Pretty JSON with control (C0, C1) and bidi characters written as `\u`
/// escapes. serde_json only escapes below 0x20; raw C1 bytes can still drive a
/// terminal. Such characters only occur inside strings, where an escape is
/// valid and means the same character.
fn escape_json(json: &str) -> String {
    let mut o = String::with_capacity(json.len());
    for c in json.chars() {
        if (c.is_control() && c != '\n') || is_bidi(c) {
            let _ = write!(o, "\\u{:04x}", c as u32);
        } else {
            o.push(c);
        }
    }
    o
}

/// An error with its causes, since reqwest's top-level text is only
/// "error sending request".
fn chain(e: &dyn std::error::Error) -> String {
    let mut s = e.to_string();
    let mut cur = e.source();
    while let Some(c) = cur {
        let _ = write!(s, ": {c}");
        cur = c.source();
    }
    s
}

async fn fetch(cli: &Cli, path: &str, query: &[(&str, &str)]) -> Result<Value, CtlError> {
    // https servers need a crypto provider; ignoring the error is correct when
    // one is already installed.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let url = format!("{}{}", cli.server.trim_end_matches('/'), path);
    // No proxy: the operator's proxy variables must not receive a request
    // meant for the Concord server. Timeouts so a silent server cannot hang us.
    let client = reqwest::Client::builder()
        .no_proxy()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| CtlError::Connect {
            server: cli.server.clone(),
            reason: chain(&e),
        })?;
    let resp = client
        .get(&url)
        .query(query)
        .send()
        .await
        .map_err(|e| CtlError::Connect {
            server: cli.server.clone(),
            // without_url: the query string is not needed in the message.
            reason: chain(&e.without_url()),
        })?;
    let status = resp.status();
    // Status first: an error page need not be JSON.
    if !status.is_success() {
        let message = match resp.json::<Value>().await {
            Ok(b) => b
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("no error message")
                .to_string(),
            Err(_) => status
                .canonical_reason()
                .unwrap_or("no error message")
                .to_string(),
        };
        return Err(CtlError::Server {
            status: status.as_u16(),
            message: sanitize(&message),
        });
    }
    let body: Value = resp
        .json()
        .await
        .map_err(|e| CtlError::Decode(chain(&e.without_url())))?;
    Ok(body)
}

fn decode<T: for<'de> Deserialize<'de>>(v: Value) -> Result<T, CtlError> {
    serde_json::from_value(v).map_err(|e| CtlError::Decode(e.to_string()))
}

/// Runs one command, writing its output to `out`.
pub async fn run(cli: &Cli, out: &mut dyn Write) -> Result<(), CtlError> {
    let (path, query): (String, Vec<(&str, &str)>) = match &cli.command {
        Command::Version => ("/api/v1/version".into(), vec![]),
        Command::Hosts => ("/api/v1/hosts".into(), vec![]),
        Command::Estate => ("/api/v1/estate".into(), vec![]),
        Command::Guests { host, kind, status } => {
            let mut q = Vec::new();
            if let Some(h) = host {
                q.push(("host", h.as_str()));
            }
            if let Some(k) = kind {
                q.push(("kind", k.as_str()));
            }
            if let Some(s) = status {
                q.push(("status", s.as_str()));
            }
            ("/api/v1/guests".into(), q)
        }
        // Path segments are percent-encoded so a host name cannot add
        // components.
        Command::Guest { host, vmid } => (
            format!("/api/v1/guests/{}/{}", encode_segment(host), vmid),
            vec![],
        ),
    };
    let body = fetch(cli, &path, &query).await?;
    let text = if cli.json {
        escape_json(
            &serde_json::to_string_pretty(&body).map_err(|e| CtlError::Decode(e.to_string()))?,
        )
    } else {
        render(&cli.command, body)?
    };
    writeln!(out, "{text}").map_err(|e| CtlError::Output(e.to_string()))
}

fn encode_segment(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            o.push(b as char);
        } else {
            let _ = write!(o, "%{b:02X}");
        }
    }
    o
}

fn opt(s: &Option<String>) -> String {
    s.as_deref().map_or("-".into(), sanitize)
}

fn mem_mib(v: Option<u64>) -> String {
    v.map_or("-".into(), |b| format!("{}M", b / (1024 * 1024)))
}

/// Left-aligned columns, widths from the data.
fn table(header: &[&str], rows: Vec<Vec<String>>) -> String {
    let mut w: Vec<usize> = header.iter().map(|h| h.chars().count()).collect();
    for r in &rows {
        for (i, c) in r.iter().enumerate() {
            w[i] = w[i].max(c.chars().count());
        }
    }
    let line = |cells: Vec<String>| -> String {
        let mut s = String::new();
        for (i, c) in cells.iter().enumerate() {
            let _ = write!(s, "{c:<width$}  ", width = w[i]);
        }
        s.trim_end().to_string()
    };
    let mut lines = vec![line(header.iter().map(|h| h.to_string()).collect())];
    lines.extend(rows.into_iter().map(line));
    lines.join("\n")
}

fn guest_rows(rows: &[(String, &Guest)]) -> String {
    table(
        &[
            "HOST", "VMID", "KIND", "NAME", "STATUS", "CPUS", "MEM", "MAXMEM", "TAGS", "NOTE",
        ],
        rows.iter()
            .map(|(host, g)| {
                let mut note = Vec::new();
                if g.stale {
                    note.push("stale");
                }
                if g.template {
                    note.push("template");
                }
                if g.detail_error.is_some() {
                    note.push("detail-error");
                }
                vec![
                    sanitize(host),
                    g.vmid.to_string(),
                    format!("{:?}", g.kind).to_lowercase(),
                    opt(&g.name),
                    sanitize(&g.status),
                    g.cpus.map_or("-".into(), |c| c.to_string()),
                    mem_mib(g.mem),
                    mem_mib(g.maxmem),
                    if g.tags.is_empty() {
                        "-".into()
                    } else {
                        sanitize(&g.tags.join(","))
                    },
                    note.join(","),
                ]
            })
            .collect(),
    )
}

fn host_table(hosts: &[HostSummary]) -> String {
    table(
        &[
            "HOST", "NODE", "STATUS", "VERSION", "GUESTS", "STALE", "ERROR",
        ],
        hosts
            .iter()
            .map(|h| {
                vec![
                    sanitize(&h.name),
                    opt(&h.node),
                    format!("{:?}", h.status).to_lowercase(),
                    opt(&h.pve_version),
                    h.guest_count.to_string(),
                    h.stale_guests.to_string(),
                    opt(&h.error),
                ]
            })
            .collect(),
    )
}

fn conflicts_text(c: &[Conflict]) -> String {
    c.iter()
        .map(|c| {
            format!(
                "\nCONFLICT: vmid {} exists on {}",
                c.vmid,
                sanitize(&c.hosts.join(", "))
            )
        })
        .collect()
}

#[derive(Deserialize)]
struct HostsBody {
    hosts: Vec<HostSummary>,
    conflicts: Vec<Conflict>,
}

#[derive(Deserialize)]
struct GuestsBody {
    guests: Vec<GuestRow>,
}

#[derive(Deserialize)]
struct GuestRow {
    host: String,
    #[serde(flatten)]
    guest: Guest,
}

fn render(cmd: &Command, body: Value) -> Result<String, CtlError> {
    Ok(match cmd {
        Command::Version => body
            .get("version")
            .and_then(Value::as_str)
            .map(sanitize)
            .ok_or_else(|| CtlError::Decode("no version field".into()))?,
        Command::Hosts => {
            let b: HostsBody = decode(body)?;
            host_table(&b.hosts) + &conflicts_text(&b.conflicts)
        }
        Command::Guests { .. } => {
            let b: GuestsBody = decode(body)?;
            let rows: Vec<(String, &Guest)> = b
                .guests
                .iter()
                .map(|r| (r.host.clone(), &r.guest))
                .collect();
            guest_rows(&rows)
        }
        Command::Guest { .. } => {
            let r: GuestRow = decode(body)?;
            let mut s = guest_rows(&[(r.host.clone(), &r.guest)]);
            if let Some(e) = &r.guest.detail_error {
                let _ = write!(s, "\ndetail error: {}", sanitize(e));
            }
            if let Some(c) = &r.guest.config {
                s.push_str("\nconfig:");
                for (k, v) in c {
                    let _ = write!(s, "\n  {}: {}", sanitize(k), sanitize(&v.to_string()));
                }
            }
            if !r.guest.config_omitted.is_empty() {
                // Said out loud, so a missing key is not read as an unset one.
                let keys = r.guest.config_omitted.join(", ");
                let _ = write!(s, "\nwithheld config: {}", sanitize(&keys));
            }
            s
        }
        Command::Estate => {
            let e: EstateSnapshot = decode(body)?;
            let summaries: Vec<HostSummary> = e.hosts.iter().map(|h| h.summary()).collect();
            let rows: Vec<(String, &Guest)> = e
                .hosts
                .iter()
                .flat_map(|h| h.guests.iter().map(move |g| (h.name.clone(), g)))
                .collect();
            format!(
                "cycle {} at {}\n\n{}\n\n{}{}",
                e.cycle,
                e.taken_at,
                host_table(&summaries),
                guest_rows(&rows),
                conflicts_text(&e.conflicts)
            )
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_removes_control_characters() {
        assert_eq!(sanitize("a\x1b[31mb\nc"), "a?[31mb?c");
    }

    #[test]
    fn sanitize_removes_bidi_overrides() {
        assert_eq!(sanitize("a\u{202e}b"), "a?b");
    }

    #[test]
    fn json_escapes_c1_and_bidi_but_stays_valid() {
        let v = serde_json::json!({"name": "a\u{9b}b\u{202e}c"});
        let out = escape_json(&serde_json::to_string_pretty(&v).unwrap());
        assert!(!out.contains('\u{9b}') && !out.contains('\u{202e}'));
        let back: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn segments_are_encoded() {
        assert_eq!(encode_segment("a/b ../c"), "a%2Fb%20..%2Fc");
    }
}
