//! Append-only JSON-lines audit log of every control request, refused ones
//! included.
//!
//! A control that sends a write leaves several rows sharing one `req` id: a
//! `started` row before the first write is sent, a `task` row for each UPID as
//! PVE returns it, and the final row with the result. If the process dies
//! mid-sequence, what was sent is still on record. Those rows are synced to
//! disk before `write_synced` returns, so that holds through a host crash or
//! power loss on the host too, which is when a half-finished darken matters
//! most.
//!
//! Refusal rows go through `write_unsynced`: they record that nothing was
//! sent, and the guard writes them before any session check, so syncing them
//! would let any page in the operator's browser make the service fsync on
//! demand, holding the audit lock a real control's `started` row needs.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Serialize)]
pub struct Row {
    pub ts: String,
    /// Ties together the rows of one request.
    pub req: String,
    pub client_ip: IpAddr,
    pub action: String,
    /// As the client sent it, so a refused out-of-allowlist request is
    /// recorded with what was asked for.
    pub vmid: String,
    /// `null` when the request was refused before its body was read.
    pub dry_run: Option<bool>,
    /// `started` or `task` for the rows written while a control runs; then
    /// the result: `ok`, `dry_run`, `refused`, `warnings`, `failed`,
    /// `timed_out`, `error` or `audit_failed`.
    pub result: &'static str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub upids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<Value>,
}

/// Where rows go: the log file, or a buffer in tests.
pub trait Sink: Write + Send {
    /// Makes what was written durable.
    fn sync(&mut self) -> std::io::Result<()>;
}

impl Sink for File {
    fn sync(&mut self) -> std::io::Result<()> {
        // Data only: the size change is part of it, and the mtime is not
        // worth a second metadata write per row.
        self.sync_data()
    }
}

pub struct AuditLog {
    file: Mutex<Box<dyn Sink>>,
}

impl AuditLog {
    /// Opened at startup so a log that cannot be written stops the service
    /// before any control can run unrecorded.
    pub fn open(path: &Path) -> std::io::Result<Self> {
        use std::os::unix::fs::OpenOptionsExt;
        let file: File = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)?;
        Ok(AuditLog {
            file: Mutex::new(Box::new(file)),
        })
    }

    #[cfg(test)]
    pub fn to_writer(w: Box<dyn Sink>) -> Self {
        AuditLog {
            file: Mutex::new(w),
        }
    }

    /// For the rows of a control that ran: `started`, `task`, and the final
    /// result. Durable before it returns.
    pub fn write_synced(&self, row: &Row) -> std::io::Result<()> {
        self.write(row, true)
    }

    /// For refusals, which sent nothing to PVE and may be triggered by
    /// anyone who can reach the port. Still one whole line, but left to the
    /// page cache.
    pub fn write_unsynced(&self, row: &Row) -> std::io::Result<()> {
        self.write(row, false)
    }

    fn write(&self, row: &Row, sync: bool) -> std::io::Result<()> {
        let mut line = serde_json::to_vec(row).map_err(std::io::Error::other)?;
        line.push(b'\n');
        let mut f = self.file.lock().unwrap_or_else(|p| p.into_inner());
        // One write per row: with O_APPEND the line lands whole.
        f.write_all(&line)?;
        f.flush()?;
        if sync {
            // `flush` on a File is a no-op; the row is on disk only after this.
            f.sync()?;
        }
        Ok(())
    }
}

/// A fresh `req` id: 8 random bytes in hex.
pub fn request_id() -> String {
    let mut b = [0u8; 8];
    // Only a correlation id: if the OS has no randomness to give, the
    // timestamp still orders the rows.
    let _ = getrandom::getrandom(&mut b);
    crate::auth::hex(&b)
}

pub fn now_rfc3339() -> String {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    rfc3339(d.as_secs(), d.subsec_millis())
}

/// UTC timestamp without a date crate: Howard Hinnant's days-to-civil.
fn rfc3339(secs: u64, millis: u32) -> String {
    let days = (secs / 86_400) as i64;
    let sod = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        sod / 3600,
        (sod / 60) % 60,
        sod % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_known_points() {
        assert_eq!(rfc3339(0, 0), "1970-01-01T00:00:00.000Z");
        assert_eq!(rfc3339(951_782_400, 5), "2000-02-29T00:00:00.005Z");
        assert_eq!(rfc3339(0x6500_0000, 0), "2023-09-12T06:06:56.000Z");
    }
}
