use std::str::FromStr;
use std::time::Duration;

use tokio::time::{sleep, Instant};

use crate::api::{PveApi, TaskState};
use crate::error::PveError;

/// A parsed task identifier: `UPID:node:pid:pstart:starttime:type:id:user:`.
///
/// Numeric fields are hex on the wire. The grammar mirrors `PVE::UPID::decode`
/// in pve-common.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Upid {
    pub node: String,
    pub pid: u32,
    pub pstart: u64,
    pub starttime: u32,
    pub task_type: String,
    /// Empty for tasks with no subject (e.g. `aptupdate`).
    pub id: String,
    /// `user@realm`, or `user@realm!tokenid` for API-token tasks.
    pub user: String,
}

impl FromStr for Upid {
    type Err = PveError;

    fn from_str(s: &str) -> Result<Self, PveError> {
        let bad = || PveError::InvalidRequest("malformed UPID".into());
        let rest = s.strip_prefix("UPID:").ok_or_else(bad)?;
        let rest = rest.strip_suffix(':').ok_or_else(bad)?;
        let f: Vec<&str> = rest.split(':').collect();
        let &[node, pid, pstart, starttime, task_type, id, user] = f.as_slice() else {
            return Err(bad());
        };
        let hex = |s: &str, lens: &[usize]| {
            lens.contains(&s.len()) && s.bytes().all(|b| b.is_ascii_hexdigit())
        };
        let name = |s: &str| !s.is_empty() && !s.contains(|c: char| c.is_whitespace() || c == '/');
        let node_ok = !node.is_empty()
            && !node.starts_with('-')
            && !node.ends_with('-')
            && node.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
        if !node_ok
            || !hex(pid, &[8])
            || !hex(pstart, &[8, 9])
            || !hex(starttime, &[8])
            || !name(task_type)
            || !name(user)
            || id.contains(|c: char| c.is_whitespace() || c == '/')
        {
            return Err(bad());
        }
        Ok(Upid {
            node: node.to_string(),
            pid: u32::from_str_radix(pid, 16).map_err(|_| bad())?,
            pstart: u64::from_str_radix(pstart, 16).map_err(|_| bad())?,
            starttime: u32::from_str_radix(starttime, 16).map_err(|_| bad())?,
            task_type: task_type.to_string(),
            id: id.to_string(),
            user: user.to_string(),
        })
    }
}

impl std::fmt::Display for Upid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "UPID:{}:{:08X}:{:08X}:{:08X}:{}:{}:{}:",
            self.node, self.pid, self.pstart, self.starttime, self.task_type, self.id, self.user
        )
    }
}

/// How a task ended, or that we stopped waiting.
///
/// Timeout is an outcome, not an error: the task is still running on the host
/// and the caller must decide whether to keep waiting, cancel it or move on.
/// `PveError` is reserved for "could not find out".
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TaskOutcome {
    /// `exitstatus` was `OK`.
    Ok,
    /// `exitstatus` was `WARNINGS: n`; the task completed. Saturates at
    /// `u32::MAX`.
    Warnings(u32),
    /// Any other `exitstatus`, carried verbatim (PVE puts the error message
    /// there).
    Failed(String),
    /// Still running when `timeout` elapsed.
    TimedOut,
}

impl TaskOutcome {
    /// For callers that treat anything but a clean finish as an error. Warnings
    /// count as success: the task did what was asked.
    pub fn into_result(self, upid: &str, waited: Duration) -> Result<(), PveError> {
        match self {
            TaskOutcome::Ok | TaskOutcome::Warnings(_) => Ok(()),
            TaskOutcome::Failed(exitstatus) => Err(PveError::TaskFailed {
                upid: upid.to_string(),
                exitstatus,
            }),
            TaskOutcome::TimedOut => Err(PveError::TaskTimeout {
                upid: upid.to_string(),
                waited,
            }),
        }
    }
}

/// Maps a stopped task's `exitstatus` the way `PVE::UPID::status_is_error`
/// does: `OK` and `WARNINGS: <digits>` are not errors, everything else is.
fn classify(exitstatus: &str) -> TaskOutcome {
    if exitstatus == "OK" {
        return TaskOutcome::Ok;
    }
    if let Some(n) = exitstatus.strip_prefix("WARNINGS: ") {
        // PVE matches `\d+`, so a sign is not a count. The digits alone decide
        // that the task completed; a count too large for u32 still means
        // "completed with warnings", so it saturates instead of turning a
        // finished task into a failure.
        if !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()) {
            return TaskOutcome::Warnings(n.parse().unwrap_or(u32::MAX));
        }
    }
    TaskOutcome::Failed(exitstatus.to_string())
}

/// Shortest wait between status polls. Each poll is a full HTTPS request that
/// occupies one of pveproxy's few workers (3 by default), so an interval of
/// zero would hammer the host and starve its UI and other API clients; 100 ms
/// still notices a finished task well inside human reaction time.
pub const MIN_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Polls `/nodes/{node}/tasks/{upid}/status` until the task stops or `timeout`
/// elapses. The task is always polled at least once.
///
/// `poll_interval` is raised to [`MIN_POLL_INTERVAL`] if shorter. A `timeout`
/// too large to add to the current time (e.g. `Duration::MAX`) means no
/// deadline.
///
/// A transport or decode error aborts the wait rather than being retried: the
/// caller knows whether the host rebooting is expected (a node restart) or a
/// failure, and this helper does not.
pub async fn wait_for_task(
    api: &dyn PveApi,
    node: &str,
    upid: &str,
    poll_interval: Duration,
    timeout: Duration,
) -> Result<TaskOutcome, PveError> {
    let poll_interval = poll_interval.max(MIN_POLL_INTERVAL);
    let deadline = Instant::now().checked_add(timeout);
    loop {
        let st = api.task_status(node, upid).await?;
        if st.status == TaskState::Stopped {
            return Ok(match st.exitstatus {
                Some(e) => classify(&e),
                // PVE always reads an exit status for a stopped task; treating
                // its absence as success could report a crashed worker as fine.
                None => TaskOutcome::Failed("task stopped without an exit status".into()),
            });
        }
        let wait = match deadline {
            Some(deadline) => {
                let now = Instant::now();
                if now >= deadline {
                    return Ok(TaskOutcome::TimedOut);
                }
                poll_interval.min(deadline - now)
            }
            None => poll_interval,
        };
        sleep(wait).await;
    }
}
