use async_trait::async_trait;
use percent_encoding::{percent_decode_str, utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::Value;

use crate::error::PveError;

/// The HTTP verbs PVE's API uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Method {
    Get,
    Post,
    Put,
    Delete,
}

impl Method {
    pub fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
            Method::Put => "PUT",
            Method::Delete => "DELETE",
        }
    }
}

// Keep RFC 3986 unreserved characters readable; encode everything else,
// notably `:` (UPIDs) and `/` (so a segment can never add path components).
const SEGMENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

/// Builds an API path from segments, percent-encoding each one.
///
/// Callers pass raw values (node names, UPIDs) and never concatenate them into
/// a path themselves: a UPID contains `:` and a hostile or corrupt value must
/// not be able to add `/` or `..` components.
///
/// Encoding alone does not stop `.` and `..`, which are unreserved and so pass
/// through, and which the URL parser then resolves into a different endpoint;
/// an empty segment is likewise not a distinct path component. Those are
/// rejected, as is any segment that percent-decodes to one of them, so no
/// later decoding step can turn a value into one.
pub fn api_path(segments: &[&str]) -> Result<String, PveError> {
    let mut out = String::new();
    for s in segments {
        if is_dot_or_empty(s) {
            return Err(PveError::InvalidRequest(
                "API path segment must not be empty, '.' or '..'".into(),
            ));
        }
        out.push('/');
        out.extend(utf8_percent_encode(s, SEGMENT));
    }
    Ok(out)
}

/// True for `""`, `"."`, `".."` and anything that percent-decodes to them.
/// WHATWG URL parsing treats `%2e` (either case) as `.`, so the decoded form
/// is what matters.
pub(crate) fn is_dot_or_empty(segment: &str) -> bool {
    let decoded = percent_decode_str(segment).decode_utf8_lossy();
    matches!(decoded.as_ref(), "" | "." | "..")
}

/// A Proxmox VE API endpoint.
///
/// `request` is the only required method; everything else is built on it, so a
/// test double needs one function. Object-safe and `Send + Sync` so
/// subsystems can hold an `Arc<dyn PveApi>`.
#[async_trait]
pub trait PveApi: Send + Sync {
    /// Calls `path` (already percent-encoded, relative to `/api2/json`, e.g.
    /// `/nodes/pve1/qemu`; build it with [`api_path`]) and returns the
    /// envelope's unwrapped `data`.
    ///
    /// GET and DELETE send `params` in the query string; POST and PUT send them
    /// as an `application/x-www-form-urlencoded` body.
    async fn request(
        &self,
        method: Method,
        path: &str,
        params: &[(&str, String)],
    ) -> Result<Value, PveError>;

    async fn version(&self) -> Result<VersionInfo, PveError> {
        decode(self.request(Method::Get, "/version", &[]).await?)
    }

    async fn nodes(&self) -> Result<Vec<NodeInfo>, PveError> {
        decode(self.request(Method::Get, "/nodes", &[]).await?)
    }

    async fn task_status(&self, node: &str, upid: &str) -> Result<TaskStatus, PveError> {
        let path = api_path(&["nodes", node, "tasks", upid, "status"])?;
        decode(self.request(Method::Get, &path, &[]).await?)
    }
}

fn decode<T: DeserializeOwned>(data: Value) -> Result<T, PveError> {
    serde_json::from_value(data).map_err(|e| PveError::Decode(e.to_string()))
}

/// `GET /version`. All three fields are required strings in PVE's schema.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct VersionInfo {
    pub version: String,
    pub release: String,
    pub repoid: String,
}

/// One item of `GET /nodes`. Only `node` and `status` are always present; the
/// rest are absent for offline nodes.
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct NodeInfo {
    pub node: String,
    pub status: NodeStatus,
    pub uptime: Option<u64>,
    pub ssl_fingerprint: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeStatus {
    Unknown,
    Online,
    Offline,
}

/// `GET /nodes/{node}/tasks/{upid}/status`.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct TaskStatus {
    pub status: TaskState,
    /// Present only once the task has stopped.
    pub exitstatus: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TaskState {
    Running,
    Stopped,
}
