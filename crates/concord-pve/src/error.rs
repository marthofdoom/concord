use std::time::Duration;

/// Everything the PVE client can fail with.
///
/// No variant carries the API token secret or the `Authorization` header: the
/// only free-text fields are filled from transport errors (with the URL
/// stripped, since a query string can hold arbitrary parameters), PVE's own
/// response bodies, and caller-supplied paths.
/// `Clone` so a test double can hand the same error out more than once.
#[derive(Clone, Debug, thiserror::Error)]
pub enum PveError {
    /// The host presented a certificate whose SHA-256 fingerprint is not the
    /// pinned one. Distinct from a transport failure because the right response
    /// is to stop and tell the operator, not to retry.
    #[error("certificate fingerprint mismatch: expected {expected}, host presented {actual}")]
    FingerprintMismatch { expected: String, actual: String },

    /// The TCP or TLS connection could not be established.
    #[error("cannot connect to PVE host: {0}")]
    Connect(String),

    /// The request ran past the client's timeout.
    #[error("request to PVE host timed out")]
    Timeout,

    /// Any other failure below HTTP (reset mid-body, protocol error).
    #[error("transport error: {0}")]
    Transport(String),

    /// PVE answered with a non-success status, or with a success status and a
    /// body that reports failure.
    #[error("PVE returned HTTP {status}: {message}{}", render_errors(.errors))]
    Http {
        status: u16,
        message: String,
        /// The `errors` object PVE attaches to parameter failures, keyed by
        /// parameter name.
        errors: Option<serde_json::Value>,
    },

    /// The response was not the envelope PVE documents, or `data` was not the
    /// shape the caller asked for.
    #[error("cannot decode PVE response: {0}")]
    Decode(String),

    /// A task ran to completion and reported an error.
    #[error("task {upid} failed: {exitstatus}")]
    TaskFailed { upid: String, exitstatus: String },

    /// A task was still running when the caller stopped waiting. It keeps
    /// running on the host; this says nothing about its eventual result.
    #[error("task {upid} still running after {waited:?}")]
    TaskTimeout { upid: String, waited: Duration },

    /// The request could not be built: bad URL, non-https base, malformed
    /// credentials, malformed UPID.
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    /// A `MockPve` call that nothing was registered for.
    #[error("mock: {0}")]
    Mock(String),
}

fn render_errors(errors: &Option<serde_json::Value>) -> String {
    match errors {
        Some(v) => format!(" (errors: {v})"),
        None => String::new(),
    }
}

/// The client addresses one host but does not know that host's node name, so
/// there is no `NodeId` to build `NodeUnreachable` from. Everything maps to
/// `Api` with the full message; callers that know the node can re-wrap
/// `Connect`/`Timeout` themselves.
impl From<PveError> for concord_core::Error {
    fn from(e: PveError) -> Self {
        concord_core::Error::Api(e.to_string())
    }
}
