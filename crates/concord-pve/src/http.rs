use std::fmt;
use std::time::Duration;

use async_trait::async_trait;
use reqwest::header::{ACCEPT, AUTHORIZATION};
use reqwest::{Client, Url};
use serde_json::Value;

use crate::api::{is_dot_or_empty, Method, PveApi};
use crate::auth::ApiToken;
use crate::error::PveError;
use crate::tls::{find_pin_mismatch, pinned_client_config, Fingerprint};

/// Longest slice of a non-JSON error body kept in an error message.
const MAX_BODY_IN_ERROR: usize = 512;

/// A PVE API client for one host, authenticated by API token and pinned to one
/// certificate.
pub struct HttpPveClient {
    /// `scheme://host[:port]/api2/json`, no trailing slash.
    base: String,
    client: Client,
    auth: reqwest::header::HeaderValue,
    pin: Fingerprint,
}

// Manual so nothing about the credential is ever formatted.
impl fmt::Debug for HttpPveClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpPveClient")
            .field("base", &self.base)
            .field("pin", &self.pin)
            .finish_non_exhaustive()
    }
}

impl HttpPveClient {
    /// `base_url` is the host's origin, e.g. `https://pve1:8006`. Plain http is
    /// refused: the client carries a root-equivalent credential.
    pub fn new(
        base_url: Url,
        token: ApiToken,
        fingerprint: Fingerprint,
        timeout: Duration,
    ) -> Result<Self, PveError> {
        let auth = token.header_value()?;
        let (base, client) = pinned_client(&base_url, fingerprint, timeout)?;
        Ok(HttpPveClient {
            base,
            client,
            auth,
            pin: fingerprint,
        })
    }
}

pub(crate) fn map_transport(e: reqwest::Error) -> PveError {
    if let Some(m) = find_pin_mismatch(&e) {
        return PveError::FingerprintMismatch {
            expected: m.expected.to_string(),
            actual: m.actual.to_string(),
        };
    }
    // The URL may carry query parameters; none of it belongs in an error.
    let e = e.without_url();
    if e.is_timeout() {
        PveError::Timeout
    } else if e.is_connect() {
        PveError::Connect(error_chain(&e))
    } else {
        PveError::Transport(error_chain(&e))
    }
}

/// A client that speaks to one pinned origin and nowhere else, and the base of
/// its API.
pub(crate) fn pinned_client(
    base_url: &Url,
    fingerprint: Fingerprint,
    timeout: Duration,
) -> Result<(String, Client), PveError> {
    if base_url.scheme() != "https" {
        return Err(PveError::InvalidRequest(
            "PVE base URL must be https".into(),
        ));
    }
    if base_url.host_str().is_none() {
        return Err(PveError::InvalidRequest("PVE base URL has no host".into()));
    }
    if base_url.path() != "/"
        || base_url.query().is_some()
        || base_url.fragment().is_some()
        || !base_url.username().is_empty()
        || base_url.password().is_some()
    {
        return Err(PveError::InvalidRequest(
            "PVE base URL must be a bare origin such as https://host:8006".into(),
        ));
    }
    let tls = pinned_client_config(fingerprint)?;

    let client = Client::builder()
        .use_preconfigured_tls(tls)
        .https_only(true)
        .timeout(timeout)
        // A redirect could carry the credential to another host.
        .redirect(reqwest::redirect::Policy::none())
        // PVE hosts are addressed directly; an ambient proxy would see the
        // credential.
        .no_proxy()
        .build()
        .map_err(|e| {
            PveError::InvalidRequest(format!("HTTP client setup failed: {}", e.without_url()))
        })?;

    let origin = base_url.origin().ascii_serialization();
    Ok((format!("{origin}/api2/json"), client))
}

/// `path` is joined onto the base as text and re-parsed as a URL, so anything
/// the parser would reinterpret is refused rather than sent: `?` and `#` would
/// move the rest out of the path, `\` is a path separator for https URLs,
/// and dot or empty segments would be resolved into another endpoint.
///
/// Control characters go first: the WHATWG parser silently deletes tab, LF
/// and CR anywhere in a URL, so `/nodes/.\t./x` would pass the segment check
/// below and then be sent as `/nodes/../x`. Non-ASCII is refused too, because
/// the parser percent-encodes it, so what is checked here would not be what is
/// sent; `api_path` output is pure ASCII, so nothing built properly is lost.
fn check_raw_path(path: &str) -> Result<(), PveError> {
    if !path.bytes().all(|b| b.is_ascii() && !b.is_ascii_control()) {
        return Err(PveError::InvalidRequest(
            "API path must be printable ASCII; build it with api_path".into(),
        ));
    }
    let Some(rest) = path.strip_prefix('/') else {
        return Err(PveError::InvalidRequest(
            "API path must start with '/'".into(),
        ));
    };
    if path.contains(['?', '#', '\\']) {
        return Err(PveError::InvalidRequest(
            "API path must not contain '?', '#' or '\\'; pass parameters separately".into(),
        ));
    }
    if rest.split('/').any(is_dot_or_empty) {
        return Err(PveError::InvalidRequest(
            "API path must not have empty, '.' or '..' segments".into(),
        ));
    }
    Ok(())
}

fn error_chain(e: &dyn std::error::Error) -> String {
    let mut s = e.to_string();
    let mut src = e.source();
    while let Some(inner) = src {
        s.push_str(": ");
        s.push_str(&inner.to_string());
        src = inner.source();
    }
    s
}

#[async_trait]
impl PveApi for HttpPveClient {
    async fn request(
        &self,
        method: Method,
        path: &str,
        params: &[(&str, String)],
    ) -> Result<Value, PveError> {
        check_raw_path(path)?;
        let url = format!("{}{}", self.base, path);
        let builder = match method {
            Method::Get => self.client.get(&url).query(params),
            Method::Delete => self.client.delete(&url).query(params),
            // pveproxy reads urlencoded bodies on POST/PUT.
            Method::Post => self.client.post(&url).form(params),
            Method::Put => self.client.put(&url).form(params),
        };
        let resp = builder
            .header(AUTHORIZATION, self.auth.clone())
            .header(ACCEPT, "application/json")
            .send()
            .await
            .map_err(map_transport)?;
        let status = resp.status();
        // pveproxy sends some errors (401s, observed) with an empty body and the
        // text only in a custom reason phrase. hyper records the phrase only
        // when it differs from the canonical one, hence the fallback.
        let reason = resp
            .extensions()
            .get::<hyper::ext::ReasonPhrase>()
            .and_then(|r| std::str::from_utf8(r.as_bytes()).ok())
            .or_else(|| status.canonical_reason())
            .map(str::to_owned);
        let body = resp.bytes().await.map_err(map_transport)?;
        parse_envelope(status.as_u16(), reason.as_deref(), &body)
    }
}

/// Unwraps PVE's JSON-format envelope.
///
/// On error statuses the `json` formatter puts the text in `message` and any
/// per-parameter failures in `errors`. A 200 carrying `success: 0` is the
/// `extjs` formatter's way of reporting failure; `/api2/json` never produces
/// it, but it is checked so that a body which says it failed is never returned
/// as data.
///
/// `reason` is the HTTP reason phrase, used as the message when the body has
/// none.
pub(crate) fn parse_envelope(
    status: u16,
    reason: Option<&str>,
    body: &[u8],
) -> Result<Value, PveError> {
    let json: Option<Value> = serde_json::from_slice(body).ok();

    if !(200..300).contains(&status) {
        let from_body = match &json {
            Some(j) => j.get("message").and_then(Value::as_str).map(str::to_owned),
            None => Some(plain_text(body)),
        };
        let message = from_body
            .filter(|m| !m.trim().is_empty())
            .or_else(|| reason.map(str::to_owned))
            .unwrap_or_default();
        let errors = json
            .as_ref()
            .and_then(|j| j.get("errors"))
            .filter(|e| !e.is_null())
            .cloned();
        return Err(PveError::Http {
            status,
            message,
            errors,
        });
    }

    let Some(Value::Object(mut obj)) = json else {
        return Err(PveError::Decode(
            "response body is not a JSON object".into(),
        ));
    };
    let failed = match obj.get("success") {
        Some(Value::Bool(b)) => !b,
        Some(Value::Number(n)) => n.as_i64() == Some(0),
        _ => false,
    };
    if failed {
        let message = obj
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("request reported failure")
            .to_owned();
        let errors = obj.get("errors").filter(|e| !e.is_null()).cloned();
        return Err(PveError::Http {
            status,
            message,
            errors,
        });
    }
    obj.remove("data")
        .ok_or_else(|| PveError::Decode("response has no `data` field".into()))
}

fn plain_text(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    let text = text.trim();
    match text.char_indices().nth(MAX_BODY_IN_ERROR) {
        Some((i, _)) => format!("{}...", &text[..i]),
        None => text.to_string(),
    }
}
