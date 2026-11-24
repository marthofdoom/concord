use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use reqwest::{Client, Url};
use serde::Deserialize;
use serde_json::Value;
use zeroize::Zeroizing;

use crate::error::PveError;
use crate::http::{map_transport, pinned_client};
use crate::tls::Fingerprint;

const USER: &str = "root@pam";
/// A root login's answer is a few KiB, most of it the capability map.
const MAX_BODY: usize = 64 * 1024;

/// Asks one host whether it would let root in, and keeps nothing of the answer.
///
/// Apart from [`crate::HttpPveClient`] because it must carry no token: the only
/// credential here is the one being checked.
#[derive(Clone)]
pub struct RootLogin {
    url: String,
    client: Client,
}

impl fmt::Debug for RootLogin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RootLogin")
            .field("url", &self.url)
            .finish_non_exhaustive()
    }
}

/// A half-finished login. Not a ticket: PVE accepts it for nothing but the
/// second factor.
pub struct TfaChallenge {
    ticket: Zeroizing<String>,
    pub totp: bool,
    pub recovery: bool,
}

impl fmt::Debug for TfaChallenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TfaChallenge(<redacted>)")
    }
}

#[derive(Debug)]
pub enum LoginOutcome {
    Accepted,
    Refused,
    /// The password was right; that is not a login.
    NeedTfa(TfaChallenge),
}

#[derive(Deserialize)]
struct Envelope {
    data: Answer,
}

/// What `create_ticket_do` returns, less what is not needed.
#[derive(Deserialize)]
struct Answer {
    username: String,
    ticket: Zeroizing<String>,
    #[serde(rename = "NeedTFA")]
    need_tfa: Option<Value>,
}

impl RootLogin {
    /// `timeout` bounds a whole check, connection to last byte.
    pub fn new(base_url: &Url, pin: Fingerprint, timeout: Duration) -> Result<Self, PveError> {
        let (base, client) = pinned_client(base_url, pin, timeout)?;
        Ok(RootLogin {
            url: format!("{base}/access/ticket"),
            client,
        })
    }

    pub async fn check(&self, password: &str) -> Result<LoginOutcome, PveError> {
        // PVE takes a valid ticket in place of a password, with no second
        // factor: a stolen one would become a login, and a fresh lifetime.
        if password.is_empty() || (password.starts_with("PVE:") && password.contains("::")) {
            return Ok(LoginOutcome::Refused);
        }
        self.ask(password, None).await
    }

    /// `response` is `totp:123456` or `recovery:...`, as PVE takes it.
    pub async fn respond(&self, c: &TfaChallenge, response: &str) -> Result<bool, PveError> {
        let offered = match response.split_once(':') {
            Some(("totp", code)) => c.totp && !code.is_empty(),
            Some(("recovery", code)) => c.recovery && !code.is_empty(),
            _ => false,
        };
        if !offered {
            return Ok(false);
        }
        Ok(matches!(
            self.ask(response, Some(&c.ticket)).await?,
            LoginOutcome::Accepted
        ))
    }

    async fn ask(&self, password: &str, challenge: Option<&str>) -> Result<LoginOutcome, PveError> {
        let mut body = Zeroizing::new(Vec::with_capacity(
            64 + 3 * (password.len() + challenge.map_or(0, str::len)),
        ));
        put(&mut body, "username=", USER);
        put(&mut body, "&password=", password);
        if let Some(c) = challenge {
            put(&mut body, "&tfa-challenge=", c);
        }
        // Wiped when the HTTP stack lets go of it. Its and TLS's own buffers
        // are copies this cannot reach.
        let body = bytes::Bytes::from_owner(body);
        let mut resp = self
            .client
            .post(&self.url)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(ACCEPT, "application/json")
            .body(body)
            .send()
            .await
            .map_err(map_transport)?;
        let status = resp.status().as_u16();
        // The one status PVE gives for any failed login; it says no more, so
        // that users cannot be enumerated.
        if status == 401 {
            return Ok(LoginOutcome::Refused);
        }
        if status != 200 {
            // No message: the body is not worth trusting near a credential.
            return Err(PveError::Http {
                status,
                message: "unexpected answer to a login".into(),
                errors: None,
            });
        }
        let mut got = Zeroizing::new(Vec::with_capacity(MAX_BODY));
        while let Some(chunk) = resp.chunk().await.map_err(map_transport)? {
            if got.len() + chunk.len() > MAX_BODY {
                return Err(PveError::Decode("login answer is too large".into()));
            }
            got.extend_from_slice(&chunk);
        }
        outcome(&got)
    }
}

fn put(body: &mut Vec<u8>, key: &str, value: &str) {
    body.extend_from_slice(key.as_bytes());
    for part in utf8_percent_encode(value, NON_ALPHANUMERIC) {
        body.extend_from_slice(part.as_bytes());
    }
}

/// Everything but a complete root ticket is refused, so that an answer not
/// understood is never a login.
fn outcome(body: &[u8]) -> Result<LoginOutcome, PveError> {
    // The parser's own errors can quote the ticket.
    let bad = || PveError::Decode("not a login answer".into());
    let a = serde_json::from_slice::<Envelope>(body)
        .map_err(|_| bad())?
        .data;
    if a.username != USER {
        return Err(bad());
    }
    // `PVE:<data>:<time>::<signature>`, with the data's colons as %3A.
    let mut parts = a.ticket.splitn(3, ':');
    let (Some("PVE"), Some(data), Some(rest)) = (parts.next(), parts.next(), parts.next()) else {
        return Err(bad());
    };
    if rest.is_empty() {
        return Err(bad());
    }
    let tfa = data.strip_prefix("!tfa!");
    match (a.need_tfa.is_some(), tfa) {
        (false, None) if data == USER => Ok(LoginOutcome::Accepted),
        (true, Some(challenge)) => {
            let text = percent_encoding::percent_decode_str(challenge)
                .decode_utf8()
                .map_err(|_| bad())?;
            let kinds: HashMap<String, Value> = serde_json::from_str(&text).map_err(|_| bad())?;
            let has = |k: &str| match kinds.get(k) {
                Some(Value::Bool(b)) => *b,
                // Recovery is the list of unused keys.
                Some(Value::Array(a)) => !a.is_empty(),
                _ => false,
            };
            Ok(LoginOutcome::NeedTfa(TfaChallenge {
                totp: has("totp"),
                recovery: has("recovery"),
                ticket: a.ticket,
            }))
        }
        _ => Err(bad()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn of(user: &str, ticket: &str, need: &str) -> Result<LoginOutcome, PveError> {
        outcome(
            format!(r#"{{"data":{{"username":"{user}","ticket":"{ticket}"{need}}}}}"#).as_bytes(),
        )
    }

    #[test]
    fn only_a_complete_root_ticket_is_a_login() {
        let full = "PVE:root@pam:65000000::c2ln";
        let half = "PVE:!tfa!{%22totp%22%3Atrue,%22recovery%22%3A[]}:65000000::c2ln";
        assert!(matches!(of(USER, full, ""), Ok(LoginOutcome::Accepted)));
        for (u, t, n) in [
            (USER, half, ""),
            (USER, full, r#","NeedTFA":1"#),
            (USER, full, r#","NeedTFA":0"#),
            ("user1@pve", full, ""),
            (USER, "PVE:user1@pve:65000000::c2ln", ""),
            (USER, "PVE:root@pam", ""),
            (USER, "", ""),
        ] {
            let e = of(u, t, n).unwrap_err();
            assert!(!e.to_string().contains("PVE:"), "{e}");
        }
        match of(USER, half, r#","NeedTFA":1"#) {
            Ok(LoginOutcome::NeedTfa(c)) => {
                assert!(c.totp && !c.recovery);
                assert!(!format!("{c:?}").contains("PVE:"));
            }
            o => panic!("{o:?}"),
        }
        assert!(outcome(b"{\"data\":null}").is_err());
    }

    #[tokio::test]
    async fn a_ticket_is_not_a_password() {
        let url = "https://192.0.2.11:8006".parse().unwrap();
        let r = RootLogin::new(&url, Fingerprint::of_der(b"x"), Duration::from_millis(1)).unwrap();
        for p in ["", "PVE:root@pam:65000000::c2ln"] {
            assert!(matches!(r.check(p).await, Ok(LoginOutcome::Refused)));
        }
    }
}
