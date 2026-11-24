use std::fmt;

use reqwest::header::HeaderValue;
use zeroize::Zeroize;

use crate::error::PveError;

/// An API token secret. Deliberately has no `Serialize`, and prints as
/// `<redacted>` under both `Debug` and `Display`, so it cannot reach a log line
/// through a derived impl on a struct that contains it.
pub struct Secret(String);

impl Secret {
    pub fn new(secret: impl Into<String>) -> Self {
        Secret(secret.into())
    }

    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

// Best effort: the header value built from this secret and the HTTP stack's
// buffers are copies this cannot reach.
impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Clone for Secret {
    fn clone(&self) -> Self {
        Secret(self.0.clone())
    }
}

/// A PVE API token: `USER@REALM!TOKENID=SECRET`.
#[derive(Clone, Debug)]
pub struct ApiToken {
    /// `user@realm`, e.g. `root@pam`.
    pub user: String,
    pub token_id: String,
    pub secret: Secret,
}

impl ApiToken {
    pub fn new(user: impl Into<String>, token_id: impl Into<String>, secret: Secret) -> Self {
        ApiToken {
            user: user.into(),
            token_id: token_id.into(),
            secret,
        }
    }

    /// Splits and checks a full token id, `USER@REALM!TOKENID`, as
    /// `(user, token_id)`. Apart from the secret, so that configuration can be
    /// validated before any credential is read. Errors never echo the input:
    /// pasting the whole `...=SECRET` here is an easy mistake.
    pub fn parse_full_id(id: &str) -> Result<(&str, &str), PveError> {
        let (user, token_id) = id.split_once('!').ok_or_else(|| {
            PveError::InvalidRequest("token id must be USER@REALM!TOKENID".into())
        })?;
        check_id(user, token_id)?;
        Ok((user, token_id))
    }

    /// The `Authorization` header value, marked sensitive so the HTTP stack
    /// omits it from its own debug output.
    ///
    /// Errors never include the offending value, only which part was bad.
    pub(crate) fn header_value(&self) -> Result<HeaderValue, PveError> {
        check_id(&self.user, &self.token_id)?;
        if !uuid_shaped(self.secret.expose()) {
            return Err(PveError::InvalidRequest(
                "token secret must be a UUID (8-4-4-4-12 hex digits), as PVE generates".into(),
            ));
        }
        let mut raw = format!(
            "PVEAPIToken={}!{}={}",
            self.user,
            self.token_id,
            self.secret.expose()
        );
        let built = HeaderValue::from_str(&raw);
        raw.zeroize();
        let mut value = built.map_err(|_| {
            PveError::InvalidRequest(
                "token contains characters not allowed in an HTTP header".into(),
            )
        })?;
        value.set_sensitive(true);
        Ok(value)
    }
}

fn check_id(user: &str, token_id: &str) -> Result<(), PveError> {
    if !valid_userid(user) {
        return Err(PveError::InvalidRequest(
            "token user must be user@realm as PVE defines it, without '!', '=', '%' or ';'".into(),
        ));
    }
    if !valid_realm_like(token_id) {
        return Err(PveError::InvalidRequest(
            "token id must be a letter followed by letters, digits, '.', '-' or '_'".into(),
        ));
    }
    Ok(())
}

/// PVE's userid grammar (pve-access-control `PVE::Auth::Plugin`):
/// `verify_username` wants 3 to 64 characters matching
/// `^([^\s:/]+)\@(realm)\z`. PVE itself would accept `!` and `=` in the user
/// part, but they are the delimiters of the token header and PVE only splits
/// such a header correctly by regex backtracking, so they are refused here
/// rather than relied on. `;` and `%` are refused because
/// `PVE::APIServer::Formatter::extract_auth_value` cuts the header value at the
/// first `;` and then `uri_unescape`s it, so either would change what PVE reads.
fn valid_userid(user: &str) -> bool {
    let len = user.chars().count();
    if !(3..=64).contains(&len) {
        return false;
    }
    // The realm cannot contain `@`, so the last one is the separator.
    let Some((name, realm)) = user.rsplit_once('@') else {
        return false;
    };
    !name.is_empty()
        && !name
            .contains(|c: char| c.is_whitespace() || matches!(c, ':' | '/' | '!' | '=' | '%' | ';'))
        && valid_realm_like(realm)
}

/// `[A-Za-z][A-Za-z0-9\.\-_]+`: PVE's `realm_regex`, which it also uses as
/// `token_subid_regex` for token ids (`PVE::AccessControl`).
fn valid_realm_like(s: &str) -> bool {
    let mut bytes = s.bytes();
    matches!(bytes.next(), Some(b) if b.is_ascii_alphabetic())
        && s.len() >= 2
        && bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

/// PVE's `extract_auth_value` stops the header value at the first `;` and
/// `uri_unescape`s it, and `verify_token` splits at the last `=`, so a secret
/// containing `;`, `%XX` or `=` would reach PVE as something else. Secrets
/// are always `UUID::uuid()` (`PVE::TokenConfig::generate_token`), so
/// requiring that shape costs nothing and rules all of those out.
fn uuid_shaped(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, &c)| match i {
            8 | 13 | 18 | 23 => c == b'-',
            _ => c.is_ascii_hexdigit(),
        })
}
