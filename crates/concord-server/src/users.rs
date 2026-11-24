//! The users file: who may use the API, as hashes only.
//!
//! The running server re-checks the file's identity on every request and reloads
//! it when it changed, so a removal takes effect on the next request with no
//! signal to send or forget. A file that stops being readable or valid refuses
//! everyone rather than leaving the previous users in force.

use std::collections::{HashMap, HashSet};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use concord_config::{lock_beside, read_private, write_private, ConfigError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub const MIN_PASSWORD: usize = 12;
/// Longer is refused unhashed.
pub const MAX_PASSWORD: usize = 1024;
const MAX_NAME: usize = 64;
const TOKEN_PREFIX: &str = "concord_";

/// OWASP's argon2id baseline: 19 MiB, two passes, one lane.
const M_COST: u32 = 19 * 1024;
const T_COST: u32 = 2;
const P_COST: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    #[value(name = "readonly")]
    ReadOnly,
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Role::Admin => "admin",
            Role::ReadOnly => "readonly",
        })
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct User {
    pub name: String,
    pub role: Role,
    pub(crate) password_hash: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Token {
    pub name: String,
    pub role: Role,
    sha256: String,
}

/// A parsed and checked users file.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Users {
    #[serde(default)]
    pub users: Vec<User>,
    #[serde(default)]
    pub tokens: Vec<Token>,
}

#[derive(Debug, thiserror::Error)]
pub enum UsersError {
    #[error(transparent)]
    File(#[from] ConfigError),
    #[error("users file {}: {reason}", path.display())]
    Content { path: PathBuf, reason: String },
    #[error("writing {}: {source}", path.display())]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("{0}")]
    Refused(String),
}

fn refused(s: impl Into<String>) -> UsersError {
    UsersError::Refused(s.into())
}

fn argon() -> Result<Argon2<'static>, UsersError> {
    let params = Params::new(M_COST, T_COST, P_COST, None)
        .map_err(|e| refused(format!("argon2 parameters: {e}")))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// Random bytes from the operating system.
pub(crate) fn random<const N: usize>() -> Result<Zeroizing<[u8; N]>, UsersError> {
    let mut b = Zeroizing::new([0u8; N]);
    getrandom::getrandom(&mut b[..]).map_err(|e| refused(format!("no randomness: {e}")))?;
    Ok(b)
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

pub(crate) fn digest(s: &str) -> [u8; 32] {
    Sha256::digest(s.as_bytes()).into()
}

/// An argon2id PHC string.
pub(crate) fn hash_password(password: &str) -> Result<String, UsersError> {
    let salt = random::<16>()?;
    let salt = SaltString::encode_b64(&salt[..]).map_err(|e| refused(format!("salt: {e}")))?;
    argon()?
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| refused(format!("hashing failed: {e}")))
}

/// Slow by design; call it off the async threads.
pub(crate) fn verify_password(phc: &str, password: &str) -> bool {
    let (Ok(hash), Ok(argon)) = (PasswordHash::new(phc), argon()) else {
        return false;
    };
    argon.verify_password(password.as_bytes(), &hash).is_ok()
}

/// Our own parameters and nothing else: a costlier hash would be a way to
/// exhaust the server, and a cheaper one would tell its user's logins apart
/// from an unknown user's by timing.
fn acceptable_hash(phc: &str) -> bool {
    let Ok(h) = PasswordHash::new(phc) else {
        return false;
    };
    let Ok(p) = Params::try_from(&h) else {
        return false;
    };
    h.algorithm == argon2::ARGON2ID_IDENT
        && h.version == Some(Version::V0x13.into())
        && h.salt.is_some()
        && h.hash
            .is_some_and(|o| o.len() == Params::DEFAULT_OUTPUT_LEN)
        && (p.m_cost(), p.t_cost(), p.p_cost()) == (M_COST, T_COST, P_COST)
}

fn check_name(name: &str) -> Result<(), UsersError> {
    let starts = name
        .bytes()
        .next()
        .is_some_and(|b| b.is_ascii_alphanumeric());
    let rest = name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'@'));
    if starts && rest && name.len() <= MAX_NAME {
        Ok(())
    } else {
        Err(refused(format!(
            "a name must start with a letter or digit, contain only letters, digits, '.', '-', \
             '_' and '@', and be at most {MAX_NAME} long"
        )))
    }
}

impl Users {
    /// A file that does not exist has no users; any other fault is an error.
    pub fn load(path: &Path) -> Result<Users, UsersError> {
        let text = match read_private(path) {
            Ok(t) => t,
            Err(ConfigError::Read { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                return Ok(Users::default())
            }
            Err(e) => return Err(e.into()),
        };
        let content = |reason: String| UsersError::Content {
            path: path.to_path_buf(),
            reason,
        };
        let users: Users = toml::from_str(&text).map_err(|e| {
            // Only where: the parser's own text quotes the line, hash and all.
            let at = e.span().map_or(0, |s| s.start);
            let line = 1 + text.bytes().take(at).filter(|b| *b == b'\n').count();
            content(format!("invalid near line {line}"))
        })?;
        users.check().map_err(|e| content(e.to_string()))?;
        Ok(users)
    }

    fn check(&self) -> Result<(), UsersError> {
        let mut seen = HashSet::new();
        for u in &self.users {
            check_name(&u.name)?;
            if !seen.insert(&u.name) {
                return Err(refused(format!("user {} is listed twice", u.name)));
            }
            if !acceptable_hash(&u.password_hash) {
                return Err(refused(format!(
                    "user {}: not a password hash made by `concord user add`",
                    u.name
                )));
            }
        }
        let mut seen = HashSet::new();
        let mut hashes = HashSet::new();
        for t in &self.tokens {
            check_name(&t.name)?;
            if !seen.insert(&t.name) || !hashes.insert(&t.sha256) {
                return Err(refused(format!("token {} is listed twice", t.name)));
            }
            let hex_ok = t
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
            if t.sha256.len() != 64 || !hex_ok {
                return Err(refused(format!("token {}: sha256 is malformed", t.name)));
            }
        }
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.users.is_empty() && self.tokens.is_empty()
    }

    /// Read, change and write back, excluding other writers throughout.
    fn edit<T>(
        path: &Path,
        change: impl FnOnce(&mut Users) -> Result<T, UsersError>,
    ) -> Result<T, UsersError> {
        let write_err = |source| UsersError::Write {
            path: path.to_path_buf(),
            source,
        };
        let _lock = lock_beside(path).map_err(write_err)?;
        let mut users = Users::load(path)?;
        let out = change(&mut users)?;
        users.check()?;
        let text =
            Zeroizing::new(toml::to_string(&users).map_err(|e| refused(format!("encoding: {e}")))?);
        write_private(path, &text).map_err(write_err)?;
        Ok(out)
    }

    pub fn add_user(path: &Path, name: &str, role: Role, password: &str) -> Result<(), UsersError> {
        check_name(name)?;
        if password.chars().count() < MIN_PASSWORD || password.len() > MAX_PASSWORD {
            return Err(refused(format!(
                "a password must be {MIN_PASSWORD} characters to {MAX_PASSWORD} bytes long"
            )));
        }
        let password_hash = hash_password(password)?;
        Users::edit(path, |f| {
            if f.users.iter().any(|u| u.name == name) {
                return Err(refused(format!("user {name} exists; remove it first")));
            }
            f.users.push(User {
                name: name.into(),
                role,
                password_hash,
            });
            Ok(())
        })
    }

    pub fn remove_user(path: &Path, name: &str) -> Result<(), UsersError> {
        Users::edit(path, |f| {
            let before = f.users.len();
            f.users.retain(|u| u.name != name);
            if f.users.len() == before {
                return Err(refused(format!("no user {name}")));
            }
            Ok(())
        })
    }

    /// The new token's secret, which is stored nowhere.
    pub fn add_token(path: &Path, name: &str, role: Role) -> Result<Zeroizing<String>, UsersError> {
        check_name(name)?;
        let secret = Zeroizing::new(format!("{TOKEN_PREFIX}{}", hex(&random::<32>()?[..])));
        let sha256 = hex(&digest(&secret));
        Users::edit(path, |f| {
            if f.tokens.iter().any(|t| t.name == name) {
                return Err(refused(format!("token {name} exists; remove it first")));
            }
            f.tokens.push(Token {
                name: name.into(),
                role,
                sha256,
            });
            Ok(secret)
        })
    }

    pub fn remove_token(path: &Path, name: &str) -> Result<(), UsersError> {
        Users::edit(path, |f| {
            let before = f.tokens.len();
            f.tokens.retain(|t| t.name != name);
            if f.tokens.len() == before {
                return Err(refused(format!("no token {name}")));
            }
            Ok(())
        })
    }

    pub(crate) fn user(&self, name: &str) -> Option<&User> {
        self.users.iter().find(|u| u.name == name)
    }
}

/// Which version of the file was read. Every write renames a new inode in.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Stamp(u64, u64, u64, i64, i64);

/// The users file, followed as it changes.
pub(crate) struct Store {
    path: PathBuf,
    seen: Mutex<Option<(Option<Stamp>, Arc<Loaded>)>>,
}

#[derive(Default)]
pub(crate) struct Loaded {
    pub(crate) users: Users,
    by_hash: HashMap<String, usize>,
}

impl Loaded {
    fn new(users: Users) -> Self {
        // Keyed by hash, so lookup timing says nothing about live secrets.
        let by_hash = users
            .tokens
            .iter()
            .enumerate()
            .map(|(i, t)| (t.sha256.clone(), i))
            .collect();
        Loaded { users, by_hash }
    }

    pub(crate) fn token(&self, secret: &str) -> Option<&Token> {
        let i = self.by_hash.get(&hex(&digest(secret)))?;
        self.users.tokens.get(*i)
    }
}

impl Store {
    pub(crate) fn new(path: PathBuf) -> Self {
        Store {
            path,
            seen: Mutex::new(None),
        }
    }

    pub(crate) fn current(&self) -> Arc<Loaded> {
        let mut seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        // Stamped before it is read: a change in between is seen next time.
        let stamp = match std::fs::metadata(&self.path) {
            Ok(m) => Some(Stamp(m.dev(), m.ino(), m.size(), m.ctime(), m.ctime_nsec())),
            Err(_) => None,
        };
        if let Some((s, l)) = &*seen {
            if *s == stamp {
                return l.clone();
            }
        }
        let users = Users::load(&self.path).unwrap_or_else(|e| {
            tracing::error!(error = %e, "cannot use the users file; refusing everyone");
            Users::default()
        });
        tracing::info!(
            users = users.users.len(),
            tokens = users.tokens.len(),
            "users file loaded"
        );
        if users.is_empty() {
            tracing::warn!(
                "no API users; add one with `concord user add NAME --role admin`. \
                 Until then every API request is refused"
            );
        }
        let loaded = Arc::new(Loaded::new(users));
        *seen = Some((stamp, loaded.clone()));
        loaded
    }
}
