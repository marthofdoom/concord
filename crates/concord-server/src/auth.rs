//! Who is asking, and whether they may.
//!
//! Every API route sits behind [`require`]; see [`crate::router`] for how that
//! is made hard to forget.

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use axum::extract::rejection::JsonRejection;
use axum::extract::{Extension, Request, State};
use axum::http::header::{AUTHORIZATION, COOKIE, HOST, ORIGIN, RETRY_AFTER, SET_COOKIE};
use axum::http::{header::WWW_AUTHENTICATE, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use concord_pve::{LoginOutcome, PveError, RootLogin, TfaChallenge};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use zeroize::Zeroizing;

use crate::users::{
    digest, hash_password, hex, random, verify_password, Role, Store, Unusable, UsersError,
    MAX_PASSWORD,
};
use crate::{coded, error};

/// Over TLS the name carries `__Host-`, which makes the browser refuse one set
/// by another host or over plain http. Cookies ignore the port, so two
/// instances forwarded to one loopback name share this and log each other out.
pub const SESSION_COOKIE: &str = "concord_session";
pub const SESSION_COOKIE_TLS: &str = "__Host-concord_session";
pub const SESSION_PATH: &str = "/api/v1/session";
/// A cross-site page cannot set this without a preflight nothing here answers.
pub const CSRF_HEADER: &str = "x-concord-request";

/// Sessions one user may hold; a login beyond this ends their oldest. The map
/// is therefore bounded by the number of users.
const SESSIONS_PER_USER: usize = 16;
/// Failed logins per source address per window.
const FAIL_LIMIT: u32 = 5;
const FAIL_WINDOW: Duration = Duration::from_secs(60);
/// Addresses remembered.
const MAX_SOURCES: usize = 4096;
/// Each hash holds 19 MiB and a core, so this bounds what logins can cost, and
/// how fast passwords can be guessed from any number of addresses.
const HASHES_AT_ONCE: usize = 2;
const HASH_WAIT: Duration = Duration::from_secs(5);

/// Checks one host is asked to make at once. Per host, so that a hung one holds
/// up nobody else's sign-in; and apart from the hashes, so not local users'.
const PVE_AT_ONCE: usize = 4;
/// Logins waiting for a slot of one host.
const PVE_QUEUE: usize = 16;
const PVE_WAIT: Duration = Duration::from_secs(5);
/// PVE's own ticket lifetime.
const PVE_ABSOLUTE: Duration = Duration::from_secs(2 * 3600);
/// No refusal of `root@...` comes sooner after its check began, whether or not
/// there is such a host.
/// Past the three seconds PVE holds a refusal back for.
const PVE_FLOOR: Duration = Duration::from_secs(5);
const CHALLENGE_LIFE: Duration = Duration::from_secs(120);
/// Each one took a right password to get.
const MAX_CHALLENGES: usize = 32;
const MAX_TFA: usize = 128;

/// The authenticated caller, as a request extension. Serialisable so that an
/// instance forwarding a write can say on whose behalf.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    pub user: String,
    pub role: Role,
    pub via: Via,
    pub source: Source,
}

/// Who vouched for the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    /// The users file.
    Local,
    /// A PVE host, for its root.
    Pve,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Via {
    Session,
    Token,
}

/// The connection's remote address, set by the listener.
#[derive(Clone, Copy, Debug)]
pub struct Peer(pub SocketAddr);

#[derive(Clone, Debug)]
pub struct AuthConfig {
    pub users_file: PathBuf,
    /// Whether clients reach this server over TLS.
    pub tls: bool,
    pub idle: Duration,
    pub absolute: Duration,
    /// Hosts whose root may sign in as `root@<name>`.
    pub pve: Vec<(String, RootLogin)>,
    pub pve_absolute: Duration,
    pub pve_floor: Duration,
    pub challenge_life: Duration,
}

impl AuthConfig {
    pub fn new(users_file: PathBuf, tls: bool) -> Self {
        AuthConfig {
            users_file,
            tls,
            idle: Duration::from_secs(30 * 60),
            absolute: Duration::from_secs(12 * 3600),
            pve: Vec::new(),
            pve_absolute: PVE_ABSOLUTE,
            pve_floor: PVE_FLOOR,
            challenge_life: CHALLENGE_LIFE,
        }
    }
}

struct Session {
    user: String,
    /// The hash logged in against. A user removed and added again, or given a
    /// new password, has a new one, and this session is then worth nothing.
    /// `None` for a PVE host's root, whom the users file says nothing about.
    password_hash: Option<String>,
    created: Instant,
    used: Instant,
}

impl Session {
    fn source(&self) -> Source {
        match self.password_hash {
            Some(_) => Source::Local,
            None => Source::Pve,
        }
    }
}

struct PveHost {
    name: String,
    login: RootLogin,
    slots: Slots,
}

struct Slots {
    run: Arc<Semaphore>,
    queue: Semaphore,
}

impl Slots {
    fn new() -> Self {
        Slots {
            run: Arc::new(Semaphore::new(PVE_AT_ONCE)),
            queue: Semaphore::new(PVE_QUEUE),
        }
    }

    async fn take(&self) -> Option<OwnedSemaphorePermit> {
        let _queued = self.queue.try_acquire().ok()?;
        let got = tokio::time::timeout(PVE_WAIT, self.run.clone().acquire_owned()).await;
        got.ok()?.ok()
    }
}

/// A password accepted by `host`, awaiting the second factor.
struct Pending {
    host: usize,
    from: IpAddr,
    tfa: TfaChallenge,
    created: Instant,
}

struct Failures {
    count: u32,
    since: Instant,
}

pub struct Auth {
    cfg: AuthConfig,
    store: Store,
    /// Verified against when the user does not exist, so that takes as long.
    dummy: String,
    /// Keyed by the SHA-256 of the cookie, so lookup timing says nothing about
    /// live ids.
    sessions: Mutex<HashMap<[u8; 32], Session>>,
    failures: Mutex<HashMap<IpAddr, Failures>>,
    hashes: Arc<Semaphore>,
    pve: Vec<PveHost>,
    /// What an unknown host is queued on, so that it queues the same.
    no_host: Slots,
    pending: Mutex<HashMap<[u8; 32], Pending>>,
}

// Nothing panics while one of these is held with the map half changed.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Auth {
    pub fn new(cfg: AuthConfig) -> Result<Arc<Auth>, UsersError> {
        let dummy = hash_password(&hex(&random::<32>()?[..]))?;
        let auth = Auth {
            store: Store::new(cfg.users_file.clone(), !cfg.pve.is_empty()),
            pve: cfg
                .pve
                .iter()
                .map(|(name, login)| PveHost {
                    name: name.clone(),
                    login: login.clone(),
                    slots: Slots::new(),
                })
                .collect(),
            no_host: Slots::new(),
            pending: Mutex::default(),
            cfg,
            dummy,
            sessions: Mutex::new(HashMap::new()),
            failures: Mutex::new(HashMap::new()),
            hashes: Arc::new(Semaphore::new(HASHES_AT_ONCE)),
        };
        // Loaded now so that its warnings are in the start-up log.
        let _ = auth.store.current();
        Ok(Arc::new(auth))
    }

    /// The challenges there still are; the rest, and their tickets, go.
    fn pending(&self, now: Instant) -> MutexGuard<'_, HashMap<[u8; 32], Pending>> {
        let mut map = lock(&self.pending);
        map.retain(|_, p| now.duration_since(p.created) < self.cfg.challenge_life);
        map
    }

    fn live(&self, s: &Session, now: Instant) -> bool {
        now.duration_since(s.used) < self.cfg.idle
            && now.duration_since(s.created) < self.lifetime(s.source())
    }

    fn lifetime(&self, source: Source) -> Duration {
        match source {
            Source::Local => self.cfg.absolute,
            Source::Pve => self.cfg.absolute.min(self.cfg.pve_absolute),
        }
    }

    fn start_session(
        &self,
        user: &str,
        password_hash: Option<&str>,
        now: Instant,
    ) -> Result<Zeroizing<String>, UsersError> {
        let id = Zeroizing::new(hex(&random::<32>()?[..]));
        let theirs =
            |s: &Session| s.user == user && s.password_hash.is_some() == password_hash.is_some();
        let mut map = lock(&self.sessions);
        map.retain(|_, s| self.live(s, now));
        while map.values().filter(|s| theirs(s)).count() >= SESSIONS_PER_USER {
            let oldest = map
                .iter()
                .filter(|(_, s)| theirs(s))
                .min_by_key(|(_, s)| s.used)
                .map(|(k, _)| *k);
            match oldest {
                Some(k) => map.remove(&k),
                None => break,
            };
        }
        map.insert(
            digest(&id),
            Session {
                user: user.into(),
                password_hash: password_hash.map(Into::into),
                created: now,
                used: now,
            },
        );
        Ok(id)
    }

    fn session(&self, id: &str, now: Instant) -> Result<Option<Identity>, Unusable> {
        // A session outlives a file that cannot be read just now; it is not
        // honoured meanwhile.
        let loaded = self.store.current()?;
        let key = digest(id);
        let mut map = lock(&self.sessions);
        let Some(s) = map.get_mut(&key) else {
            return Ok(None);
        };
        // The role is the file's, not the login's: a demotion is immediate.
        let role = match &s.password_hash {
            None => Some(Role::Admin),
            Some(hash) => loaded
                .users
                .user(&s.user)
                .filter(|u| u.password_hash == *hash)
                .map(|u| u.role),
        };
        match role {
            Some(role) if self.live(s, now) => {
                s.used = now;
                Ok(Some(Identity {
                    user: s.user.clone(),
                    role,
                    via: Via::Session,
                    source: s.source(),
                }))
            }
            _ => {
                map.remove(&key);
                Ok(None)
            }
        }
    }

    fn end_session(&self, id: &str) {
        lock(&self.sessions).remove(&digest(id));
    }

    /// Counts an attempt before it is checked, so that parallel guesses cannot
    /// all pass the limit together. `Err` is how long to wait.
    fn begin_attempt(&self, from: IpAddr, now: Instant) -> Result<(), Duration> {
        let mut map = lock(&self.failures);
        if !map.contains_key(&from) && map.len() >= MAX_SOURCES {
            map.retain(|_, f| now.duration_since(f.since) < FAIL_WINDOW);
            if map.len() >= MAX_SOURCES {
                if let Some(k) = map.iter().min_by_key(|(_, f)| f.since).map(|(k, _)| *k) {
                    map.remove(&k);
                }
            }
        }
        let f = map.entry(from).or_insert(Failures {
            count: 0,
            since: now,
        });
        let age = now.duration_since(f.since);
        if age >= FAIL_WINDOW {
            *f = Failures {
                count: 0,
                since: now,
            };
        } else if f.count >= FAIL_LIMIT {
            return Err(FAIL_WINDOW - age);
        }
        f.count += 1;
        Ok(())
    }

    /// Takes back one attempt, and no more: a success must not forgive the
    /// guesses made beside it.
    fn refund_attempt(&self, from: IpAddr) {
        if let Some(f) = lock(&self.failures).get_mut(&from) {
            f.count = f.count.saturating_sub(1);
        }
    }

    fn identify(&self, headers: &HeaderMap) -> Result<Option<Identity>, Unusable> {
        // A bad Authorization header is not excused by a good cookie: the
        // caller must get the identity it named, or none.
        if headers.contains_key(AUTHORIZATION) {
            let Some(secret) = bearer(headers) else {
                return Ok(None);
            };
            let loaded = self.store.current()?;
            return Ok(loaded.token(secret).map(|t| Identity {
                user: t.name.clone(),
                role: t.role,
                via: Via::Token,
                source: Source::Local,
            }));
        }
        match self.cookie(headers) {
            Some(id) => self.session(id, Instant::now()),
            None => Ok(None),
        }
    }

    fn cookie_name(&self) -> &'static str {
        if self.cfg.tls {
            SESSION_COOKIE_TLS
        } else {
            SESSION_COOKIE
        }
    }

    /// `None` when there are several: something else on this host name is
    /// setting cookies, and which one the browser puts first is not a basis to
    /// choose on.
    fn cookie<'a>(&self, headers: &'a HeaderMap) -> Option<&'a str> {
        let mut found = headers
            .get_all(COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(';'))
            .filter_map(|p| p.trim().split_once('='))
            .filter(|(k, _)| *k == self.cookie_name())
            .map(|(_, v)| v);
        let id = found.next()?;
        found.next().is_none().then_some(id)
    }

    fn set_cookie(&self, id: &str, max_age: u64) -> Option<HeaderValue> {
        let secure = if self.cfg.tls { "; Secure" } else { "" };
        let v = Zeroizing::new(format!(
            "{}={id}; HttpOnly; SameSite=Strict; Path=/; Max-Age={max_age}{secure}",
            self.cookie_name()
        ));
        let mut v = HeaderValue::from_str(&v).ok()?;
        v.set_sensitive(true);
        Some(v)
    }

    fn same_origin(&self, headers: &HeaderMap) -> bool {
        let mut origins = headers.get_all(ORIGIN).iter();
        let Some(origin) = origins.next() else {
            return true;
        };
        let mut hosts = headers.get_all(HOST).iter();
        let (Some(host), None, None) = (hosts.next(), hosts.next(), origins.next()) else {
            return false;
        };
        let (Ok(origin), Ok(host)) = (origin.to_str(), host.to_str()) else {
            return false;
        };
        let scheme = if self.cfg.tls { "https" } else { "http" };
        origin.eq_ignore_ascii_case(&format!("{scheme}://{host}"))
    }
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    let mut all = headers.get_all(AUTHORIZATION).iter();
    let v = all.next()?.to_str().ok()?;
    if all.next().is_some() {
        return None;
    }
    let (scheme, secret) = v.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then_some(secret)
}

fn unauthorized() -> Response {
    let mut r = error(StatusCode::UNAUTHORIZED, "authentication required");
    r.headers_mut()
        .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    r
}

/// Not 401: that would tell a client its credentials are no longer good.
fn unusable() -> Response {
    coded(
        StatusCode::SERVICE_UNAVAILABLE,
        "users_unusable",
        "the users file cannot be used; see the server log",
    )
}

/// The gate in front of every API route.
pub(crate) async fn require(
    State(auth): State<Arc<Auth>>,
    mut req: Request,
    next: Next,
) -> Response {
    let on_session = req.uri().path() == SESSION_PATH;
    // Logging in is the one thing done without an identity.
    if on_session && req.method() == Method::POST {
        return next.run(req).await;
    }
    let who = match auth.identify(req.headers()) {
        Ok(Some(who)) => who,
        Ok(None) => return unauthorized(),
        Err(Unusable) => return unusable(),
    };
    if !matches!(*req.method(), Method::GET | Method::HEAD) {
        if who.via == Via::Session {
            let marked = req
                .headers()
                .get(CSRF_HEADER)
                .is_some_and(|v| v.as_bytes() == b"1");
            if !marked || !auth.same_origin(req.headers()) {
                return error(
                    StatusCode::FORBIDDEN,
                    "cross-site request refused: needs X-Concord-Request: 1 from the same origin",
                );
            }
        }
        let own_session = on_session && req.method() == Method::DELETE;
        if who.role != Role::Admin && !own_session {
            return error(StatusCode::FORBIDDEN, "read-only: this needs an admin");
        }
    }
    req.extensions_mut().insert(who);
    next.run(req).await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Credentials {
    username: Option<String>,
    password: Option<Zeroizing<String>>,
    challenge: Option<String>,
    tfa: Option<Zeroizing<String>>,
}

const WRONG: &str = "wrong username or password";

/// One bucket per IPv4 address or IPv6 /64, the least a subscriber gets.
fn source(peer: Option<Extension<Peer>>) -> IpAddr {
    bucket(peer.map_or(IpAddr::V6(Ipv6Addr::UNSPECIFIED), |Extension(p)| p.0.ip()))
}

pub(crate) fn bucket(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from_bits(v6.to_bits() & !u128::from(u64::MAX))),
        v4 => v4,
    }
}

pub(crate) async fn login(
    Extension(auth): Extension<Arc<Auth>>,
    peer: Option<Extension<Peer>>,
    headers: HeaderMap,
    body: Result<Json<Credentials>, JsonRejection>,
) -> Response {
    let from = source(peer);
    // Login CSRF: signing a victim in as someone else.
    if !auth.same_origin(&headers) {
        return error(StatusCode::FORBIDDEN, "cross-site login refused");
    }
    let usage = "expected JSON {\"username\", \"password\"} or {\"challenge\", \"tfa\"}";
    let given = match body {
        Ok(Json(c)) => c,
        // Not the rejection's own text, which quotes the body.
        Err(r) => return error(r.status(), usage),
    };
    let (username, password) = match given {
        Credentials {
            username: Some(u),
            password: Some(p),
            challenge: None,
            tfa: None,
        } => (u, p),
        Credentials {
            username: None,
            password: None,
            challenge: Some(c),
            tfa: Some(t),
        } => return second_factor(&auth, from, &headers, &c, t).await,
        _ => return error(StatusCode::UNPROCESSABLE_ENTITY, usage),
    };
    let Ok(loaded) = auth.store.current() else {
        return unusable();
    };
    let user = loaded.users.user(&username).cloned();
    // A local user by such a name goes first, and its password to no host.
    if user.is_none() && !auth.pve.is_empty() {
        if let Some(host) = username.strip_prefix("root@") {
            return pve_login(&auth, from, &headers, host, password).await;
        }
    }
    // A name that is not a user's may well be a password typed in the wrong
    // field, so it is never logged.
    let audit_name = user
        .as_ref()
        .map_or_else(|| "<unknown>".to_string(), |u| u.name.clone());
    if let Err(wait) = auth.begin_attempt(from, Instant::now()) {
        return throttled(&audit_name, from, wait);
    }
    let permit = tokio::time::timeout(HASH_WAIT, auth.hashes.clone().acquire_owned()).await;
    let Ok(Ok(permit)) = permit else {
        auth.refund_attempt(from);
        return error(StatusCode::SERVICE_UNAVAILABLE, "too many logins at once");
    };
    let phc = user
        .as_ref()
        .map_or_else(|| auth.dummy.clone(), |u| u.password_hash.clone());
    let known = user.is_some();
    let checked = tokio::task::spawn_blocking(move || {
        // Held and audited here, not in the request: a client that hangs up
        // must not free the slot while its hash is still running, nor hide it.
        let _permit = permit;
        let ok = password.len() <= MAX_PASSWORD && verify_password(&phc, &password) && known;
        audit_check(&audit_name, from, ok);
        ok
    })
    .await
    .unwrap_or(false);
    let Some(user) = user.filter(|_| checked) else {
        return error(StatusCode::UNAUTHORIZED, WRONG);
    };
    auth.refund_attempt(from);
    let hash = Some(user.password_hash.as_str());
    open(&auth, &headers, &user.name, user.role, hash, from)
}

/// An accepted check is a login only once the client gets its session.
fn audit_check(user: &str, from: IpAddr, ok: bool) {
    if ok {
        tracing::info!(target: "audit", %user, %from, "credentials accepted");
    } else {
        tracing::warn!(target: "audit", %user, %from, "login refused");
    }
}

fn throttled(user: &str, from: IpAddr, wait: Duration) -> Response {
    tracing::warn!(target: "audit", %user, %from, "login throttled");
    let mut r = error(StatusCode::TOO_MANY_REQUESTS, "too many failed logins");
    r.headers_mut()
        .insert(RETRY_AFTER, HeaderValue::from(wait.as_secs().max(1)));
    r
}

fn open(
    auth: &Auth,
    headers: &HeaderMap,
    user: &str,
    role: Role,
    hash: Option<&str>,
    from: IpAddr,
) -> Response {
    if let Some(old) = auth.cookie(headers) {
        auth.end_session(old);
    }
    let source = hash.map_or(Source::Pve, |_| Source::Local);
    let cookie = auth
        .start_session(user, hash, Instant::now())
        .ok()
        .and_then(|id| auth.set_cookie(&id, auth.lifetime(source).as_secs()));
    let Some(cookie) = cookie else {
        return error(StatusCode::INTERNAL_SERVER_ERROR, "cannot start a session");
    };
    tracing::info!(target: "audit", %user, %role, ?source, %from, "login");
    (StatusCode::NO_CONTENT, [(SET_COOKIE, cookie)]).into_response()
}

fn busy(auth: &Auth, from: IpAddr) -> Response {
    auth.refund_attempt(from);
    error(StatusCode::SERVICE_UNAVAILABLE, "too many logins at once")
}

async fn pve_login(
    auth: &Arc<Auth>,
    from: IpAddr,
    headers: &HeaderMap,
    host: &str,
    password: Zeroizing<String>,
) -> Response {
    let found = auth.pve.iter().position(|h| h.name == host);
    let host = found.map(|i| &auth.pve[i]);
    let name = host.map_or_else(|| "<unknown>".into(), |h| format!("root@{}", h.name));
    if let Err(wait) = auth.begin_attempt(from, Instant::now()) {
        return throttled(&name, from, wait);
    }
    let Some(permit) = host.map_or(&auth.no_host, |h| &h.slots).take().await else {
        return busy(auth, from);
    };
    let login = host
        .filter(|_| password.len() <= MAX_PASSWORD)
        .map(|h| h.login.clone());
    let check = async move {
        match login {
            Some(l) => l.check(&password).await,
            None => Ok(LoginOutcome::Refused),
        }
    };
    match (found, run_check(auth, permit, &name, from, check).await) {
        (Some(_), Some(LoginOutcome::Accepted)) => {
            auth.refund_attempt(from);
            open(auth, headers, &name, Role::Admin, None, from)
        }
        (Some(i), Some(LoginOutcome::NeedTfa(tfa))) => challenge(auth, from, i, tfa),
        (_, None) => unreachable_host(),
        (_, Some(_)) => error(StatusCode::UNAUTHORIZED, WRONG),
    }
}

/// `None` is a check that could not be made.
///
/// In a task of its own: PVE holds a refusal back, so a client that hung up
/// before it would otherwise have its answer, and no audit line, and its slot
/// back. One is spawned per slot. Only the request makes a session or a
/// challenge, so a client that is gone gets neither.
async fn run_check(
    auth: &Auth,
    permit: OwnedSemaphorePermit,
    name: &str,
    from: IpAddr,
    check: impl Future<Output = Result<LoginOutcome, PveError>> + Send + 'static,
) -> Option<LoginOutcome> {
    let (name, floor) = (name.to_string(), auth.cfg.pve_floor);
    let task = tokio::spawn(async move {
        // Held to the end of the wait, so that a refusal costs the same slot
        // time whichever host was named; and the wait starts here, so that it
        // takes as long however long the queue was.
        let _permit = permit;
        let began = Instant::now();
        let outcome = match check.await {
            Ok(LoginOutcome::NeedTfa(tfa)) => {
                tracing::info!(target: "audit", user = %name, %from, "second factor needed");
                return Some(LoginOutcome::NeedTfa(tfa));
            }
            Ok(LoginOutcome::Accepted) => {
                audit_check(&name, from, true);
                return Some(LoginOutcome::Accepted);
            }
            Ok(LoginOutcome::Refused) => {
                audit_check(&name, from, false);
                Some(LoginOutcome::Refused)
            }
            Err(e) => {
                tracing::warn!(target: "audit", user = %name, %from, error = %e, "login not checked");
                None
            }
        };
        tokio::time::sleep(floor.saturating_sub(began.elapsed())).await;
        outcome
    });
    task.await.ok().flatten()
}

/// The attempt is not refunded: that would be unlimited tries at a host.
fn unreachable_host() -> Response {
    coded(
        StatusCode::SERVICE_UNAVAILABLE,
        "host_unreachable",
        "that host could not be reached, or not trusted, to check the password",
    )
}

/// Not a login, and the attempt stays counted until it is one.
fn challenge(auth: &Auth, from: IpAddr, host: usize, tfa: TfaChallenge) -> Response {
    let mut kinds = Vec::new();
    if tfa.totp {
        kinds.push("totp");
    }
    if tfa.recovery {
        kinds.push("recovery");
    }
    if kinds.is_empty() {
        return coded(
            StatusCode::NOT_IMPLEMENTED,
            "tfa_not_supported",
            "this account's second factor is not supported here; only TOTP and recovery keys are",
        );
    }
    let Ok(id) = random::<32>().map(|b| hex(&b[..])) else {
        return error(StatusCode::INTERNAL_SERVER_ERROR, "no randomness");
    };
    let now = Instant::now();
    let mut map = auth.pending(now);
    if map.len() >= MAX_CHALLENGES {
        if let Some(k) = map.iter().min_by_key(|(_, p)| p.created).map(|(k, _)| *k) {
            map.remove(&k);
        }
    }
    map.insert(
        digest(&id),
        Pending {
            host,
            from,
            tfa,
            created: now,
        },
    );
    drop(map);
    let body = json!({ "error": "second factor needed", "tfa": kinds, "challenge": id });
    (StatusCode::UNAUTHORIZED, Json(body)).into_response()
}

async fn second_factor(
    auth: &Arc<Auth>,
    from: IpAddr,
    headers: &HeaderMap,
    id: &str,
    response: Zeroizing<String>,
) -> Response {
    const REFUSED: &str = "second factor refused; sign in again";
    let began = Instant::now();
    if let Err(wait) = auth.begin_attempt(from, began) {
        return throttled("<second factor>", from, wait);
    }
    let none = || {
        tracing::warn!(target: "audit", %from, "second factor refused: no such challenge");
        error(StatusCode::UNAUTHORIZED, REFUSED)
    };
    let key = digest(id);
    let host = auth
        .pending(began)
        .get(&key)
        .filter(|p| p.from == from)
        .map(|p| p.host);
    let Some(host) = host.map(|i| &auth.pve[i]) else {
        return none();
    };
    let Some(permit) = host.slots.take().await else {
        return busy(auth, from);
    };
    // A local user by the host's name, or a file that can no longer be used,
    // may have come about since the password.
    let Ok(loaded) = auth.store.current() else {
        return unusable();
    };
    // Taken before it is tried, but after the queue: one answer each, and it
    // is not spent on being turned away.
    let Some(p) = auth.pending(Instant::now()).remove(&key) else {
        return none();
    };
    let name = format!("root@{}", host.name);
    let login = (response.len() <= MAX_TFA && loaded.users.user(&name).is_none())
        .then(|| host.login.clone());
    let check = async move {
        Ok(match login {
            Some(l) if l.respond(&p.tfa, &response).await? => LoginOutcome::Accepted,
            _ => LoginOutcome::Refused,
        })
    };
    match run_check(auth, permit, &name, from, check).await {
        Some(LoginOutcome::Accepted) => {
            // This attempt, and the password's that led to it.
            auth.refund_attempt(from);
            auth.refund_attempt(from);
            open(auth, headers, &name, Role::Admin, None, from)
        }
        Some(_) => error(StatusCode::UNAUTHORIZED, REFUSED),
        None => unreachable_host(),
    }
}

pub(crate) async fn whoami(Extension(who): Extension<Identity>) -> Response {
    Json(json!({ "user": who.user, "role": who.role, "source": who.source })).into_response()
}

pub(crate) async fn logout(
    Extension(auth): Extension<Arc<Auth>>,
    Extension(who): Extension<Identity>,
    headers: HeaderMap,
) -> Response {
    // A token has no session of its own, and must not end one it was sent beside.
    if who.via == Via::Session {
        if let Some(id) = auth.cookie(&headers) {
            auth.end_session(id);
            tracing::info!(target: "audit", user = %who.user, "logout");
        }
    }
    match auth.set_cookie("", 0) {
        Some(c) => (StatusCode::NO_CONTENT, [(SET_COOKIE, c)]).into_response(),
        None => StatusCode::NO_CONTENT.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::users::Users;

    fn setup() -> (tempfile::TempDir, Arc<Auth>) {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("users.toml");
        Users::add_user(&f, "user1@pve", Role::Admin, "correct horse battery").unwrap();
        let a = Auth::new(AuthConfig::new(f, false)).unwrap();
        (d, a)
    }

    #[test]
    fn sessions_expire_idle_and_absolute_and_are_capped() {
        let (_d, a) = setup();
        let hash = a.store.current().unwrap().users.users[0]
            .password_hash
            .clone();
        let t0 = Instant::now();
        let idle = a.cfg.idle;
        let id = a.start_session("user1@pve", Some(&hash), t0).unwrap();
        assert!(a.session(&id, t0 + idle / 2).unwrap().is_some());
        assert!(
            a.session(&id, t0 + idle).unwrap().is_some(),
            "use renews idle"
        );
        assert!(a.session(&id, t0 + idle * 2).unwrap().is_none());
        let id = a.start_session("user1@pve", Some(&hash), t0).unwrap();
        let mut t = t0;
        while t + idle / 2 < t0 + a.cfg.absolute {
            t += idle / 2;
            assert!(a.session(&id, t).unwrap().is_some());
        }
        assert!(a.session(&id, t0 + a.cfg.absolute).unwrap().is_none());
        for _ in 0..SESSIONS_PER_USER * 2 {
            a.start_session("user1@pve", Some(&hash), t0).unwrap();
        }
        assert_eq!(lock(&a.sessions).len(), SESSIONS_PER_USER);
    }

    #[test]
    fn throttle_is_per_source_refundable_and_bounded() {
        let (_d, a) = setup();
        let t = Instant::now();
        let ip = |n: u32| IpAddr::V4(std::net::Ipv4Addr::from_bits(n));
        for _ in 0..FAIL_LIMIT {
            a.begin_attempt(ip(1), t).unwrap();
        }
        assert!(a.begin_attempt(ip(1), t).is_err());
        assert!(a.begin_attempt(ip(2), t).is_ok());
        a.refund_attempt(ip(1));
        assert!(a.begin_attempt(ip(1), t).is_ok());
        assert!(a.begin_attempt(ip(1), t).is_err());
        assert!(a.begin_attempt(ip(1), t + FAIL_WINDOW).is_ok());
        for n in 0..MAX_SOURCES as u32 * 2 {
            let _ = a.begin_attempt(ip(n), t);
        }
        assert!(lock(&a.failures).len() <= MAX_SOURCES);
    }

    #[test]
    fn ipv6_is_bucketed_by_64() {
        let peer = |n: u128| {
            let ip = Ipv6Addr::from_bits((0x2001_0db8u128 << 96) | n);
            Some(Extension(Peer(SocketAddr::from((ip, 1)))))
        };
        assert_eq!(source(peer(1)), source(peer(2)));
        assert_ne!(source(peer(1)), source(peer(1 << 64)));
    }

    #[test]
    fn a_pve_session_is_admin_and_ends_at_two_hours_however_used() {
        let (_d, a) = setup();
        let t0 = Instant::now();
        let id = a.start_session("root@pve1", None, t0).unwrap();
        let who = a.session(&id, t0).unwrap().unwrap();
        assert_eq!((who.role, who.source), (Role::Admin, Source::Pve));
        let mut t = t0;
        while t + a.cfg.idle / 2 < t0 + PVE_ABSOLUTE {
            t += a.cfg.idle / 2;
            assert!(a.session(&id, t).unwrap().is_some());
        }
        assert!(a.session(&id, t0 + PVE_ABSOLUTE).unwrap().is_none());
        let id = a.start_session("root@pve1", None, t0).unwrap();
        assert!(a.session(&id, t0 + a.cfg.idle).unwrap().is_none());
    }
}
