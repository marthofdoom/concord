//! The controls: power, darken (mirroring testbed/nested/darken.sh), and
//! snapshots.
//!
//! Every action first runs the guards darken.sh runs before every action
//! (lib.sh `preflight_common` and `vm_is_ours`), so a guest that is not this
//! estate's node is never stopped or rolled back, whatever its VMID.
//!
//! Dry run sends no write. It still makes the read-only GETs, exactly as
//! `darken.sh --dry-run` does: the guards, and for darken modes the state
//! reads that decide whether a write happens and what sever writes.
//!
//! No call is ever retried, and a failure is never answered with a different
//! or broader call: the first error ends the action and is reported as PVE
//! gave it.

use std::time::Duration;

use concord_pve::{wait_for_task, Method, PveApi, PveError, TaskOutcome};
use serde::Serialize;
use serde_json::Value;

use crate::estate::{paths, Node, PowerVerb, SnapName, Vmid, POOL, VM_TAG, VNET};

/// How often a running task is polled. darken.sh sleeps 5 s between polls; a
/// person is watching here, so 1 s.
const TASK_POLL: Duration = Duration::from_secs(1);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Start,
    Stop,
    Reset,
    Kill,
    Pause,
    Sever,
    Restore,
    SnapshotCreate(SnapName),
    SnapshotRollback(SnapName),
}

impl Action {
    pub fn parse(name: &str, snapname: Option<&str>) -> Result<Action, String> {
        let snap = || -> Result<SnapName, String> {
            SnapName::new(snapname.ok_or("snapname is required for this action")?)
        };
        Ok(match name {
            "start" => Action::Start,
            "stop" => Action::Stop,
            "reset" => Action::Reset,
            "kill" => Action::Kill,
            "pause" => Action::Pause,
            "sever" => Action::Sever,
            "restore" => Action::Restore,
            "snapshot" => Action::SnapshotCreate(snap()?),
            "rollback" => Action::SnapshotRollback(snap()?),
            _ => return Err("unknown action".into()),
        })
    }

    pub fn name(&self) -> &'static str {
        match self {
            Action::Start => "start",
            Action::Stop => "stop",
            Action::Reset => "reset",
            Action::Kill => "kill",
            Action::Pause => "pause",
            Action::Sever => "sever",
            Action::Restore => "restore",
            Action::SnapshotCreate(_) => "snapshot",
            Action::SnapshotRollback(_) => "rollback",
        }
    }
}

/// A call as it is (or would be) sent.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Call {
    pub method: &'static str,
    pub path: String,
    pub params: Vec<(String, String)>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Step {
    pub call: Call,
    /// False in a dry run.
    pub sent: bool,
    pub upid: Option<String>,
    /// `wait_for_task`'s outcome, when the call started a task.
    pub outcome: Option<String>,
}

/// Where the audit trail is written while an action runs, so a write is on
/// record before it is sent and its UPID as soon as PVE returns it, not only
/// when the action ends.
pub trait Recorder: Send + Sync {
    /// Called once, just before the first write is sent. An error stops the
    /// action with nothing sent.
    fn started(&self) -> Result<(), String>;
    /// Called as soon as a write has returned a UPID. An error stops the
    /// sequence: no further write is sent unrecorded.
    fn task(&self, call: &Call, upid: &str) -> Result<(), String>;
}

/// For tests, which check the audit trail through the router instead.
#[cfg(test)]
pub struct NoRecord;

#[cfg(test)]
impl Recorder for NoRecord {
    fn started(&self) -> Result<(), String> {
        Ok(())
    }
    fn task(&self, _: &Call, _: &str) -> Result<(), String> {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionResult {
    Ok,
    DryRun,
    /// darken.sh would have died before writing: a precondition failed.
    Refused,
    /// A task finished with warnings. darken.sh's `wait_task` treats anything
    /// but `OK` as fatal, so the sequence stops here.
    Warnings,
    Failed,
    TimedOut,
    /// A call itself failed (HTTP error, 403 included, or transport).
    Error,
    /// The audit log could not be written, so the action stopped there.
    AuditFailed,
}

impl ActionResult {
    pub fn as_str(self) -> &'static str {
        match self {
            ActionResult::Ok => "ok",
            ActionResult::DryRun => "dry_run",
            ActionResult::Refused => "refused",
            ActionResult::Warnings => "warnings",
            ActionResult::Failed => "failed",
            ActionResult::TimedOut => "timed_out",
            ActionResult::Error => "error",
            ActionResult::AuditFailed => "audit_failed",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub action: &'static str,
    pub vmid: u32,
    pub dry_run: bool,
    pub result: ActionResult,
    /// What was read and decided, in the words darken.sh logs.
    pub log: Vec<String>,
    /// Every write sent or, in a dry run, that would have been sent.
    pub writes: Vec<Step>,
    pub error: Option<String>,
}

enum Stop {
    Refused(String),
    Pve(PveError),
    Task(ActionResult, String),
    Audit(String),
}

impl From<PveError> for Stop {
    fn from(e: PveError) -> Self {
        Stop::Pve(e)
    }
}

struct Exec<'a> {
    api: &'a dyn PveApi,
    node: &'a Node,
    rec: &'a dyn Recorder,
    /// Whether `rec.started()` has been written.
    started: bool,
    dry_run: bool,
    task_timeout: Duration,
    log: Vec<String>,
    writes: Vec<Step>,
}

impl Exec<'_> {
    async fn get(&mut self, path: &str, params: &[(&str, String)]) -> Result<Value, Stop> {
        Ok(self.api.request(Method::Get, path, params).await?)
    }

    /// `api_write` (and with `wait`, `api_write_wait`) from lib.sh.
    async fn write(
        &mut self,
        method: Method,
        path: String,
        params: Vec<(&'static str, String)>,
        wait: bool,
    ) -> Result<(), Stop> {
        let call = Call {
            method: method.as_str(),
            path: path.clone(),
            params: params
                .iter()
                .map(|(k, v)| ((*k).to_string(), v.clone()))
                .collect(),
        };
        if self.dry_run {
            self.writes.push(Step {
                call,
                sent: false,
                upid: None,
                outcome: None,
            });
            return Ok(());
        }
        if !self.started {
            self.rec.started().map_err(|e| {
                Stop::Audit(format!("audit log write failed, so nothing was sent: {e}"))
            })?;
            self.started = true;
        }
        let idx = self.writes.len();
        self.writes.push(Step {
            call,
            sent: true,
            upid: None,
            outcome: None,
        });
        let data = self.api.request(method, &path, &params).await?;
        // Synchronous calls (PUT config) return null; only a UPID is waited on,
        // as in lib.sh's wait_task.
        let Some(upid) = data.as_str().filter(|s| s.starts_with("UPID:")) else {
            return Ok(());
        };
        self.writes[idx].upid = Some(upid.to_string());
        self.rec.task(&self.writes[idx].call, upid).map_err(|e| {
            Stop::Audit(format!(
                "audit log write failed after task {upid} was started; \
                     the sequence stops here: {e}"
            ))
        })?;
        if !wait {
            return Ok(());
        }
        let outcome = wait_for_task(
            self.api,
            self.node.as_str(),
            upid,
            TASK_POLL,
            self.task_timeout,
        )
        .await?;
        let (text, stop) = match &outcome {
            TaskOutcome::Ok => ("OK".to_string(), None),
            TaskOutcome::Warnings(n) => (format!("WARNINGS: {n}"), Some(ActionResult::Warnings)),
            TaskOutcome::Failed(s) => (s.clone(), Some(ActionResult::Failed)),
            TaskOutcome::TimedOut => (
                format!(
                    "still running after {}s (the task continues on the host)",
                    self.task_timeout.as_secs()
                ),
                Some(ActionResult::TimedOut),
            ),
        };
        self.writes[idx].outcome = Some(text.clone());
        match stop {
            None => Ok(()),
            Some(r) => Err(Stop::Task(r, format!("task {upid}: {text}"))),
        }
    }
}

pub async fn run(
    api: &dyn PveApi,
    node: &Node,
    vmid: Vmid,
    action: &Action,
    dry_run: bool,
    task_timeout: Duration,
    rec: &dyn Recorder,
) -> Report {
    let mut ex = Exec {
        api,
        node,
        rec,
        started: false,
        dry_run,
        task_timeout,
        log: Vec::new(),
        writes: Vec::new(),
    };
    let r = dispatch(&mut ex, vmid, action).await;
    let (result, error) = match r {
        Ok(()) if dry_run => (ActionResult::DryRun, None),
        Ok(()) => (ActionResult::Ok, None),
        Err(Stop::Refused(m)) => (ActionResult::Refused, Some(m)),
        Err(Stop::Pve(e)) => (ActionResult::Error, Some(e.to_string())),
        Err(Stop::Task(r, m)) => (r, Some(m)),
        Err(Stop::Audit(m)) => (ActionResult::AuditFailed, Some(m)),
    };
    Report {
        action: action.name(),
        vmid: vmid.get(),
        dry_run,
        result,
        log: ex.log,
        writes: ex.writes,
        error,
    }
}

async fn dispatch(ex: &mut Exec<'_>, vmid: Vmid, action: &Action) -> Result<(), Stop> {
    let node = ex.node.clone();
    guards(ex, &node, vmid).await?;
    match action {
        Action::Start => power(ex, &node, vmid, PowerVerb::Start).await,
        Action::Stop => power(ex, &node, vmid, PowerVerb::Stop).await,
        Action::Reset => power(ex, &node, vmid, PowerVerb::Reset).await,
        Action::SnapshotCreate(name) => {
            let path = paths::snapshots(&node, vmid)?;
            ex.write(
                Method::Post,
                path,
                vec![("snapname", name.as_str().to_string())],
                true,
            )
            .await
        }
        Action::SnapshotRollback(name) => {
            let path = paths::rollback(&node, vmid, name)?;
            ex.write(Method::Post, path, vec![], true).await
        }
        Action::Kill => darken(ex, &node, vmid, Darken::Kill).await,
        Action::Pause => darken(ex, &node, vmid, Darken::Pause).await,
        Action::Sever => darken(ex, &node, vmid, Darken::Sever).await,
        Action::Restore => darken(ex, &node, vmid, Darken::Restore).await,
    }
}

async fn power(ex: &mut Exec<'_>, node: &Node, vmid: Vmid, verb: PowerVerb) -> Result<(), Stop> {
    let path = paths::power(node, vmid, verb)?;
    ex.write(Method::Post, path, vec![], true).await
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Darken {
    Kill,
    Pause,
    Sever,
    Restore,
}

/// `jq -r` output for a value: strings bare, missing as `null`.
fn jq_r(v: Option<&Value>) -> String {
    match v {
        None | Some(Value::Null) => "null".into(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    }
}

/// The guards darken.sh runs before every action: lib.sh `preflight_common`,
/// then `vm_is_ours`. Run here before every action, power and snapshot ones
/// included.
///
/// One deliberate difference: `preflight_common` reads `/cluster/status` to
/// prove the endpoint is the configured node on a standalone host. That needs
/// Sys.Audit on `/`, which the pool-scoped token does not have (observed: 403
/// "Permission check failed (/, Sys.Audit)"). Rather than reach for a broader
/// token, the same two facts are read from `GET /nodes`, which the token can
/// read: exactly one node, and it is the configured one.
async fn guards(ex: &mut Exec<'_>, node: &Node, vmid: Vmid) -> Result<(), Stop> {
    // ---- preflight_common
    let v = ex.get("/version", &[]).await?;
    ex.log
        .push(format!("connected: PVE {}", jq_r(v.get("version"))));
    let nodes = ex.get("/nodes", &[]).await?;
    let names: Vec<String> = nodes
        .as_array()
        .map(|a| a.iter().map(|n| jq_r(n.get("node"))).collect())
        .unwrap_or_default();
    if names.len() != 1 {
        return Err(Stop::Refused(format!(
            "expected a standalone host (exactly one node in /nodes), found {}",
            names.len()
        )));
    }
    if names[0] != node.as_str() {
        return Err(Stop::Refused(format!(
            "this API endpoint is not node '{}'",
            node.as_str()
        )));
    }

    // ---- vm_is_ours
    let name = vmid.expected_name();
    if let Err(why) = vm_is_ours(ex, node, vmid).await? {
        return Err(Stop::Refused(format!(
            "VMID {vmid} is not this estate's {name}; refusing ({why})"
        )));
    }
    Ok(())
}

/// darken.sh, step for step after the guards: the state reads, then the one
/// write per mode.
async fn darken(ex: &mut Exec<'_>, node: &Node, vmid: Vmid, mode: Darken) -> Result<(), Stop> {
    let name = vmid.expected_name();
    // ---- state reads
    let res = vm_resource(ex, vmid)
        .await?
        .ok_or_else(|| Stop::Refused(format!("VMID {vmid} vanished from /cluster/resources")))?;
    // Logged only. The resources `status` is pvestatd's `qmpstatus || status`
    // (pvestatd.pm), so it reads "paused" for a suspended VM (seen live on
    // 9002, PVE 9.2.21) and can be any QMP run state. It cannot say whether a
    // QEMU process exists, which is what kill, sever and restore decide on.
    let res_state = jq_r(res.get("status"));
    let cfg = ex.get(&paths::config(node, vmid)?, &[]).await?;
    let net0 = jq_r(cfg.get("net0"));
    // `status/current` `.status` is the QEMU process state, enum
    // running|stopped in qemu-server's schema, so a paused VM is "running"
    // there and only `qmpstatus` says it is paused.
    let cur = ex.get(&paths::status_current(node, vmid)?, &[]).await?;
    let state = jq_r(cur.get("status"));
    let qmp = match cur.get("qmpstatus") {
        Some(q) if !q.is_null() && q != &Value::Bool(false) => jq_r(Some(q)),
        _ => state.clone(),
    };
    let linkdown = net0.contains("link_down=1");
    ex.log.push(format!(
        "VM {vmid} ({name}): status={state} qmp={qmp} link_down={} (resources status={res_state})",
        if linkdown { "yes" } else { "no" }
    ));
    let mode_name = match mode {
        Darken::Kill => "kill",
        Darken::Pause => "pause",
        Darken::Sever => "sever",
        Darken::Restore => "restore",
    };
    // The states darken acts on, as darken.sh's guard. Any
    // other QMP state of a live process (io-error, internal-error,
    // guest-panicked, shutdown, or one QEMU adds later) is a fault darken did
    // not cause, and a stop, cont or config change would hide it. A
    // `.status` outside the schema's running|stopped enum would otherwise
    // read as stopped and make restore send a start. Both refuse before any
    // write. prelaunch counts as paused, as in PVE's `vm_is_paused`
    // (QemuServer.pm): a VM started paused (vzdump of a stopped VM,
    // live-restore) is left there by an interrupted job, and `vm_resume`
    // (QemuServer/RunState.pm) sends `cont` for it.
    let running = match (state.as_str(), qmp.as_str()) {
        ("stopped", _) => false,
        ("running", "running" | "paused" | "suspended" | "prelaunch") => true,
        _ => {
            return Err(Stop::Refused(format!(
                "VM {vmid} is in an unexpected state (status={state} qmp={qmp}); \
                 refusing '{mode_name}', look at the VM first"
            )))
        }
    };

    let start = paths::power(node, vmid, PowerVerb::Start)?;
    match mode {
        Darken::Kill => {
            if !running {
                return Err(Stop::Refused(format!("VM {vmid} is not running")));
            }
            let p = paths::power(node, vmid, PowerVerb::Stop)?;
            ex.write(Method::Post, p, vec![], true).await?;
        }
        Darken::Pause => {
            if qmp != "running" {
                return Err(Stop::Refused(format!(
                    "VM {vmid} is not in the running state (qmp={qmp})"
                )));
            }
            let p = paths::power(node, vmid, PowerVerb::Suspend)?;
            ex.write(Method::Post, p, vec![], true).await?;
        }
        Darken::Sever => {
            if !running {
                ex.log.push(
                    "VM is not running; the setting is saved and applies at next start".into(),
                );
            }
            if linkdown {
                return Err(Stop::Refused("NIC already severed".into()));
            }
            let p = paths::config(node, vmid)?;
            ex.write(
                Method::Put,
                p,
                vec![("net0", format!("{net0},link_down=1"))],
                false,
            )
            .await?;
        }
        Darken::Restore => {
            // The guard leaves only stopped, or a live process whose qmp
            // state is running or one that resume undoes.
            if !running {
                ex.write(Method::Post, start, vec![], true).await?;
            } else if qmp != "running" {
                let p = paths::power(node, vmid, PowerVerb::Resume)?;
                ex.write(Method::Post, p, vec![], true).await?;
            }
            if linkdown {
                let fixed = net0.replace(",link_down=1", "");
                let p = paths::config(node, vmid)?;
                ex.write(Method::Put, p, vec![("net0", fixed)], false)
                    .await?;
            }
            if qmp == "running" && !linkdown {
                ex.log
                    .push("nothing to restore: VM is running, resumed, and linked".into());
            }
        }
    }
    ex.log.push(format!("done: {mode_name} {name}"));
    Ok(())
}

/// lib.sh `vm_resource`: this VMID's entry in `/cluster/resources?type=vm`.
async fn vm_resource(ex: &mut Exec<'_>, vmid: Vmid) -> Result<Option<Value>, Stop> {
    let all = ex
        .get("/cluster/resources", &[("type", "vm".to_string())])
        .await?;
    Ok(all.as_array().and_then(|a| {
        a.iter()
            .find(|r| r.get("vmid").and_then(Value::as_u64) == Some(u64::from(vmid.get())))
            .cloned()
    }))
}

/// lib.sh `vm_is_ours`: right name, qemu, tagged, NIC on the vnet, in the pool.
///
/// lib.sh's `api_get_try` turns a failed config or pool read into "not ours".
/// Here that failure is carried into the refusal message instead, so a 403
/// is shown as a 403. The outer `Result` is for `/cluster/resources`, which
/// lib.sh reads with `api_get` (fatal on error).
async fn vm_is_ours(
    ex: &mut Exec<'_>,
    node: &Node,
    vmid: Vmid,
) -> Result<Result<(), String>, Stop> {
    let Some(res) = vm_resource(ex, vmid).await? else {
        return Ok(Err("not in /cluster/resources".into()));
    };
    let name = vmid.expected_name();
    if jq_r(res.get("name")) != name {
        return Ok(Err(format!("name is {}", jq_r(res.get("name")))));
    }
    if jq_r(res.get("type")) != "qemu" {
        return Ok(Err(format!("type is {}", jq_r(res.get("type")))));
    }
    let cfg = match ex.get(&paths::config(node, vmid)?, &[]).await {
        Ok(c) => c,
        Err(Stop::Pve(e)) => return Ok(Err(format!("config read failed: {e}"))),
        Err(other) => return Err(other),
    };
    let tags = cfg.get("tags").and_then(Value::as_str).unwrap_or("");
    if !tags.split(';').any(|t| t == VM_TAG) {
        return Ok(Err(format!("not tagged {VM_TAG}")));
    }
    let net0 = cfg.get("net0").and_then(Value::as_str).unwrap_or("");
    let bridge = format!("bridge={VNET}");
    if !net0.split(',').any(|p| p == bridge) {
        return Ok(Err(format!("net0 is not on {VNET}")));
    }
    let members = match ex.get("/pools", &[("poolid", POOL.to_string())]).await {
        Ok(m) => m,
        Err(Stop::Pve(e)) => return Ok(Err(format!("pool read failed: {e}"))),
        Err(other) => return Err(other),
    };
    let in_pool = members
        .get(0)
        .and_then(|p| p.get("members"))
        .and_then(Value::as_array)
        .is_some_and(|m| {
            m.iter()
                .any(|x| x.get("vmid").and_then(Value::as_u64) == Some(u64::from(vmid.get())))
        });
    if !in_pool {
        return Ok(Err(format!("not a member of pool {POOL}")));
    }
    Ok(Ok(()))
}

#[cfg(test)]
mod tests;
