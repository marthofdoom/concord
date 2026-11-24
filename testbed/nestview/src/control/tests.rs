//! Call sequences against MockPve, checked against darken.sh by hand: each
//! expected list below is the order darken.sh (via lib.sh) issues its calls
//! in, with `/cluster/status` replaced by `/nodes` (see `guards`). Power and
//! snapshot actions run the same guards first.

use concord_pve::{api_path, Call as MockCall, MockPve};
use serde_json::{json, Value};

use super::*;

const NET0: &str = "virtio=02:00:00:00:00:01,bridge=cnest";
const UPID: &str = "UPID:pve1:0000ABCD:0000BEEF:65000000:qmstop:9002:concord@pve!nest:";
const T: Duration = Duration::from_secs(5);

fn node() -> Node {
    Node::new("pve1").unwrap()
}

fn vm2() -> Vmid {
    Vmid::new(9002).unwrap()
}

fn task_path(upid: &str) -> String {
    api_path(&["nodes", "pve1", "tasks", upid, "status"]).unwrap()
}

/// A host on which 9002 is this estate's nest2, in the given state. Shapes
/// follow responses captured from a real host.
///
/// `state` is `status/current` `.status` (the QEMU process: running or
/// stopped) and `qmp` its `.qmpstatus`. `/cluster/resources` gets what
/// pvestatd puts there, `qmpstatus || status`, so a paused VM reads "paused"
/// in it, as observed for 9002 on PVE 9.2.21.
fn host(state: &str, qmp: &str, net0: &str) -> MockPve {
    host_tagged(state, qmp, net0, "concord-nest")
}

fn host_tagged(state: &str, qmp: &str, net0: &str, tags: &str) -> MockPve {
    let res_state = if qmp.is_empty() { state } else { qmp };
    let res = json!([
        {"vmid": 9001, "name": "nest1", "type": "qemu", "status": "running", "pool": "concord-nest"},
        {"vmid": 9002, "name": "nest2", "type": "qemu", "status": res_state, "pool": "concord-nest"},
        {"vmid": 100, "name": "other", "type": "lxc", "status": "running"}
    ]);
    MockPve::new()
        .on(Method::Get, "/version", json!({"version": "9.2.21", "release": "9.2", "repoid": "4f6e0ac86f9e8c7f"}))
        .on(Method::Get, "/nodes", json!([{"node": "pve1", "status": "online", "type": "node"}]))
        .on(Method::Get, "/cluster/resources", res)
        .on(
            Method::Get,
            "/nodes/pve1/qemu/9002/config",
            json!({"name": "nest2", "tags": tags, "net0": net0, "agent": "1",
                   "ipconfig0": "ip=10.99.0.12/24,gw=10.99.0.1",
                   "watchdog": "model=i6300esb,action=reset"}),
        )
        .on(
            Method::Get,
            "/pools",
            json!([{"poolid": "concord-nest", "members": [{"vmid": 9001}, {"vmid": 9002}, {"vmid": 9003}]}]),
        )
        .on(
            Method::Get,
            "/nodes/pve1/qemu/9002/status/current",
            json!({"status": state, "qmpstatus": qmp, "vmid": 9002}),
        )
}

fn with_task(m: MockPve, method: Method, path: &str, upid: &str, exit: &str) -> MockPve {
    m.on(method, path, Value::String(upid.into())).on(
        Method::Get,
        &task_path(upid),
        json!({"status": "stopped", "exitstatus": exit}),
    )
}

fn get(path: &str) -> (Method, String) {
    (Method::Get, path.to_string())
}

/// The guards every action runs: preflight_common, then vm_is_ours.
fn estate_guards() -> Vec<(Method, String)> {
    vec![
        get("/version"),
        get("/nodes"),
        // vm_is_ours
        get("/cluster/resources"),
        get("/nodes/pve1/qemu/9002/config"),
        get("/pools"),
    ]
}

/// The reads every darken mode makes before it writes.
fn guard_reads() -> Vec<(Method, String)> {
    let mut v = estate_guards();
    // darken.sh's own reads
    v.extend([
        get("/cluster/resources"),
        get("/nodes/pve1/qemu/9002/config"),
        get("/nodes/pve1/qemu/9002/status/current"),
    ]);
    v
}

fn seq(calls: &[MockCall]) -> Vec<(Method, String)> {
    calls.iter().map(|c| (c.method, c.path.clone())).collect()
}

fn no_writes(calls: &[MockCall]) -> bool {
    calls.iter().all(|c| c.method == Method::Get)
}

async fn go(api: &MockPve, action: Action, dry_run: bool) -> Report {
    run(api, &node(), vm2(), &action, dry_run, T, &NoRecord).await
}

#[tokio::test]
async fn kill_running_stops_hard_and_waits() {
    let api = with_task(
        host("running", "running", NET0),
        Method::Post,
        "/nodes/pve1/qemu/9002/status/stop",
        UPID,
        "OK",
    );
    let r = go(&api, Action::Kill, false).await;
    assert_eq!(r.result, ActionResult::Ok, "{r:?}");
    let mut want = guard_reads();
    want.push((Method::Post, "/nodes/pve1/qemu/9002/status/stop".into()));
    want.push(get(&task_path(UPID)));
    assert_eq!(seq(&api.calls()), want);
    // /cluster/resources is read with type=vm, the pool with poolid, as in lib.sh.
    let calls = api.calls();
    assert_eq!(
        calls[2].params,
        vec![("type".to_string(), "vm".to_string())]
    );
    assert_eq!(
        calls[4].params,
        vec![("poolid".to_string(), "concord-nest".to_string())]
    );
    assert!(calls[8].params.is_empty());
    assert_eq!(r.writes[0].upid.as_deref(), Some(UPID));
    assert_eq!(r.writes[0].outcome.as_deref(), Some("OK"));
}

#[tokio::test]
async fn kill_dry_run_reads_but_sends_no_write() {
    let api = host("running", "running", NET0);
    let r = go(&api, Action::Kill, true).await;
    assert_eq!(r.result, ActionResult::DryRun, "{r:?}");
    assert!(no_writes(&api.calls()));
    assert_eq!(seq(&api.calls()), guard_reads());
    assert_eq!(r.writes.len(), 1);
    assert!(!r.writes[0].sent);
    assert_eq!(r.writes[0].call.method, "POST");
    assert_eq!(r.writes[0].call.path, "/nodes/pve1/qemu/9002/status/stop");
}

#[tokio::test]
async fn kill_refuses_a_stopped_vm() {
    let api = host("stopped", "stopped", NET0);
    let r = go(&api, Action::Kill, false).await;
    assert_eq!(r.result, ActionResult::Refused);
    assert_eq!(r.error.as_deref(), Some("VM 9002 is not running"));
    assert!(no_writes(&api.calls()));
}

#[tokio::test]
async fn pause_suspends_only_a_running_qmp() {
    let api = with_task(
        host("running", "running", NET0),
        Method::Post,
        "/nodes/pve1/qemu/9002/status/suspend",
        UPID,
        "OK",
    );
    let r = go(&api, Action::Pause, false).await;
    assert_eq!(r.result, ActionResult::Ok, "{r:?}");
    let mut want = guard_reads();
    want.push((Method::Post, "/nodes/pve1/qemu/9002/status/suspend".into()));
    want.push(get(&task_path(UPID)));
    assert_eq!(seq(&api.calls()), want);

    // Already paused: status says running, qmpstatus says paused.
    let api = host("running", "paused", NET0);
    let r = go(&api, Action::Pause, false).await;
    assert_eq!(r.result, ActionResult::Refused);
    assert!(no_writes(&api.calls()));
}

#[tokio::test]
async fn sever_sets_link_down_on_net0_without_waiting() {
    let api = host("running", "running", NET0).on(
        Method::Put,
        "/nodes/pve1/qemu/9002/config",
        Value::Null,
    );
    let r = go(&api, Action::Sever, false).await;
    assert_eq!(r.result, ActionResult::Ok, "{r:?}");
    assert!(!r.log.iter().any(|l| l.contains("applies at next start")));
    let mut want = guard_reads();
    want.push((Method::Put, "/nodes/pve1/qemu/9002/config".into()));
    assert_eq!(seq(&api.calls()), want);
    let put = api.calls().pop().unwrap();
    assert_eq!(
        put.params,
        vec![("net0".to_string(), format!("{NET0},link_down=1"))]
    );

    let api = host("running", "running", &format!("{NET0},link_down=1"));
    let r = go(&api, Action::Sever, false).await;
    assert_eq!(r.result, ActionResult::Refused);
    assert_eq!(r.error.as_deref(), Some("NIC already severed"));
    assert!(no_writes(&api.calls()));
}

#[tokio::test]
async fn sever_on_stopped_vm_notes_it_and_still_writes() {
    let api = host("stopped", "stopped", NET0).on(
        Method::Put,
        "/nodes/pve1/qemu/9002/config",
        Value::Null,
    );
    let r = go(&api, Action::Sever, false).await;
    assert_eq!(r.result, ActionResult::Ok);
    assert!(r.log.iter().any(|l| l.contains("applies at next start")));
}

#[tokio::test]
async fn restore_undoes_kill_and_sever_in_darken_order() {
    let start_upid = "UPID:pve1:00000001:00000002:65000000:qmstart:9002:concord@pve!nest:";
    let api = with_task(
        host("stopped", "stopped", &format!("{NET0},link_down=1")),
        Method::Post,
        "/nodes/pve1/qemu/9002/status/start",
        start_upid,
        "OK",
    )
    .on(Method::Put, "/nodes/pve1/qemu/9002/config", Value::Null);
    let r = go(&api, Action::Restore, false).await;
    assert_eq!(r.result, ActionResult::Ok, "{r:?}");
    let mut want = guard_reads();
    want.push((Method::Post, "/nodes/pve1/qemu/9002/status/start".into()));
    want.push(get(&task_path(start_upid)));
    want.push((Method::Put, "/nodes/pve1/qemu/9002/config".into()));
    assert_eq!(seq(&api.calls()), want);
    assert_eq!(
        api.calls().pop().unwrap().params,
        vec![("net0".to_string(), NET0.to_string())]
    );
}

#[tokio::test]
async fn restore_resumes_a_paused_vm() {
    let api = with_task(
        host("running", "paused", NET0),
        Method::Post,
        "/nodes/pve1/qemu/9002/status/resume",
        UPID,
        "OK",
    );
    let r = go(&api, Action::Restore, false).await;
    assert_eq!(r.result, ActionResult::Ok, "{r:?}");
    let mut want = guard_reads();
    want.push((Method::Post, "/nodes/pve1/qemu/9002/status/resume".into()));
    want.push(get(&task_path(UPID)));
    assert_eq!(seq(&api.calls()), want);
}

#[tokio::test]
async fn restore_of_a_paused_vm_never_sends_start() {
    // The live failure on a real host: /cluster/resources said "paused", so
    // restore sent status/start, PVE answered "VM 9002 already running", and
    // resume was never reached. Now: resume only.
    let api = with_task(
        host("running", "paused", NET0),
        Method::Post,
        "/nodes/pve1/qemu/9002/status/resume",
        UPID,
        "OK",
    );
    let r = go(&api, Action::Restore, false).await;
    assert_eq!(r.result, ActionResult::Ok, "{r:?}");
    assert_eq!(
        api.calls()[5].params,
        vec![("type".to_string(), "vm".to_string())]
    );
    let writes: Vec<&str> = r.writes.iter().map(|w| w.call.path.as_str()).collect();
    assert_eq!(writes, vec!["/nodes/pve1/qemu/9002/status/resume"]);
    assert!(
        r.log
            .iter()
            .any(|l| l.contains("status=running qmp=paused")
                && l.contains("resources status=paused")),
        "{:?}",
        r.log
    );
}

#[tokio::test]
async fn restore_of_a_paused_severed_vm_resumes_then_relinks() {
    let api = with_task(
        host("running", "paused", &format!("{NET0},link_down=1")),
        Method::Post,
        "/nodes/pve1/qemu/9002/status/resume",
        UPID,
        "OK",
    )
    .on(Method::Put, "/nodes/pve1/qemu/9002/config", Value::Null);
    let r = go(&api, Action::Restore, false).await;
    assert_eq!(r.result, ActionResult::Ok, "{r:?}");
    let mut want = guard_reads();
    want.push((Method::Post, "/nodes/pve1/qemu/9002/status/resume".into()));
    want.push(get(&task_path(UPID)));
    want.push((Method::Put, "/nodes/pve1/qemu/9002/config".into()));
    assert_eq!(seq(&api.calls()), want);
    assert_eq!(
        api.calls().pop().unwrap().params,
        vec![("net0".to_string(), NET0.to_string())]
    );

    // The dry run plans the same two writes and sends neither.
    let api = host("running", "paused", &format!("{NET0},link_down=1"));
    let r = go(&api, Action::Restore, true).await;
    assert_eq!(r.result, ActionResult::DryRun);
    assert!(no_writes(&api.calls()));
    let planned: Vec<(&str, &str)> = r
        .writes
        .iter()
        .map(|s| (s.call.method, s.call.path.as_str()))
        .collect();
    assert_eq!(
        planned,
        vec![
            ("POST", "/nodes/pve1/qemu/9002/status/resume"),
            ("PUT", "/nodes/pve1/qemu/9002/config"),
        ]
    );
}

#[tokio::test]
async fn kill_stops_a_paused_vm() {
    let api = with_task(
        host("running", "paused", NET0),
        Method::Post,
        "/nodes/pve1/qemu/9002/status/stop",
        UPID,
        "OK",
    );
    let r = go(&api, Action::Kill, false).await;
    assert_eq!(r.result, ActionResult::Ok, "{r:?}");
    let mut want = guard_reads();
    want.push((Method::Post, "/nodes/pve1/qemu/9002/status/stop".into()));
    want.push(get(&task_path(UPID)));
    assert_eq!(seq(&api.calls()), want);
}

#[tokio::test]
async fn sever_on_a_paused_vm_does_not_say_next_start() {
    let api = host("running", "paused", NET0).on(
        Method::Put,
        "/nodes/pve1/qemu/9002/config",
        Value::Null,
    );
    let r = go(&api, Action::Sever, false).await;
    assert_eq!(r.result, ActionResult::Ok, "{r:?}");
    assert!(!r.log.iter().any(|l| l.contains("applies at next start")));
    let mut want = guard_reads();
    want.push((Method::Put, "/nodes/pve1/qemu/9002/config".into()));
    assert_eq!(seq(&api.calls()), want);
    assert_eq!(
        api.calls().pop().unwrap().params,
        vec![("net0".to_string(), format!("{NET0},link_down=1"))]
    );
}

#[tokio::test]
async fn status_outside_the_schema_enum_refuses_every_darken_mode() {
    // status/current `.status` is enum running|stopped; anything else must
    // not be read as "stopped" (which would make restore send a start).
    for action in [Action::Kill, Action::Pause, Action::Sever, Action::Restore] {
        let api = host("prelaunch", "prelaunch", NET0);
        let r = go(&api, action.clone(), false).await;
        assert_eq!(r.result, ActionResult::Refused, "{action:?}: {r:?}");
        assert_eq!(
            r.error,
            Some(format!(
                "VM 9002 is in an unexpected state (status=prelaunch qmp=prelaunch); \
                 refusing '{}', look at the VM first",
                action.name()
            ))
        );
        assert!(no_writes(&api.calls()));
        assert!(r.writes.is_empty());
    }
}

/// darken.sh's guard: a live process in a QMP state darken
/// cannot undo is a fault to look at, so every mode refuses, names the
/// state, and sends nothing, dry run or not.
#[tokio::test]
async fn faulted_qmp_states_refuse_every_darken_mode_without_writes() {
    for qmp in [
        "io-error",
        "internal-error",
        "guest-panicked",
        "shutdown",
        "watchdog",
        "colo",
    ] {
        for net0 in [NET0.to_string(), format!("{NET0},link_down=1")] {
            for action in [Action::Kill, Action::Pause, Action::Sever, Action::Restore] {
                for dry_run in [false, true] {
                    let api = host("running", qmp, &net0);
                    let r = go(&api, action.clone(), dry_run).await;
                    assert_eq!(r.result, ActionResult::Refused, "{qmp} {action:?}: {r:?}");
                    assert_eq!(
                        r.error,
                        Some(format!(
                            "VM 9002 is in an unexpected state (status=running qmp={qmp}); \
                             refusing '{}', look at the VM first",
                            action.name()
                        ))
                    );
                    assert_eq!(seq(&api.calls()), guard_reads());
                    assert!(r.writes.is_empty());
                    assert!(!r.log.iter().any(|l| l.starts_with("nothing to restore")));
                }
            }
        }
    }
}

#[tokio::test]
async fn restore_of_a_prelaunch_vm_sends_exactly_one_resume() {
    let api = with_task(
        host("running", "prelaunch", NET0),
        Method::Post,
        "/nodes/pve1/qemu/9002/status/resume",
        UPID,
        "OK",
    );
    let r = go(&api, Action::Restore, false).await;
    assert_eq!(r.result, ActionResult::Ok, "{r:?}");
    let mut want = guard_reads();
    want.push((Method::Post, "/nodes/pve1/qemu/9002/status/resume".into()));
    want.push(get(&task_path(UPID)));
    assert_eq!(seq(&api.calls()), want);
    let writes: Vec<&str> = r.writes.iter().map(|w| w.call.path.as_str()).collect();
    assert_eq!(writes, vec!["/nodes/pve1/qemu/9002/status/resume"]);
    assert!(!r.log.iter().any(|l| l.starts_with("nothing to restore")));
}

#[tokio::test]
async fn kill_stops_a_prelaunch_vm() {
    let api = with_task(
        host("running", "prelaunch", NET0),
        Method::Post,
        "/nodes/pve1/qemu/9002/status/stop",
        UPID,
        "OK",
    );
    let r = go(&api, Action::Kill, false).await;
    assert_eq!(r.result, ActionResult::Ok, "{r:?}");
    let mut want = guard_reads();
    want.push((Method::Post, "/nodes/pve1/qemu/9002/status/stop".into()));
    want.push(get(&task_path(UPID)));
    assert_eq!(seq(&api.calls()), want);
}

#[tokio::test]
async fn pause_refuses_a_prelaunch_or_suspended_vm() {
    for qmp in ["prelaunch", "suspended"] {
        let api = host("running", qmp, NET0);
        let r = go(&api, Action::Pause, false).await;
        assert_eq!(r.result, ActionResult::Refused, "{qmp}: {r:?}");
        assert_eq!(
            r.error,
            Some(format!("VM 9002 is not in the running state (qmp={qmp})"))
        );
        assert!(no_writes(&api.calls()));
    }
}

#[tokio::test]
async fn sever_on_a_prelaunch_vm_writes_link_down_now() {
    let api = host("running", "prelaunch", NET0).on(
        Method::Put,
        "/nodes/pve1/qemu/9002/config",
        Value::Null,
    );
    let r = go(&api, Action::Sever, false).await;
    assert_eq!(r.result, ActionResult::Ok, "{r:?}");
    assert!(!r.log.iter().any(|l| l.contains("applies at next start")));
    assert_eq!(
        api.calls().pop().unwrap().params,
        vec![("net0".to_string(), format!("{NET0},link_down=1"))]
    );
}

#[tokio::test]
async fn stopped_vm_is_accepted_whatever_qmpstatus_says() {
    // darken.sh accepts `stopped:*`: with no process, qmpstatus is only a
    // copy of status (QemuServer.pm), so it is no fault to look at.
    let api = with_task(
        host("stopped", "", NET0),
        Method::Post,
        "/nodes/pve1/qemu/9002/status/start",
        UPID,
        "OK",
    );
    let r = go(&api, Action::Restore, false).await;
    assert_eq!(r.result, ActionResult::Ok, "{r:?}");
    let writes: Vec<&str> = r.writes.iter().map(|w| w.call.path.as_str()).collect();
    assert_eq!(writes, vec!["/nodes/pve1/qemu/9002/status/start"]);
}

#[tokio::test]
async fn nothing_to_restore_only_when_running_and_linked() {
    // A severed running VM is relinked, and that is not "nothing".
    let api = host("running", "running", &format!("{NET0},link_down=1")).on(
        Method::Put,
        "/nodes/pve1/qemu/9002/config",
        Value::Null,
    );
    let r = go(&api, Action::Restore, false).await;
    assert_eq!(r.result, ActionResult::Ok, "{r:?}");
    let writes: Vec<&str> = r.writes.iter().map(|w| w.call.path.as_str()).collect();
    assert_eq!(writes, vec!["/nodes/pve1/qemu/9002/config"]);
    assert!(!r.log.iter().any(|l| l.starts_with("nothing to restore")));

    // A paused VM gets resumed, also not "nothing".
    let api = with_task(
        host("running", "paused", NET0),
        Method::Post,
        "/nodes/pve1/qemu/9002/status/resume",
        UPID,
        "OK",
    );
    let r = go(&api, Action::Restore, false).await;
    assert_eq!(r.result, ActionResult::Ok, "{r:?}");
    assert!(!r.log.iter().any(|l| l.starts_with("nothing to restore")));
}

#[tokio::test]
async fn restore_with_nothing_to_do_writes_nothing() {
    let api = host("running", "running", NET0);
    let r = go(&api, Action::Restore, false).await;
    assert_eq!(r.result, ActionResult::Ok);
    assert!(no_writes(&api.calls()));
    assert!(r
        .log
        .iter()
        .any(|l| l == "nothing to restore: VM is running, resumed, and linked"));
}

#[tokio::test]
async fn restore_dry_run_lists_every_write_and_sends_none() {
    let api = host("stopped", "stopped", &format!("{NET0},link_down=1"));
    let r = go(&api, Action::Restore, true).await;
    assert_eq!(r.result, ActionResult::DryRun);
    assert!(no_writes(&api.calls()));
    let planned: Vec<(&str, &str)> = r
        .writes
        .iter()
        .map(|s| (s.call.method, s.call.path.as_str()))
        .collect();
    assert_eq!(
        planned,
        vec![
            ("POST", "/nodes/pve1/qemu/9002/status/start"),
            ("PUT", "/nodes/pve1/qemu/9002/config"),
        ]
    );
    assert_eq!(
        r.writes[1].call.params,
        vec![("net0".to_string(), NET0.to_string())]
    );
}

#[tokio::test]
async fn task_warnings_stop_the_sequence_like_wait_task() {
    let start_upid = "UPID:pve1:00000001:00000002:65000000:qmstart:9002:concord@pve!nest:";
    let api = with_task(
        host("stopped", "stopped", &format!("{NET0},link_down=1")),
        Method::Post,
        "/nodes/pve1/qemu/9002/status/start",
        start_upid,
        "WARNINGS: 1",
    );
    let r = go(&api, Action::Restore, false).await;
    assert_eq!(r.result, ActionResult::Warnings);
    // The config PUT that would follow is never sent.
    assert!(!api.calls().iter().any(|c| c.method == Method::Put));
}

#[tokio::test]
async fn foreign_vm_is_refused_before_any_write() {
    let api = host_tagged("running", "running", NET0, "other");
    let r = go(&api, Action::Kill, false).await;
    assert_eq!(r.result, ActionResult::Refused, "{r:?}");
    assert!(r.error.unwrap().contains("not this estate's nest2"));
    assert!(no_writes(&api.calls()));
}

#[tokio::test]
async fn power_and_snapshot_refuse_a_foreign_vm_before_any_write() {
    let snap = SnapName::new("s1").unwrap();
    for action in [
        Action::Start,
        Action::Stop,
        Action::Reset,
        Action::SnapshotCreate(snap.clone()),
        Action::SnapshotRollback(snap.clone()),
    ] {
        // A guest that holds the VMID but is not the estate's (no tag).
        let api = host_tagged("running", "running", NET0, "");
        let r = go(&api, action.clone(), false).await;
        assert_eq!(r.result, ActionResult::Refused, "{action:?}: {r:?}");
        assert!(r.error.unwrap().contains("not tagged concord-nest"));
        assert!(no_writes(&api.calls()));
        assert!(r.writes.is_empty());
    }
}

/// Records what the audit trail sees, and can be told to fail.
#[derive(Default)]
struct Rec {
    fail_started: bool,
    fail_task: bool,
    seen: std::sync::Mutex<Vec<String>>,
}

impl Recorder for Rec {
    fn started(&self) -> Result<(), String> {
        self.seen.lock().unwrap().push("started".into());
        if self.fail_started {
            Err("disk full".into())
        } else {
            Ok(())
        }
    }
    fn task(&self, call: &Call, upid: &str) -> Result<(), String> {
        self.seen
            .lock()
            .unwrap()
            .push(format!("task {} {upid}", call.path));
        if self.fail_task {
            Err("disk full".into())
        } else {
            Ok(())
        }
    }
}

#[tokio::test]
async fn audit_rows_are_written_before_the_write_and_on_each_upid() {
    let api = with_task(
        host("running", "running", NET0),
        Method::Post,
        "/nodes/pve1/qemu/9002/status/stop",
        UPID,
        "OK",
    );
    let rec = Rec::default();
    let r = run(&api, &node(), vm2(), &Action::Kill, false, T, &rec).await;
    assert_eq!(r.result, ActionResult::Ok);
    assert_eq!(
        *rec.seen.lock().unwrap(),
        vec![
            "started".to_string(),
            format!("task /nodes/pve1/qemu/9002/status/stop {UPID}")
        ]
    );

    // Dry runs and refusals never write a started row.
    let rec = Rec::default();
    let api = host("running", "running", NET0);
    run(&api, &node(), vm2(), &Action::Kill, true, T, &rec).await;
    let api = host("stopped", "stopped", NET0);
    run(&api, &node(), vm2(), &Action::Kill, false, T, &rec).await;
    assert!(rec.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn failed_started_row_sends_nothing() {
    let api = host("running", "running", NET0);
    let rec = Rec {
        fail_started: true,
        ..Rec::default()
    };
    let r = run(&api, &node(), vm2(), &Action::Kill, false, T, &rec).await;
    assert_eq!(r.result, ActionResult::AuditFailed);
    assert!(r.error.unwrap().contains("nothing was sent"));
    assert!(no_writes(&api.calls()));
}

#[tokio::test]
async fn failed_task_row_stops_the_sequence() {
    let start_upid = "UPID:pve1:00000001:00000002:65000000:qmstart:9002:concord@pve!nest:";
    let api = with_task(
        host("stopped", "stopped", &format!("{NET0},link_down=1")),
        Method::Post,
        "/nodes/pve1/qemu/9002/status/start",
        start_upid,
        "OK",
    )
    .on(Method::Put, "/nodes/pve1/qemu/9002/config", Value::Null);
    let rec = Rec {
        fail_task: true,
        ..Rec::default()
    };
    let r = run(&api, &node(), vm2(), &Action::Restore, false, T, &rec).await;
    assert_eq!(r.result, ActionResult::AuditFailed);
    assert_eq!(r.writes[0].upid.as_deref(), Some(start_upid));
    // The un-sever PUT is not sent unrecorded.
    assert!(!api.calls().iter().any(|c| c.method == Method::Put));
}

#[tokio::test]
async fn permission_failure_is_surfaced_and_not_retried() {
    let api = MockPve::new().on_err(
        Method::Get,
        "/version",
        PveError::Http {
            status: 403,
            message: "Permission check failed (/, Sys.Audit)\n".into(),
            errors: None,
        },
    );
    let r = go(&api, Action::Kill, false).await;
    assert_eq!(r.result, ActionResult::Error);
    assert!(r.error.unwrap().contains("403"));
    assert_eq!(api.calls().len(), 1);

    // A 403 on the write itself: one attempt, reported as is.
    let api = host("running", "running", NET0).on_err(
        Method::Post,
        "/nodes/pve1/qemu/9002/status/stop",
        PveError::Http {
            status: 403,
            message: "Permission check failed (/vms/9002, VM.PowerMgmt)\n".into(),
            errors: None,
        },
    );
    let r = go(&api, Action::Kill, false).await;
    assert_eq!(r.result, ActionResult::Error);
    assert!(r.error.unwrap().contains("VM.PowerMgmt"));
    assert_eq!(
        api.calls()
            .iter()
            .filter(|c| c.method != Method::Get)
            .count(),
        1
    );
}

#[tokio::test]
async fn power_and_snapshot_dry_runs_run_the_guards_and_send_no_write() {
    let snap = SnapName::new("before-fence").unwrap();
    for (action, method, path, params) in [
        (
            Action::Start,
            "POST",
            "/nodes/pve1/qemu/9002/status/start",
            vec![],
        ),
        (
            Action::Stop,
            "POST",
            "/nodes/pve1/qemu/9002/status/stop",
            vec![],
        ),
        (
            Action::Reset,
            "POST",
            "/nodes/pve1/qemu/9002/status/reset",
            vec![],
        ),
        (
            Action::SnapshotCreate(snap.clone()),
            "POST",
            "/nodes/pve1/qemu/9002/snapshot",
            vec![("snapname".to_string(), "before-fence".to_string())],
        ),
        (
            Action::SnapshotRollback(snap.clone()),
            "POST",
            "/nodes/pve1/qemu/9002/snapshot/before-fence/rollback",
            vec![],
        ),
    ] {
        let api = host("running", "running", NET0);
        let r = go(&api, action, true).await;
        assert_eq!(r.result, ActionResult::DryRun);
        assert_eq!(seq(&api.calls()), estate_guards());
        assert_eq!(r.writes.len(), 1);
        assert_eq!(r.writes[0].call.method, method);
        assert_eq!(r.writes[0].call.path, path);
        assert_eq!(r.writes[0].call.params, params);
        assert!(!r.writes[0].sent);
    }
}

#[tokio::test]
async fn snapshot_create_waits_and_reports_failure_outcome() {
    let api = with_task(
        host("running", "running", NET0),
        Method::Post,
        "/nodes/pve1/qemu/9002/snapshot",
        UPID,
        "snapshot feature is not available",
    );
    let r = go(
        &api,
        Action::SnapshotCreate(SnapName::new("s1").unwrap()),
        false,
    )
    .await;
    assert_eq!(r.result, ActionResult::Failed);
    assert_eq!(
        r.writes[0].outcome.as_deref(),
        Some("snapshot feature is not available")
    );
}

#[test]
fn snapshot_names_follow_pve_configid() {
    assert!(SnapName::new("before-fence_1").is_ok());
    for bad in [
        "",
        "a",
        "1abc",
        "current",
        "Pending",
        "a/b",
        "a..b",
        &"a".repeat(41),
    ] {
        assert!(SnapName::new(bad).is_err(), "{bad}");
    }
    assert!(Action::parse("snapshot", None).is_err());
    assert!(Action::parse("delete", None).is_err());
}
