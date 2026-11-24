//! Second half of sanitising a capture: removes what the *values* tell about an
//! estate once its names are gone. Guest ids, dates, sizes, counters, uptimes
//! and hardware details identify a host as well as a hostname does, and a long
//! backup list is a schedule.
//!
//! What stays is the contract: field names, JSON types, numbers sent as strings,
//! zero against non-zero, enum values, ordering, and the agreement between
//! fields that carry the same fact (a UPID and the fields beside it, an
//! archive's name and its `ctime`, a guest's id wherever it appears).
//!
//! [`normalise`] is idempotent, so "is this committed fixture normalised" is
//! the same question as "does normalising it change nothing"; a test asks it.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use serde_json::{json, Value};

use crate::capture::Entry;
use crate::sanitize::{decode, encode};

/// 2026-01-01T00:00:00Z. Every date becomes a whole number of hours after it,
/// numbered in the order of the originals.
const EPOCH_BASE: u64 = 1_767_225_600;
const EPOCH_STEP: u64 = 3600;
/// Smaller values in a time field are not dates (the probe UPID's `00000001`).
const EPOCH_MIN: u64 = 1_000_000_000;
const TASK_PID: u64 = 0x1000;
const TASK_PSTART: u64 = 0x10000;

/// Guests whose endpoints were captured are numbered from here, so a replayed
/// capture picks the same ones.
const FIRST_VMID: u64 = 101;
/// Any other guest id (a list entry, an archive, a task) from here: above the
/// captured ones and the test estate's, which the committed fixtures keep.
const FIRST_OTHER_VMID: u64 = 9101;

/// The capture's deliberate miss: the one id that is never a real guest's.
const PROBE_VMID: u64 = 999_999_999;

/// Ids of the documented test estate, which the committed fixtures were
/// captured with and still carry. Only those fixtures are checked with these
/// kept: on any other host the same numbers are somebody's real guests.
#[cfg(test)]
pub(crate) const TEST_ESTATE_VMIDS: &[u64] = &[9001, 9002, 9003, 9004];

const GIB: u64 = 1 << 30;
const FAILED: &str = "command 'placeholder' failed: exit code 1";

/// Rewrites a sanitised capture in place. Takes the whole set, because ids and
/// dates are numbered over all of it.
pub fn normalise(entries: &mut [Entry]) {
    normalise_keeping(entries, &[]);
}

/// [`normalise`], leaving the guest ids in `keep` as they are.
pub(crate) fn normalise_keeping(entries: &mut [Entry], keep: &[u64]) {
    let kept = |id: u64| id == PROBE_VMID || keep.contains(&id);
    for e in entries.iter_mut() {
        e.path = map_path(&e.path, &generic_task);
        each_body(e, &mut |v| task_outcomes(v));
    }
    let captured = captured_vmids(entries, &kept);
    for e in entries.iter_mut() {
        trim(e, &captured);
    }

    let mut seen = Seen::default();
    for e in entries.iter_mut() {
        for seg in e.path.split('/').map(decode).collect::<Vec<_>>() {
            seen.string(&seg);
        }
        seen.ids.extend(guest_in_path(&e.path));
        each_body(e, &mut |v| seen.value(None, v));
    }
    let maps = Maps::new(&seen, &captured, &kept);

    for e in entries.iter_mut() {
        if let Some(id) = guest_in_path(&e.path) {
            let new = maps.vmid(id);
            e.path = map_path(&e.path, &|s| {
                if s == id.to_string() {
                    new.to_string()
                } else {
                    s.to_string()
                }
            });
        }
        e.path = map_path(&e.path, &|s| maps.string(s));
        for (_, v) in e.params.iter_mut() {
            *v = maps.string(v);
        }
        if let Err(b) = &mut e.result {
            b.message = maps.string(&b.message);
        }
        each_body(e, &mut |v| maps.value(None, v));
    }
}

fn each_body(e: &mut Entry, f: &mut dyn FnMut(&mut Value)) {
    match &mut e.result {
        Ok(v) => f(v),
        Err(b) => {
            if let Some(v) = &mut b.errors {
                f(v);
            }
        }
    }
}

fn map_path(path: &str, f: &dyn Fn(&str) -> String) -> String {
    path.split('/')
        .filter(|s| !s.is_empty())
        .map(|s| format!("/{}", encode(&f(&decode(s)))))
        .collect()
}

/// `/nodes/{n}/(qemu|lxc)/{vmid}[/...]`
fn guest_in_path(path: &str) -> Option<u64> {
    let segs: Vec<&str> = path.split('/').collect();
    segs.windows(2)
        .find(|w| matches!(w[0], "qemu" | "lxc"))
        .and_then(|w| w[1].parse().ok())
}

fn captured_vmids(entries: &[Entry], kept: &dyn Fn(u64) -> bool) -> BTreeSet<u64> {
    entries
        .iter()
        .filter_map(|e| guest_in_path(&e.path))
        .filter(|id| !kept(*id))
        .collect()
}

fn as_u64(v: &Value) -> Option<u64> {
    match v {
        Value::String(s) => s.parse().ok(),
        _ => v.as_u64(),
    }
}

fn upid_fields(s: &str) -> Option<Vec<String>> {
    let f: Vec<String> = s.split(':').map(str::to_string).collect();
    (f.len() == 9 && f[0] == "UPID").then_some(f)
}

/// Certificate tasks become the commonest other kind: whether a host's renewals
/// work is nobody's business, and the shape is the same.
fn generic_task(s: &str) -> String {
    match upid_fields(s) {
        Some(mut f) if f[5].starts_with("acme") => {
            f[5] = "aptupdate".to_string();
            f.join(":")
        }
        _ => s.to_string(),
    }
}

/// Generic task types, and generic text for a failure's reason.
fn task_outcomes(v: &mut Value) {
    match v {
        Value::Array(a) => a.iter_mut().for_each(task_outcomes),
        Value::Object(m) if m.contains_key("upid") => {
            for (k, c) in m.iter_mut() {
                let Value::String(s) = c else { continue };
                match k.as_str() {
                    "upid" => *s = generic_task(s),
                    "type" if s.starts_with("acme") => *s = "aptupdate".to_string(),
                    "status" | "exitstatus" => {
                        if s.starts_with("WARNINGS: ") {
                            *s = "WARNINGS: 1".to_string();
                        } else if !matches!(s.as_str(), "OK" | "stopped" | "running")
                            && s != "no such task"
                        {
                            *s = FAILED.to_string();
                        }
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }
}

/// Cuts the long lists to the first entry of each shape, keeping every guest
/// that has endpoints of its own in the set.
fn trim(e: &mut Entry, captured: &BTreeSet<u64>) {
    let segs: Vec<String> = e.path.split('/').skip(1).map(decode).collect();
    let segs: Vec<&str> = segs.iter().map(String::as_str).collect();
    let Ok(body) = &mut e.result else { return };
    match segs.as_slice() {
        ["cluster", "resources"] | ["nodes", _, "qemu" | "lxc"] => trim_guests(body, captured),
        ["pools", _] => {
            if let Some(m) = body.get_mut("members") {
                trim_guests(m, captured);
            }
        }
        ["nodes", _, "storage", _, "content"] => {
            trim_by(body, &["content", "format", "subtype"], |_| false)
        }
        ["nodes", _, "tasks"] => trim_by(body, &["type"], |_| false),
        _ => {}
    }
}

fn trim_guests(body: &mut Value, captured: &BTreeSet<u64>) {
    trim_by(body, &["type", "status"], |g| {
        g.get("vmid")
            .and_then(as_u64)
            .is_some_and(|id| captured.contains(&id))
    });
}

fn trim_by(body: &mut Value, enums: &[&str], keep: impl Fn(&Value) -> bool) {
    let Value::Array(a) = body else { return };
    let shape = |v: &Value| -> String {
        let keys: Vec<&String> = v
            .as_object()
            .map(|m| m.keys().collect())
            .unwrap_or_default();
        let vals: Vec<Option<&Value>> = enums.iter().map(|k| v.get(*k)).collect();
        // A task list's `status` is free text; only which side it is on counts.
        let ok = v.get("upid").map(|_| v.get("status") == Some(&json!("OK")));
        let subject = v.get("upid").map(|_| v.get("id") == Some(&json!("")));
        format!("{keys:?}{vals:?}{ok:?}{subject:?}")
    };
    let mut seen: HashSet<String> = a.iter().filter(|v| keep(v)).map(shape).collect();
    a.retain(|v| keep(v) || seen.insert(shape(v)));
}

/// The guest ids and dates a set mentions.
#[derive(Default)]
struct Seen {
    ids: BTreeSet<u64>,
    epochs: BTreeSet<u64>,
}

impl Seen {
    fn epoch(&mut self, n: u64) {
        if n >= EPOCH_MIN {
            self.epochs.insert(n);
        }
    }

    fn string(&mut self, s: &str) {
        for (a, b) in vmid_spans(s) {
            self.ids.extend(s[a..b].parse::<u64>().ok());
        }
        if let Some(f) = upid_fields(s) {
            self.ids.extend(f[6].parse::<u64>().ok());
            if let Ok(n) = u64::from_str_radix(&f[4], 16) {
                self.epoch(n);
            }
        }
        for part in s.split(',') {
            if let Some(n) = part.strip_prefix("ctime=").and_then(|n| n.parse().ok()) {
                self.epoch(n);
            }
        }
    }

    fn value(&mut self, key: Option<&str>, v: &Value) {
        match v {
            Value::Object(m) => {
                for (k, c) in m {
                    self.string(k);
                    self.value(Some(k), c);
                }
            }
            Value::Array(a) => a.iter().for_each(|c| self.value(key, c)),
            _ => {
                if let (Some(k), Some(n)) = (key, as_u64(v)) {
                    if is_vmid_key(k, v) {
                        self.ids.insert(n);
                    } else if is_epoch_key(k) {
                        self.epoch(n);
                    }
                }
                if let Value::String(s) = v {
                    self.string(s);
                }
            }
        }
    }
}

fn is_epoch_key(k: &str) -> bool {
    matches!(k, "ctime" | "snaptime" | "starttime" | "endtime")
}

/// `vmid`, and a task's `id` when the task's subject is a guest.
fn is_vmid_key(k: &str, v: &Value) -> bool {
    k == "vmid" || (k == "id" && v.is_string())
}

struct Maps {
    ids: HashMap<u64, u64>,
    epochs: BTreeMap<u64, u64>,
}

impl Maps {
    fn new(seen: &Seen, captured: &BTreeSet<u64>, kept: &dyn Fn(u64) -> bool) -> Self {
        let others = seen
            .ids
            .iter()
            .filter(|id| !kept(**id) && !captured.contains(id));
        let ids = (captured.iter().zip(FIRST_VMID..))
            .chain(others.zip(FIRST_OTHER_VMID..))
            .map(|(old, new)| (*old, new))
            .collect();
        let epochs = seen.epochs.iter().zip(1..);
        Maps {
            ids,
            epochs: epochs
                .map(|(e, n)| (*e, EPOCH_BASE + n * EPOCH_STEP))
                .collect(),
        }
    }

    fn vmid(&self, id: u64) -> u64 {
        self.ids.get(&id).copied().unwrap_or(id)
    }

    fn epoch(&self, n: u64) -> u64 {
        self.epochs.get(&n).copied().unwrap_or(n)
    }

    /// Guest ids, dates and quantities inside a string.
    fn string(&self, s: &str) -> String {
        if let Some(mut f) = upid_fields(s) {
            if let Ok(id) = f[6].parse::<u64>() {
                f[6] = self.vmid(id).to_string();
            }
            match u64::from_str_radix(&f[4], 16) {
                Ok(n) if n >= EPOCH_MIN => {
                    f[2] = format!("{TASK_PID:08X}");
                    f[3] = format!("{TASK_PSTART:08X}");
                    f[4] = format!("{:08X}", self.epoch(n));
                }
                _ => {}
            }
            return f.join(":");
        }
        let mut out = String::new();
        let mut last = 0;
        for (a, b) in vmid_spans(s) {
            out.push_str(&s[last..a]);
            out.push_str(
                &s[a..b]
                    .parse()
                    .map_or_else(|_| s[a..b].to_string(), |id| self.vmid(id).to_string()),
            );
            last = b;
        }
        out.push_str(&s[last..]);
        let out = archive_date(&out, EPOCH_BASE);
        if !out.contains('=') {
            return out;
        }
        out.split(',')
            .map(|kv| match kv.split_once('=') {
                Some((k, v)) => format!("{k}={}", self.option(k, v)),
                None => kv.to_string(),
            })
            .collect::<Vec<_>>()
            .join(",")
    }

    /// One `key=value` of an option string.
    fn option(&self, k: &str, v: &str) -> String {
        match k {
            "ctime" => v
                .parse()
                .map_or_else(|_| v.to_string(), |n| self.epoch(n).to_string()),
            "creation-qemu" => "10.0.0".to_string(),
            // The unit is the shape: EFI and TPM volumes are K or M sized.
            "size" => match v.as_bytes().last() {
                Some(b'K') => "528K".to_string(),
                Some(b'M') => "4M".to_string(),
                _ => "48G".to_string(),
            },
            "tag" => "10".to_string(),
            "memory" => "128".to_string(),
            "up" | "down" => "30".to_string(),
            "order" if v.bytes().all(|b| b.is_ascii_digit()) => "1".to_string(),
            _ => v.to_string(),
        }
    }

    fn value(&self, key: Option<&str>, v: &mut Value) {
        match v {
            Value::Object(m) => {
                for (k, mut c) in std::mem::take(m) {
                    self.value(Some(&k), &mut c);
                    m.insert(self.string(&k), c);
                }
                // An archive's name carries its `ctime`, in the host's local
                // time; here UTC.
                let when = m.get("ctime").and_then(as_u64);
                if let (Some(when), Some(Value::String(vol))) = (when, m.get_mut("volid")) {
                    *vol = archive_date(vol, when);
                }
            }
            Value::Array(a) => a.iter_mut().for_each(|c| self.value(key, c)),
            _ => {
                let k = key.unwrap_or_default();
                let n = as_u64(v);
                let new = match n {
                    Some(n) if is_vmid_key(k, v) => Some(json!(self.vmid(n))),
                    Some(n) if is_epoch_key(k) => Some(json!(self.epoch(n))),
                    _ => quantity(k, v),
                };
                match (new, &mut *v) {
                    (Some(new), Value::String(s)) => {
                        *s = new.as_str().map_or_else(|| new.to_string(), str::to_string)
                    }
                    (Some(new), _) => *v = new,
                    (None, Value::String(s)) => *s = self.string(s),
                    _ => {}
                }
            }
        }
    }
}

/// The stand-in for a number (or a number sent as a string) that describes the
/// host or a guest. Zero means something different from any other value, so it
/// stays. Anything large that no rule names is replaced too: a new counter in a
/// newer PVE must not need a rule to be covered.
fn quantity(k: &str, v: &Value) -> Option<Value> {
    // Text that identifies hardware or a guest's age.
    match (k, v) {
        ("flags", Value::String(_)) => return Some(json!("fpu vme de pse tsc msr pae mce cx8")),
        ("vendor", Value::String(_)) => return Some(json!("GenuineIntel")),
        ("affinity", Value::String(_)) => return Some(json!("0")),
        ("machine", Value::String(s)) if s.starts_with("pc-") => {
            let base = s.rsplit_once('-').map_or(s.as_str(), |(b, _)| b);
            return Some(json!(format!("{base}-10.0")));
        }
        _ => {}
    }
    let text = v.as_str();
    let f = match text {
        Some(s) => s.parse::<f64>().ok()?,
        None => v.as_f64()?,
    };
    if f == 0.0 {
        return None;
    }
    let pressure = k.starts_with("pressure");
    Some(match k {
        "cpu" | "cpulimit" if text.is_some() => json!("2"),
        "cpu" if !v.is_u64() => json!(0.01),
        "wait" => json!(0.001),
        "loadavg" => json!("0.10"),
        "mhz" => json!("2000.000"),
        "family" => json!("6"),
        "used_fraction" => json!(0.25),
        _ if pressure && text.is_some() => json!("0.01"),
        _ if pressure => json!(0.01),
        "uptime" | "idle" => json!(100_000),
        "pid" => json!(TASK_PID),
        "pstart" => json!(TASK_PSTART),
        "cores" | "cpus" | "maxcpu" => json!(2),
        "sockets" => json!(1),
        "cpuunits" => json!(100),
        // Megabytes in a config; the node status has an object here.
        "memory" => json!(3072),
        "balloon" => json!(1536),
        "maxmem" => json!(3 * GIB),
        "mem" | "memhost" | "balloon_min" => json!(3 * GIB / 2),
        // Megabytes in a config, bytes in a status.
        "swap" if f >= 1e6 => json!(3 * GIB / 16),
        "swap" => json!(512),
        "maxswap" => json!(3 * GIB / 4),
        "maxdisk" | "size" => json!(48 * GIB),
        "disk" => json!(14 * GIB),
        "total" => json!(88 * GIB),
        "used" => json!(22 * GIB),
        "free" | "avail" | "available" => json!(66 * GIB),
        _ if k.ends_with("_operations") || k.ends_with("_merged") => json!(1000),
        "diskread" | "diskwrite" | "netin" | "netout" => json!(1_000_000),
        _ if k.ends_with("_bytes") || k.ends_with("_ns") || k.ends_with("_offset") => {
            json!(1_000_000)
        }
        _ if f.abs() >= 1e6 && (text.is_none() || f.fract() == 0.0) && is_plain(text) => {
            json!(1_000_000)
        }
        _ if v.is_f64() => json!(0.01),
        _ => return None,
    })
}

/// A number, or a string of nothing but digits (not a hex id that happens to
/// read as a float, as a digest can).
fn is_plain(text: Option<&str>) -> bool {
    text.is_none_or(|s| s.len() < 20 && s.bytes().all(|b| b.is_ascii_digit()))
}

/// Where guest ids stand inside a string: volume, archive, interface and
/// resource names, and the `storage:ID/` directory of a volume id.
fn vmid_spans(s: &str) -> Vec<(usize, usize)> {
    const BEFORE: &[&str] = &[
        "guest-",
        "vm-",
        "ct-",
        "subvol-",
        "basevol-",
        "base-",
        "vzdump-qemu-",
        "vzdump-lxc-",
        "vzdump-openvz-",
        "qemu/",
        "lxc/",
        "openvz/",
        "qemu-server/",
        "tap",
        "veth",
        "fwbr",
        "fwpr",
        "fwln",
        "VM ",
        "CT ",
        "vm/",
        "ct/",
    ];
    let b = s.as_bytes();
    let mut v = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if !b[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        // PVE's own range; also keeps `base-2`-like names out.
        if !(3..=9).contains(&(i - start)) || b[start] == b'0' {
            continue;
        }
        let prefixed = BEFORE.iter().any(|p| {
            s[..start]
                .strip_suffix(p)
                .is_some_and(|rest| !rest.ends_with(|c: char| c.is_ascii_alphanumeric()))
        });
        let volume_dir = start >= 2
            && b[start - 1] == b':'
            && b[start - 2].is_ascii_alphanumeric()
            && b.get(i) == Some(&b'/')
            && !b[..start - 1].contains(&b':');
        if prefixed || volume_dir {
            v.push((start, i));
        }
    }
    v
}

/// Replaces the date in a `vzdump-...-YYYY_MM_DD-HH_MM_SS` name.
fn archive_date(s: &str, epoch: u64) -> String {
    const SHAPE: &[u8] = b"0000_00_00-00_00_00";
    let Some(at) = s.find("vzdump-") else {
        return s.to_string();
    };
    let b = s.as_bytes();
    let fits = |i: &usize| {
        b[*i..*i + SHAPE.len()].iter().zip(SHAPE).all(|(c, p)| {
            if *p == b'0' {
                c.is_ascii_digit()
            } else {
                c == p
            }
        })
    };
    match (at..(b.len() + 1).saturating_sub(SHAPE.len())).find(fits) {
        Some(i) => format!("{}{}{}", &s[..i], utc(epoch), &s[i + SHAPE.len()..]),
        None => s.to_string(),
    }
}

/// Seconds since the epoch as vzdump writes a date (Howard Hinnant's civil
/// calendar algorithm, so this needs no date dependency).
fn utc(secs: u64) -> String {
    let z = secs / 86400 + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + u64::from(m <= 2);
    let t = secs % 86400;
    format!(
        "{y:04}_{m:02}_{d:02}-{:02}_{:02}_{:02}",
        t / 3600,
        t / 60 % 60,
        t % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(path: &str, v: Value) -> Entry {
        Entry {
            path: path.to_string(),
            params: vec![],
            result: Ok(v),
        }
    }

    fn raw() -> Vec<Entry> {
        let task = "UPID:node1:001ADED9:0BA18A76:6AFC4126:vzdump:4242:root@pam:";
        let bad = "UPID:node1:000829F7:02CDB41F:6AFC3441:acmerenew::root@pam:";
        let backup = |id: u64, ctime: u64, date: &str| {
            json!({"content": "backup", "format": "tar.zst", "subtype": "lxc", "vmid": id,
            "ctime": ctime, "size": 1234567891,
            "volid": format!("storage1:backup/vzdump-lxc-{id}-{date}.tar.zst")})
        };
        vec![
            entry(
                "/nodes/node1/qemu",
                json!([
                    {"vmid": 4242, "name": "guest-4242", "status": "running", "uptime": 987654, "cpu": 0.1234, "cpus": 6},
                    {"vmid": 4343, "name": "guest-4343", "status": "running", "uptime": 987654, "cpu": 0.1234, "cpus": 6},
                    {"vmid": 4444, "name": "guest-4444", "status": "stopped", "uptime": 0, "cpu": 0, "cpus": 6},
                ]),
            ),
            entry(
                "/nodes/node1/qemu/4242/config",
                json!({"scsi0": "storage1:4242/vm-4242-disk-0.raw,iothread=1,size=77G", "memory": "7777",
                "meta": "creation-qemu=8.1.5,ctime=1714508376", "net0": "virtio=02:00:00:00:00:01,tag=77",
                "cpu": "host", "digest": "0000000000000000000000000000000000000001"}),
            ),
            entry(
                "/nodes/node1/qemu/4242/status/current",
                json!({"nics": {"tap4242i0": {"netin": 123456789, "netout": 0}}, "brand_new_counter": 123456789012_u64,
                "pressureiofull": "4.51", "pid": 77777}),
            ),
            entry(
                "/nodes/node1/storage/storage1/content",
                json!([
                    backup(4242, 1774904937, "2026_03_30-14_08_57"),
                    backup(4343, 1774904999, "2026_03_30-14_09_59"),
                ]),
            ),
            entry(
                "/nodes/node1/tasks",
                json!([
                    {"upid": task, "id": "4242", "type": "vzdump", "status": "OK", "pid": 1760985, "pstart": 195136118, "starttime": 1794916646, "endtime": 1794916699},
                    {"upid": bad, "id": "", "type": "acmerenew", "status": "some reason", "pid": 535031, "pstart": 47035423, "starttime": 1794913345, "endtime": 1794913361},
                ]),
            ),
            entry(
                &format!("/nodes/node1/tasks/{}/status", encode(task)),
                json!({"upid": task, "id": "4242", "type": "vzdump", "status": "stopped", "exitstatus": "OK", "pid": 1760985, "pstart": 195136118, "starttime": 1794916646}),
            ),
        ]
    }

    #[test]
    fn values_are_synthetic_and_still_agree_with_each_other() {
        let mut es = raw();
        normalise(&mut es);
        let body = |i: usize| es[i].result.as_ref().unwrap();
        assert_eq!(es[1].path, "/nodes/node1/qemu/101/config");
        // The second running guest is the same shape and has nothing of its own.
        assert_eq!(body(0).as_array().unwrap().len(), 2);
        assert_eq!(
            body(0)[0],
            json!({"vmid": 101, "name": "guest-101", "status": "running", "uptime": 100000, "cpu": 0.01, "cpus": 2})
        );
        assert_eq!(body(0)[1]["vmid"], 9101);
        assert_eq!(body(0)[1]["uptime"], 0);
        assert_eq!(
            body(1)["scsi0"],
            "storage1:101/vm-101-disk-0.raw,iothread=1,size=48G"
        );
        assert_eq!(body(1)["memory"], "3072");
        assert_eq!(body(1)["cpu"], "host");
        assert_eq!(body(1)["meta"], "creation-qemu=10.0.0,ctime=1767229200");
        assert_eq!(body(1)["net0"], "virtio=02:00:00:00:00:01,tag=10");
        assert_eq!(body(1)["digest"].as_str().unwrap().len(), 40);
        assert_eq!(
            body(2)["nics"],
            json!({"tap101i0": {"netin": 1000000, "netout": 0}})
        );
        assert_eq!(body(2)["brand_new_counter"], 1000000);
        assert_eq!(body(2)["pressureiofull"], "0.01");
        assert_eq!(body(3).as_array().unwrap().len(), 1);
        assert_eq!(body(3)[0]["ctime"], 1767232800);
        assert_eq!(
            body(3)[0]["volid"],
            "storage1:backup/vzdump-lxc-101-2026_01_01-02_00_00.tar.zst"
        );
        for (i, u) in [(4, &body(4)[0]), (5, body(5))] {
            let f = upid_fields(u["upid"].as_str().unwrap()).unwrap();
            assert_eq!(u64::from_str_radix(&f[2], 16).unwrap(), u["pid"], "{i}");
            assert_eq!(u64::from_str_radix(&f[3], 16).unwrap(), u["pstart"]);
            assert_eq!(u64::from_str_radix(&f[4], 16).unwrap(), u["starttime"]);
            assert_eq!((f[6].as_str(), &u["id"]), ("101", &json!("101")));
        }
        assert_eq!(body(4)[1]["type"], "aptupdate");
        assert_eq!(body(4)[1]["status"], FAILED);
        assert!(body(4)[0]["starttime"].as_u64() > body(4)[1]["endtime"].as_u64());
        let upid = body(5)["upid"].as_str().unwrap();
        assert!(es[5].path.contains(&encode(upid)));

        let all = format!("{es:?}");
        for real in [
            "4242",
            "4343",
            "4444",
            "77",
            "8.1.5",
            "123456789",
            "1234567891",
            "acme",
        ] {
            assert!(!all.contains(real), "{real} survives in {all}");
        }
    }

    #[test]
    fn normalising_twice_changes_nothing() {
        let mut once = raw();
        normalise(&mut once);
        let mut twice = once.clone();
        normalise(&mut twice);
        assert_eq!(once, twice);
    }

    #[test]
    fn documented_and_probe_ids_stay() {
        let p = "/nodes/node1/tasks/UPID%3Anode1%3A00000001%3A00000001%3A00000001%3Avzdump%3A999999999%3Aroot%40pam%3A/status";
        let mut es = vec![
            entry(
                "/nodes/node1/qemu/9001/config",
                json!({"ide2": "storage1:9001/vm-9001-cloudinit.qcow2"}),
            ),
            entry("/nodes/node1/qemu/999999999/status/current", json!({})),
            entry(p, json!({})),
        ];
        let before = es.clone();
        normalise_keeping(&mut es, TEST_ESTATE_VMIDS);
        assert_eq!(es, before);

        // Without that allowance they are an ordinary host's guests.
        normalise(&mut es);
        let all = format!("{es:?}");
        assert!(!all.contains("9001"), "{all}");
        assert_eq!(es[0].path, "/nodes/node1/qemu/101/config");
        assert_eq!(es[1..], before[1..]);
    }

    #[test]
    fn dates_are_utc() {
        assert_eq!(utc(0), "1970_01_01-00_00_00");
        assert_eq!(utc(951_827_696), "2000_02_29-12_34_56");
        assert_eq!(utc(EPOCH_BASE), "2026_01_01-00_00_00");
    }
}
