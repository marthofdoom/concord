//! Read-only capture of real PVE responses.
//!
//! The capture walks a fixed set of GET endpoints on one host and records what
//! came back. Mutation is excluded by construction: everything goes through
//! [`ReadOnly`], which holds the API behind a private field and has no method
//! that can issue anything but GET.

use std::path::Path;

use serde_json::{json, Map, Value};

use crate::api::{api_path, Method, PveApi};
use crate::error::PveError;
use crate::sanitize::{LeakScanner, Sanitizer};

/// A view of a [`PveApi`] that can only read.
///
/// The capture tool takes this, not the `PveApi`, so "it never mutates" is a
/// property of the type rather than of the code that happens to call it.
pub struct ReadOnly<'a> {
    api: &'a dyn PveApi,
}

impl<'a> ReadOnly<'a> {
    pub fn new(api: &'a dyn PveApi) -> Self {
        ReadOnly { api }
    }

    pub async fn get(&self, path: &str, params: &[(&str, String)]) -> Result<Value, PveError> {
        self.api.request(Method::Get, path, params).await
    }
}

/// A non-2xx answer, kept because the error shapes are as much a part of the
/// contract as the successes.
#[derive(Clone, Debug, PartialEq)]
pub struct ErrBody {
    pub status: u16,
    pub message: String,
    pub errors: Option<Value>,
}

/// One endpoint's recorded response.
#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    /// Percent-encoded, relative to `/api2/json`, as passed to `request`.
    pub path: String,
    pub params: Vec<(String, String)>,
    pub result: Result<Value, ErrBody>,
}

/// How much of a busy host to record. Fixtures are for shapes; a few of each
/// kind is enough and keeps review of the committed files practical.
#[derive(Clone, Copy, Debug)]
pub struct CaptureLimits {
    /// Guests of each type (qemu, lxc) whose config, status and snapshots are
    /// taken. Chosen to include a running and a stopped one where both exist.
    pub guests_per_type: usize,
    pub storages: usize,
    pub tasks: usize,
}

impl Default for CaptureLimits {
    fn default() -> Self {
        CaptureLimits {
            guests_per_type: 2,
            storages: 3,
            tasks: 20,
        }
    }
}

struct Recorder<'a> {
    api: &'a ReadOnly<'a>,
    entries: Vec<Entry>,
}

impl Recorder<'_> {
    /// Records an HTTP-level failure as an entry and returns None; anything
    /// below HTTP (timeout, TLS) aborts the capture, since a half-recorded set
    /// is worse than none.
    async fn get(
        &mut self,
        path: &str,
        params: &[(&str, String)],
    ) -> Result<Option<Value>, PveError> {
        // MockPve and the fixture manifest key on path alone, so one entry per
        // path keeps replay unambiguous.
        if self.entries.iter().any(|e| e.path == path) {
            return Ok(None);
        }
        let result = match self.api.get(path, params).await {
            Ok(v) => Ok(v),
            Err(PveError::Http {
                status,
                message,
                errors,
            }) => Err(ErrBody {
                status,
                message,
                errors,
            }),
            Err(other) => return Err(other),
        };
        let data = result.as_ref().ok().cloned();
        self.entries.push(Entry {
            path: path.to_string(),
            params: params
                .iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect(),
            result,
        });
        Ok(data)
    }
}

impl Recorder<'_> {
    /// Like `get`, but keeps only a failure.
    async fn probe(&mut self, path: &str) -> Result<(), PveError> {
        match self.api.get(path, &[]).await {
            Err(PveError::Http {
                status,
                message,
                errors,
            }) => self.entries.push(Entry {
                path: path.to_string(),
                params: vec![],
                result: Err(ErrBody {
                    status,
                    message,
                    errors,
                }),
            }),
            Err(other) => return Err(other),
            Ok(_) => {}
        }
        Ok(())
    }
}

fn s<'v>(v: &'v Value, k: &str) -> Option<&'v str> {
    v.get(k).and_then(Value::as_str)
}

fn list(v: &Option<Value>) -> &[Value] {
    v.as_ref()
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

/// Up to `n` guests, a running and a stopped one first, then by vmid.
fn pick_guests(guests: &[Value], n: usize) -> Vec<String> {
    let mut g: Vec<&Value> = guests.iter().filter(|g| g.get("vmid").is_some()).collect();
    g.sort_by_key(|g| g.get("vmid").and_then(Value::as_u64).unwrap_or(0));
    let mut out: Vec<&Value> = Vec::new();
    for want in ["running", "stopped"] {
        if let Some(x) = g.iter().find(|x| s(x, "status") == Some(want)) {
            out.push(x);
        }
    }
    for x in &g {
        if out.len() >= n {
            break;
        }
        if !out.iter().any(|o| std::ptr::eq(*o, *x)) {
            out.push(x);
        }
    }
    out.truncate(n);
    out.iter()
        .filter_map(|g| {
            g.get("vmid")
                .map(|v| v.to_string().trim_matches('"').to_string())
        })
        .collect()
}

/// Records every endpoint concord-pve needs a real shape for, from `api` only.
pub async fn capture_all(
    api: &ReadOnly<'_>,
    limits: CaptureLimits,
) -> Result<Vec<Entry>, PveError> {
    let mut r = Recorder {
        api,
        entries: Vec::new(),
    };
    r.get("/version", &[]).await?;
    let nodes = r.get("/nodes", &[]).await?;
    r.get("/cluster/resources", &[("type", "vm".into())])
        .await?;
    r.get("/storage", &[]).await?;
    let pools = r.get("/pools", &[]).await?;
    if let Some(id) = list(&pools).first().and_then(|p| s(p, "poolid")) {
        r.get(&api_path(&["pools", id])?, &[]).await?;
    }

    let node_names: Vec<String> = list(&nodes)
        .iter()
        .filter_map(|n| s(n, "node").map(str::to_string))
        .collect();
    for node in &node_names {
        let n = node.as_str();
        r.get(&api_path(&["nodes", n, "status"])?, &[]).await?;
        let storages = r.get(&api_path(&["nodes", n, "storage"])?, &[]).await?;
        for st in list(&storages)
            .iter()
            .filter(|st| {
                st.get("active").and_then(Value::as_u64) == Some(1)
                    && s(st, "content").is_some_and(|c| !c.is_empty())
            })
            .take(limits.storages)
        {
            if let Some(id) = s(st, "storage") {
                r.get(&api_path(&["nodes", n, "storage", id, "content"])?, &[])
                    .await?;
            }
        }

        for kind in ["qemu", "lxc"] {
            let guests = r.get(&api_path(&["nodes", n, kind])?, &[]).await?;
            for vmid in pick_guests(list(&guests), limits.guests_per_type) {
                for leaf in [&["config"][..], &["status", "current"], &["snapshot"]] {
                    let mut segs = vec!["nodes", n, kind, vmid.as_str()];
                    segs.extend_from_slice(leaf);
                    r.get(&api_path(&segs)?, &[]).await?;
                }
            }
        }

        let tasks = r
            .get(
                &api_path(&["nodes", n, "tasks"])?,
                &[("limit", limits.tasks.to_string())],
            )
            .await?;
        // One clean finish and one failure: their `exitstatus` shapes differ.
        let stopped = |t: &&Value| s(t, "status").is_some();
        let ok = list(&tasks)
            .iter()
            .filter(stopped)
            .find(|t| s(t, "status") == Some("OK"));
        let bad = list(&tasks)
            .iter()
            .filter(stopped)
            .find(|t| s(t, "status") != Some("OK"));
        for t in [ok, bad].into_iter().flatten() {
            if let Some(upid) = s(t, "upid") {
                r.get(&api_path(&["nodes", n, "tasks", upid, "status"])?, &[])
                    .await?;
            }
        }

        // Deliberate misses, for the error shapes. A guest id no host has and a
        // path that is not an endpoint at all.
        r.get(
            &api_path(&["nodes", n, "qemu", "999999999", "status", "current"])?,
            &[],
        )
        .await?;
        r.get(&api_path(&["nodes", n, "nonexistent"])?, &[]).await?;
        // Needs Sys.Modify, which an auditor token lacks: a 403 on such a
        // token. An admin token gets the whole package list, which is large
        // and says nothing about shapes, so only a failure is recorded.
        r.probe(&api_path(&["nodes", n, "apt", "update"])?).await?;
        r.get(
            &api_path(&[
                "nodes",
                n,
                "tasks",
                &format!("UPID:{n}:00000001:00000001:00000001:vzdump:999999999:root@pam:"),
                "status",
            ])?,
            &[],
        )
        .await?;
    }
    Ok(r.entries)
}

fn file_name(e: &Entry) -> String {
    let mut parts: Vec<String> = e
        .path
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|seg| {
            let d = percent_encoding::percent_decode_str(seg).decode_utf8_lossy();
            let clean: String = d
                .chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() || c == '-' || c == '.' {
                        c
                    } else {
                        '-'
                    }
                })
                .collect();
            clean.chars().take(48).collect()
        })
        .collect();
    for (k, v) in &e.params {
        parts.push(format!("{k}-{v}"));
    }
    let base = parts.join("_");
    if e.result.is_err() {
        format!("errors/{base}.json")
    } else {
        format!("{base}.json")
    }
}

/// `^[0-9]+(\.[0-9]+)*$`: safe to put in a path.
fn is_version(v: &str) -> bool {
    !v.is_empty()
        && v.split('.')
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

/// Sanitises `entries`, refuses them if anything still looks like the real
/// estate, and writes `<out>/pve-<version>/` with a `MANIFEST.json`. Returns
/// the set directory. Fails closed: nothing is written when a leak is found.
pub fn write_set(out: &Path, mut entries: Vec<Entry>) -> Result<std::path::PathBuf, String> {
    let version = entries
        .iter()
        .find(|e| e.path == "/version")
        .and_then(|e| e.result.as_ref().ok())
        .and_then(|v| s(v, "version"))
        .ok_or("capture has no /version")?
        .to_string();
    // The version comes from the host and names the directory removed below.
    if !is_version(&version) {
        return Err("host reported a version that is not digits and dots".to_string());
    }
    // Loaded first, so an unusable digest list stops the capture being written.
    let scanner = LeakScanner::from_env()?;
    Sanitizer::new().set(&mut entries);
    write_sanitised(out, &version, entries, &scanner)
}

fn write_sanitised(
    out: &Path,
    version: &str,
    entries: Vec<Entry>,
    scanner: &LeakScanner,
) -> Result<std::path::PathBuf, String> {
    let mut files = Vec::new();
    let mut manifest = Vec::new();
    for e in &entries {
        let file = file_name(e);
        let (status, body) = match &e.result {
            Ok(v) => (200, v.clone()),
            Err(b) => (
                b.status,
                json!({"status": b.status, "message": b.message, "errors": b.errors}),
            ),
        };
        let text = serde_json::to_string_pretty(&body).map_err(|e| e.to_string())? + "\n";
        let params: Map<String, Value> = e
            .params
            .iter()
            .map(|(k, v)| (k.clone(), Value::String(v.clone())))
            .collect();
        manifest
            .push(json!({"path": e.path, "params": params, "file": file, "http_status": status}));
        files.push((file, text));
    }
    let manifest = json!({"pve_version": version, "endpoints": manifest});
    let manifest_text = serde_json::to_string_pretty(&manifest).map_err(|e| e.to_string())? + "\n";
    files.push(("MANIFEST.json".to_string(), manifest_text));

    let mut leaks = Vec::new();
    for (name, text) in &files {
        for l in scanner
            .find_leaks(text)
            .into_iter()
            .chain(scanner.find_leaks(name))
        {
            leaks.push(format!("{name}: {l}"));
        }
    }
    if !leaks.is_empty() {
        return Err(format!(
            "sanitised capture still looks identifying, nothing written:\n{}",
            leaks.join("\n")
        ));
    }

    let dir = out.join(format!("pve-{version}"));
    if dir.exists() {
        std::fs::remove_dir_all(&dir).map_err(|e| e.to_string())?;
    }
    for (name, text) in files {
        let p = dir.join(&name);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        std::fs::write(&p, text).map_err(|e| e.to_string())?;
    }
    Ok(dir)
}
