//! Replay of captured fixtures: serves what a real host answered to
//! tests, through [`MockPve`], so a test agrees with Proxmox and not just with
//! what its author assumed.

use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::api::Method;
use crate::error::PveError;
use crate::mock::MockPve;

/// Where the committed fixture sets live.
pub const FIXTURE_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

/// One captured, sanitised set: every endpoint's response from one PVE
/// version.
#[derive(Clone, Debug)]
pub struct FixtureSet {
    pub dir: PathBuf,
    pub pve_version: String,
    /// (path, http status, body). Bodies of non-2xx entries are
    /// `{status, message, errors}`.
    pub endpoints: Vec<(String, u16, Value)>,
}

impl FixtureSet {
    pub fn load(dir: &Path) -> Result<Self, String> {
        let read = |p: &Path| -> Result<Value, String> {
            let t = std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?;
            serde_json::from_str(&t).map_err(|e| format!("{}: {e}", p.display()))
        };
        let m = read(&dir.join("MANIFEST.json"))?;
        let field = |k: &str| {
            m.get(k)
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or_else(|| format!("MANIFEST.json: missing `{k}`"))
        };
        let mut endpoints = Vec::new();
        for e in m
            .get("endpoints")
            .and_then(Value::as_array)
            .ok_or("MANIFEST.json: missing `endpoints`")?
        {
            let path = e
                .get("path")
                .and_then(Value::as_str)
                .ok_or("endpoint without path")?;
            let file = e
                .get("file")
                .and_then(Value::as_str)
                .ok_or("endpoint without file")?;
            let status = e
                .get("http_status")
                .and_then(Value::as_u64)
                .and_then(|s| u16::try_from(s).ok())
                .ok_or("endpoint without http_status")?;
            endpoints.push((path.to_string(), status, read(&dir.join(file))?));
        }
        Ok(FixtureSet {
            dir: dir.to_path_buf(),
            pve_version: field("pve_version")?,
            endpoints,
        })
    }

    /// Every `pve-*` set under `root`, oldest version name first.
    pub fn load_all(root: &Path) -> Result<Vec<Self>, String> {
        let mut dirs: Vec<PathBuf> = std::fs::read_dir(root)
            .map_err(|e| format!("{}: {e}", root.display()))?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.join("MANIFEST.json").is_file())
            .collect();
        dirs.sort();
        dirs.iter().map(|d| Self::load(d)).collect()
    }

    /// The committed set for one PVE version, e.g. `"9.2.21"`.
    pub fn committed(version: &str) -> Result<Self, String> {
        Self::load(&Path::new(FIXTURE_ROOT).join(format!("pve-{version}")))
    }

    /// A successful body by exact path, as passed to `request`.
    pub fn data(&self, path: &str) -> Option<&Value> {
        self.endpoints
            .iter()
            .find(|(p, s, _)| p == path && (200..300).contains(s))
            .map(|(_, _, v)| v)
    }

    /// A [`MockPve`] answering GET for every captured path, failures included.
    pub fn mock(&self) -> MockPve {
        let mut m = MockPve::new();
        for (path, status, body) in &self.endpoints {
            m = if (200..300).contains(status) {
                m.on(Method::Get, path, body.clone())
            } else {
                m.on_err(
                    Method::Get,
                    path,
                    PveError::Http {
                        status: *status,
                        message: body
                            .get("message")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_string(),
                        errors: body.get("errors").filter(|e| !e.is_null()).cloned(),
                    },
                )
            };
        }
        m
    }
}
