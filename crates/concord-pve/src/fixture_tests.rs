//! Tests over the committed fixture sets: that they are clean, that
//! they still parse into the types this crate uses, that the capture routine
//! is read-only, and that it and the fixtures agree on what gets fetched.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{json, Value};

use crate::http::parse_envelope;
use crate::normalise::{normalise_keeping, TEST_ESTATE_VMIDS};
use crate::*;

fn sets() -> Vec<FixtureSet> {
    let sets = FixtureSet::load_all(Path::new(FIXTURE_ROOT)).unwrap();
    assert!(sets.len() >= 3, "expected one set per captured PVE version");
    sets
}

fn files_under(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            files_under(&p, out);
        } else {
            out.push(p);
        }
    }
}

#[test]
fn manifest_versions_match_their_directories() {
    for s in sets() {
        let dir = s.dir.file_name().unwrap().to_str().unwrap();
        assert_eq!(dir, format!("pve-{}", s.pve_version));
        let reported = s.data("/version").unwrap()["version"].as_str().unwrap();
        assert_eq!(
            reported, s.pve_version,
            "{dir}: MANIFEST disagrees with /version"
        );
    }
}

#[test]
fn every_fixture_file_is_in_a_manifest_and_free_of_estate_identifiers() {
    let scanner = LeakScanner::from_env().unwrap();
    for s in sets() {
        let mut files = Vec::new();
        files_under(&s.dir, &mut files);
        let listed: Vec<String> = {
            let m: Value = serde_json::from_str(
                &std::fs::read_to_string(s.dir.join("MANIFEST.json")).unwrap(),
            )
            .unwrap();
            m["endpoints"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| e["file"].as_str().unwrap().to_string())
                .collect()
        };
        for f in &files {
            let rel = f
                .strip_prefix(&s.dir)
                .unwrap()
                .to_str()
                .unwrap()
                .to_string();
            // A file nobody listed is one nobody reviewed.
            assert!(
                rel == "MANIFEST.json" || listed.contains(&rel),
                "unlisted fixture {rel}"
            );
            let text = std::fs::read_to_string(f).unwrap();
            let mut leaks = scanner.find_leaks(&text);
            leaks.extend(scanner.find_leaks(&rel));
            assert!(leaks.is_empty(), "{}: {leaks:?}", f.display());
        }
        assert_eq!(files.len(), listed.len() + 1);
    }
}

/// A committed set, as the capture would hand it to the sanitiser.
fn entries_of(s: &FixtureSet) -> Vec<Entry> {
    s.endpoints
        .iter()
        .map(|(path, status, body)| Entry {
            path: path.clone(),
            params: vec![],
            result: if *status == 200 {
                Ok(body.clone())
            } else {
                Err(ErrBody {
                    status: *status,
                    message: str_of(body, "message").to_string(),
                    errors: body.get("errors").filter(|e| !e.is_null()).cloned(),
                })
            },
        })
        .collect()
}

#[test]
fn committed_fixtures_are_normalised() {
    for s in sets() {
        let before = entries_of(&s);
        let mut after = before.clone();
        normalise_keeping(&mut after, TEST_ESTATE_VMIDS);
        for (b, a) in before.iter().zip(&after) {
            assert_eq!(b, a, "{}: not normalised", s.pve_version);
        }
    }
}

#[tokio::test]
async fn fixtures_decode_into_the_client_types() {
    for s in sets() {
        let m = s.mock();
        let v = m.version().await.unwrap();
        assert_eq!(v.version, s.pve_version);
        assert!(v.release.starts_with(&v.version[..3]));
        assert_eq!(v.repoid.len(), 16);

        let nodes = m.nodes().await.unwrap();
        assert!(!nodes.is_empty());
        for n in &nodes {
            assert_eq!(n.status, NodeStatus::Online);
            assert!(n.uptime.is_some() && n.ssl_fingerprint.is_some());
            let fp: Fingerprint = n.ssl_fingerprint.as_deref().unwrap().parse().unwrap();
            // Round-trips in PVE's own display form.
            assert_eq!(fp.to_string(), n.ssl_fingerprint.clone().unwrap());
        }

        let mut seen = 0;
        for (path, status, body) in &s.endpoints {
            if !(path.contains("/tasks/UPID") && path.ends_with("/status") && *status == 200) {
                continue;
            }
            seen += 1;
            let upid = body["upid"].as_str().unwrap();
            let node = body["node"].as_str().unwrap();
            let parsed: Upid = upid.parse().unwrap();
            assert_eq!(parsed.to_string(), upid);
            assert_eq!(parsed.node, node);
            // The path the capture fetched is the path `api_path` builds.
            assert_eq!(
                api_path(&["nodes", node, "tasks", upid, "status"]).unwrap(),
                *path
            );
            let st = m.task_status(node, upid).await.unwrap();
            assert_eq!(st.status, TaskState::Stopped);
            let out = wait_for_task(
                &m,
                node,
                upid,
                Duration::from_secs(1),
                Duration::from_secs(5),
            )
            .await
            .unwrap();
            match body["exitstatus"].as_str().unwrap() {
                "OK" => assert_eq!(out, TaskOutcome::Ok),
                other => assert_eq!(out, TaskOutcome::Failed(other.to_string())),
            }
        }
        assert!(seen >= 1, "{}: no task status captured", s.pve_version);

        // Every UPID the task list shows parses, and its pieces agree with the
        // fields PVE lists next to it.
        for (path, _, body) in &s.endpoints {
            if !path.ends_with("/tasks") {
                continue;
            }
            for t in body.as_array().unwrap() {
                let u: Upid = t["upid"].as_str().unwrap().parse().unwrap();
                assert_eq!(u.node, t["node"].as_str().unwrap());
                assert_eq!(u.task_type, t["type"].as_str().unwrap());
                assert_eq!(u.id, t["id"].as_str().unwrap());
                assert_eq!(u.pid as u64, t["pid"].as_u64().unwrap());
                assert_eq!(u.pstart, t["pstart"].as_u64().unwrap());
                assert_eq!(u64::from(u.starttime), t["starttime"].as_u64().unwrap());
            }
        }
    }
}

fn str_of<'v>(v: &'v Value, k: &str) -> &'v str {
    v[k].as_str()
        .unwrap_or_else(|| panic!("`{k}` not a string in {v}"))
}

#[test]
fn guest_and_storage_shapes_are_what_later_code_will_rely_on() {
    for s in sets() {
        let res = s.data("/cluster/resources").unwrap().as_array().unwrap();
        for g in res {
            assert!(g["vmid"].is_u64());
            assert!(matches!(str_of(g, "type"), "qemu" | "lxc"));
            assert_eq!(
                str_of(g, "id"),
                format!("{}/{}", str_of(g, "type"), g["vmid"])
            );
            assert!(matches!(str_of(g, "status"), "running" | "stopped"));
            assert!(g["template"].is_u64());
        }
        for (path, status, body) in &s.endpoints {
            if *status != 200 {
                continue;
            }
            let segs: Vec<&str> = path.split('/').collect();
            match segs.as_slice() {
                ["", "nodes", _, kind @ ("qemu" | "lxc")] => {
                    for g in body.as_array().unwrap() {
                        assert!(g["vmid"].is_u64());
                        assert!(!str_of(g, "name").is_empty());
                        assert!(
                            matches!(str_of(g, "status"), "running" | "stopped"),
                            "{kind}"
                        );
                    }
                }
                ["", "nodes", _, "qemu", _, "config"] => {
                    assert!(body["name"].is_string() && body["digest"].is_string());
                }
                ["", "nodes", _, "lxc", _, "config"] => {
                    assert!(body["hostname"].is_string() && body["rootfs"].is_string());
                }
                ["", "nodes", _, "qemu" | "lxc", _, "status", "current"] => {
                    assert!(matches!(str_of(body, "status"), "running" | "stopped"));
                    assert!(body["vmid"].is_u64());
                }
                ["", "nodes", _, "qemu" | "lxc", _, "snapshot"] => {
                    // The live state is always listed last, named `current`.
                    let last = body.as_array().unwrap().last().unwrap();
                    assert_eq!(str_of(last, "name"), "current");
                }
                ["", "storage"] | ["", "nodes", _, "storage"] => {
                    for st in body.as_array().unwrap() {
                        assert!(st["storage"].is_string() && st["type"].is_string());
                        assert!(st["content"].is_string());
                    }
                }
                ["", "nodes", _, "storage", _, "content"] => {
                    for c in body.as_array().unwrap() {
                        assert!(c["volid"].is_string() && c["size"].is_u64());
                    }
                }
                _ => {}
            }
        }
    }
}

#[test]
fn error_fixtures_parse_back_through_the_envelope() {
    let mut n = 0;
    for s in sets() {
        for (path, status, body) in &s.endpoints {
            if (200..300).contains(status) {
                continue;
            }
            n += 1;
            let wire = json!({"data": null, "message": body["message"], "errors": body["errors"]});
            match parse_envelope(*status, None, wire.to_string().as_bytes()) {
                Err(PveError::Http {
                    status: st,
                    message,
                    errors,
                }) => {
                    assert_eq!(st, *status, "{path}");
                    assert_eq!(message, str_of(body, "message"));
                    assert_eq!(errors, body.get("errors").filter(|e| !e.is_null()).cloned());
                }
                other => panic!("{path}: {other:?}"),
            }
        }
    }
    assert!(n >= 3 * 3, "expected the error probes from every set");
}

#[test]
fn read_only_wrapper_issues_get_and_nothing_else() {
    // The wrapper's only method is `get`; the capture module must not even
    // name another verb. Cheap, and catches someone widening it.
    let src = include_str!("capture.rs");
    for verb in ["Method::Post", "Method::Put", "Method::Delete"] {
        assert!(!src.contains(verb), "capture.rs mentions {verb}");
    }
}

#[tokio::test]
async fn capture_replays_get_only_and_fetches_exactly_what_was_committed() {
    for s in sets() {
        let mut m = s.mock();
        // The write-permission probe is recorded only when it fails, so an
        // admin-host set has no route for it.
        let apt = format!("/nodes/{}/apt/update", "node1");
        if !s.endpoints.iter().any(|(p, _, _)| *p == apt) {
            m = m.on(Method::Get, &apt, json!([]));
        }
        let entries = capture_all(&ReadOnly::new(&m), CaptureLimits::default())
            .await
            .unwrap();

        let calls = m.calls();
        assert!(calls.len() >= s.endpoints.len());
        assert!(
            calls.iter().all(|c| c.method == Method::Get),
            "capture issued a non-GET"
        );

        let mut got: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
        let mut want: Vec<&str> = s.endpoints.iter().map(|(p, _, _)| p.as_str()).collect();
        got.sort_unstable();
        want.sort_unstable();
        assert_eq!(
            got, want,
            "{}: capture and fixtures disagree",
            s.pve_version
        );
    }
}

#[tokio::test]
async fn capture_aborts_on_transport_errors_and_records_http_ones() {
    let m = MockPve::new().on_err(
        Method::Get,
        "/version",
        PveError::Http {
            status: 403,
            message: "no".into(),
            errors: None,
        },
    );
    // /version failing at HTTP level is recorded; the next fetch has no route.
    assert!(matches!(
        capture_all(&ReadOnly::new(&m), CaptureLimits::default()).await,
        Err(PveError::Mock(_))
    ));
    let t = MockPve::new().on_err(Method::Get, "/version", PveError::Timeout);
    assert!(matches!(
        capture_all(&ReadOnly::new(&t), CaptureLimits::default()).await,
        Err(PveError::Timeout)
    ));
}

#[test]
fn write_set_refuses_a_version_that_is_not_digits_and_dots() {
    let out = std::env::temp_dir().join(format!("concord-fixture-test-{}", std::process::id()));
    for bad in ["../..", "", "9.2.", ".9", "9..2", "9.2/1", "9.2-1"] {
        let entry = Entry {
            path: "/version".to_string(),
            params: vec![],
            result: Ok(json!({"version": bad})),
        };
        let err = write_set(&out, vec![entry]).unwrap_err();
        assert!(err.contains("version"), "{bad}: {err}");
    }
    assert!(!out.exists(), "nothing may be written");
}
