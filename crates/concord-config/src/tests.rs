use std::env::VarError;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use concord_core::{restore_delay, FENCE_DEADLINE};

use crate::*;

const EXAMPLE: &str = include_str!("../../../concord.example.toml");
/// Shaped like a PVE token secret, so that leaking it would be visible.
const SECRET: &str = "00000000-0000-4000-8000-000000000001";
const OTHER: &str = "00000000-0000-4000-8000-000000000002";

fn no_env(_: &str) -> Result<String, VarError> {
    Err(VarError::NotPresent)
}

fn err(text: &str) -> String {
    let e = Config::parse(text).unwrap_err();
    assert!(!format!("{e:?}").contains(SECRET), "{e:?}");
    e.to_string()
}

fn swap(from: &str, to: &str) -> String {
    assert!(EXAMPLE.contains(from), "{from}");
    EXAMPLE.replacen(from, to, 1)
}

/// Replaces text in the second host only.
fn swap_second(from: &str, to: &str) -> String {
    let (a, b) = EXAMPLE.rsplit_once("[[hosts]]").unwrap();
    assert!(b.contains(from), "{from}");
    format!("{a}[[hosts]]{}", b.replacen(from, to, 1))
}

#[cfg(unix)]
fn secrets_file(dir: &Path, mode: u32, text: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let p = dir.join("s.toml");
    let mut f = std::fs::File::create(&p).unwrap();
    f.write_all(text.as_bytes()).unwrap();
    f.set_permissions(std::fs::Permissions::from_mode(mode))
        .unwrap();
    p
}

fn cfg_with(path: &Path) -> Config {
    let mut c = Config::parse(EXAMPLE).unwrap();
    c.secrets_file = Some(path.to_path_buf());
    c
}

fn both() -> String {
    format!("pve1 = \"{SECRET}\"\npve2 = \"{OTHER}\"\n")
}

#[test]
fn example_round_trips() {
    let c = Config::parse(EXAMPLE).unwrap();
    assert_eq!(c.hosts.len(), 2);
    let text = toml::to_string(&c).unwrap();
    assert_eq!(Config::parse(&text).unwrap(), c);
    // With the optional fields set as well.
    let full = swap("# fence_deadline_secs = 60", "fence_deadline_secs = 90")
        .replace("# network_mb_per_sec", "network_mb_per_sec");
    let c = Config::parse(&full).unwrap();
    assert_eq!(c.fence_deadline(), Duration::from_secs(90));
    assert_eq!(Config::parse(&toml::to_string(&c).unwrap()).unwrap(), c);
}

#[test]
fn defaults() {
    let host = EXAMPLE.split("[[hosts]]").nth(1).unwrap();
    let c = Config::parse(&format!("[[hosts]]{host}")).unwrap();
    assert!(c.listen.ip().is_loopback());
    assert_eq!(c.listen.port(), 8010);
    assert_eq!(c.poll_interval(), Duration::from_secs(10));
    assert_eq!(c.fence_deadline(), FENCE_DEADLINE);
    assert_eq!(c.budget, Budget::default());
    assert_eq!(c.secrets_file, None);
}

#[test]
fn the_malformed_field_is_named() {
    let fp = "10:11:12:13:14:15:16:17:18:19:1A:1B:1C:1D:1E:1F:20:21:22:23:24:25:26:27:28:29:2A:2B:2C:2D:2E:2F";
    let long = format!("user1@pve!token-1={SECRET}");
    let user_url = format!("https://root:{SECRET}@192.0.2.12");
    for (text, field) in [
        (swap_second(fp, "00:11"), "hosts[1].fingerprint: "),
        (
            swap_second("fingerprint", "# "),
            "hosts[1].fingerprint: missing",
        ),
        (
            swap_second("user1@pve!token-1", "concord"),
            "hosts[1].token_id: ",
        ),
        (
            swap_second("user1@pve!token-1", &long),
            "hosts[1].token_id: ",
        ),
        (swap_second("https", "http"), "hosts[1].api_url: "),
        (swap_second(":8006", ":8006/x"), "hosts[1].api_url: "),
        (
            swap_second("https://192.0.2.12", &user_url),
            "hosts[1].api_url: ",
        ),
        (
            swap_second("\"https://192.0.2.12:8006\"", "5"),
            "hosts[1].api_url: wrong type",
        ),
        (
            swap_second("\"pve2\"", "\"pve1\""),
            "hosts[1].name: same name as hosts[0]",
        ),
        (swap_second("\"pve2\"", "\"PVE1\""), "hosts[1].name: shares"),
        (swap_second("\"pve2\"", "\"a b\""), "hosts[1].name: "),
        (
            swap_second("name =", "nmae ="),
            "hosts[1]: unknown field `nmae`",
        ),
        (
            swap("poll_interval_secs = 10", "poll_interval_secs = 0"),
            "poll_interval_secs: ",
        ),
        (
            swap("poll_interval_secs = 10", "poll_interval_secs = -1"),
            "poll_interval_secs: ",
        ),
        (
            swap(
                "poll_interval_secs = 10",
                &format!("poll_interval_secs = \"{SECRET}\""),
            ),
            "poll_interval_secs: wrong type",
        ),
        (
            swap("# fence_deadline_secs = 60", "fence_deadline_secs = 0"),
            "fence_deadline_secs: ",
        ),
        (swap("127.0.0.1:8010", "localhost"), "listen: "),
        (
            swap("io_weight = 10", "io_weight = 0"),
            "budget.io_weight: ",
        ),
        (
            swap("io_weight = 10", "io_weight = \"x\""),
            "budget.io_weight: wrong type",
        ),
        (
            swap("link_mbps = 1000", "link_mbps = 0"),
            "budget.link_mbps: ",
        ),
        (swap("link_mbps", "lnk"), "budget: unknown field `lnk`"),
        (
            swap("# fence_deadline_secs", "extra"),
            "configuration: unknown field `extra`",
        ),
        ("poll_interval_secs = 10".into(), "hosts: "),
        (
            format!("a = 1\ntoken = {SECRET}"),
            "configuration: syntax error on line 2",
        ),
    ] {
        let e = err(&text);
        assert!(e.starts_with(field), "wanted {field}, got {e}");
    }
}

#[test]
fn colliding_override_variables_are_refused() {
    let text = swap("\"pve1\"", "\"pve-a\"").replace("\"pve2\"", "\"pve.a\"");
    assert!(err(&text).contains("CONCORD_TOKEN_PVE_A"));
}

#[test]
fn fence_override_keeps_the_restore_margin() {
    let c = Config::parse(&swap(
        "# fence_deadline_secs = 60",
        "fence_deadline_secs = 3600",
    ))
    .unwrap();
    assert!(restore_delay(c.fence_deadline()) > c.fence_deadline());
}

#[test]
fn network_cap() {
    let cap = |link_mbps| {
        Budget {
            link_mbps,
            ..Budget::default()
        }
        .network_cap_mb_per_sec()
    };
    assert_eq!((cap(100), cap(1000), cap(10_000)), (30, 50, 300));
    let caps: Vec<u64> = (1..100).map(|n| cap(n * 500)).collect();
    assert!(caps.windows(2).all(|w| w[0] <= w[1]), "{caps:?}");
    let b = Budget {
        network_mb_per_sec: Some(5),
        ..Budget::default()
    };
    assert_eq!(b.network_cap_mb_per_sec(), 5);
}

#[test]
fn a_relative_secrets_file_is_beside_the_config() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("concord.toml");
    std::fs::write(&p, EXAMPLE).unwrap();
    let c = Config::load(&p).unwrap();
    assert_eq!(
        c.secrets_file,
        Some(dir.path().join("concord-secrets.toml"))
    );
}

#[cfg(unix)]
#[test]
fn any_group_or_other_permission_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    for bit in [0o040, 0o020, 0o010, 0o004, 0o002, 0o001] {
        let p = secrets_file(dir.path(), 0o600 | bit, &both());
        let e = Secrets::load_with(&cfg_with(&p), &no_env).unwrap_err();
        assert!(matches!(e, ConfigError::SecretsFile { .. }), "{e}");
        assert!(e.to_string().contains("mode 06"), "{e}");
    }
    for mode in [0o600, 0o400] {
        let p = dir.path().join("s.toml");
        std::fs::remove_file(&p).unwrap();
        let p = secrets_file(p.parent().unwrap(), mode, &both());
        Secrets::load_with(&cfg_with(&p), &no_env).unwrap();
    }
}

#[cfg(unix)]
#[test]
fn only_a_regular_file_is_accepted() {
    use std::os::unix::ffi::OsStrExt;
    let dir = tempfile::tempdir().unwrap();
    let fifo = dir.path().join("fifo");
    let c = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
    // SAFETY: `c` is a valid NUL-terminated path for the length of the call.
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    for p in [fifo.as_path(), dir.path(), Path::new("/dev/null")] {
        let e = Secrets::load_with(&cfg_with(p), &no_env).unwrap_err();
        assert!(e.to_string().contains("not a regular file"), "{e}");
    }
}

#[cfg(unix)]
#[test]
fn nothing_prints_a_secret() {
    let dir = tempfile::tempdir().unwrap();
    let p = secrets_file(dir.path(), 0o600, &both());
    let c = cfg_with(&p);
    let s = Secrets::load_with(&c, &no_env).unwrap();
    let clients = c.build_clients(&s, Duration::from_secs(5)).unwrap();
    assert_eq!(clients[0].0, "pve1");
    assert_eq!(clients[1].0, "pve2");
    for out in [
        format!("{s:?} {:?} {}", s.get("pve1"), s.get("pve1").unwrap()),
        format!("{c:?}"),
        toml::to_string(&c).unwrap(),
    ] {
        assert!(!out.contains(SECRET), "{out}");
    }
    assert!(format!("{s:?}").contains("pve1"));
}

#[cfg(unix)]
#[test]
fn secrets_file_errors_quote_nothing() {
    let dir = tempfile::tempdir().unwrap();
    for text in [
        format!("pve1 = {SECRET}\n"),
        format!("pve1 = \"{SECRET}\n"),
        format!("pve1 = [\"{SECRET}\"]\n"),
        format!("pve1 = \"{SECRET}\"\npve1 = \"{SECRET}\"\n"),
        format!("\"{SECRET}\"\n"),
        format!("[pve1]\n\"{SECRET}\" = 1\n"),
        format!("\"{SECRET}\" = 1\n"),
    ] {
        let p = secrets_file(dir.path(), 0o600, &text);
        let e = Secrets::load_with(&cfg_with(&p), &no_env).unwrap_err();
        let shown = format!("{e} {e:?} {e:#?}");
        assert!(matches!(e, ConfigError::SecretsFile { .. }), "{e}");
        assert!(!shown.contains(&SECRET[..13]), "{shown}");
    }
    // A well-formed file whose secret the client refuses.
    let bad = format!("{SECRET}x");
    let p = secrets_file(
        dir.path(),
        0o600,
        &format!("pve1 = \"{bad}\"\npve2 = \"{OTHER}\""),
    );
    let c = cfg_with(&p);
    let s = Secrets::load_with(&c, &no_env).unwrap();
    let e = c.build_clients(&s, Duration::from_secs(5)).err().unwrap();
    let shown = format!("{e} {e:?}");
    assert!(shown.contains("pve1") && !shown.contains(SECRET), "{shown}");
}

#[cfg(unix)]
#[test]
fn a_missing_secret_names_the_host() {
    let dir = tempfile::tempdir().unwrap();
    let p = secrets_file(dir.path(), 0o600, &format!("pve1 = \"{SECRET}\""));
    let e = Secrets::load_with(&cfg_with(&p), &no_env).unwrap_err();
    assert!(e.to_string().contains("\"pve2\""), "{e}");
    assert!(e.to_string().contains("CONCORD_TOKEN_PVE2"), "{e}");
}

#[cfg(unix)]
#[test]
fn the_environment_overrides() {
    use std::os::unix::ffi::OsStringExt;
    let dir = tempfile::tempdir().unwrap();
    let p = secrets_file(dir.path(), 0o600, &both());
    // Config points nowhere; the variable points at the file. The host override
    // is malformed so that building a client shows which value was used.
    let c = cfg_with(Path::new("/nonexistent"));
    let file_var = p.to_str().unwrap().to_string();
    let env = |k: &str| match k {
        SECRETS_FILE_ENV => Ok(file_var.clone()),
        "CONCORD_TOKEN_PVE2" => Ok("not-a-uuid".into()),
        _ => Err(VarError::NotPresent),
    };
    let s = Secrets::load_with(&c, &env).unwrap();
    let e = c.build_clients(&s, Duration::from_secs(5)).err().unwrap();
    assert!(matches!(e, ConfigError::Client { host, .. } if host == "pve2"));

    let mut c = c;
    c.secrets_file = None;
    Secrets::load_with(&c, &|k| match k {
        SECRETS_FILE_ENV => Err(VarError::NotPresent),
        _ => Ok(SECRET.into()),
    })
    .unwrap();

    let mut bytes = SECRET.as_bytes().to_vec();
    bytes.push(0xff);
    let e = Secrets::load_with(&c, &|k| match k {
        "CONCORD_TOKEN_PVE1" => Err(VarError::NotUnicode(std::ffi::OsString::from_vec(
            bytes.clone(),
        ))),
        _ => Err(VarError::NotPresent),
    })
    .unwrap_err();
    assert!(!format!("{e} {e:?}").contains(SECRET), "{e:?}");
    assert!(e.to_string().starts_with("CONCORD_TOKEN_PVE1"), "{e}");
}
