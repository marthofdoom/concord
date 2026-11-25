use std::collections::BTreeSet;
use std::path::Path;

use serde_json::{json, Map, Value};

use crate::keys::{INDEXED, PLAIN};
use crate::property::{Schema, DEV, FEATURES, MP, NET, ROOTFS, UNUSED};
use crate::*;

fn pending(digest: &str) -> Value {
    json!([{"key": "digest", "value": digest}, {"key": "hostname", "value": "x"}])
}

fn parse(config: &Value) -> Result<Layout, Refusals> {
    let digest = config["digest"].as_str().unwrap_or("d");
    Layout::parse(ConfigSource {
        config,
        pending: Some(&pending(digest)),
        env: EnvVisibility::Established,
    })
}

fn base() -> Value {
    json!({"arch": "amd64", "digest": "d", "ostype": "debian", "rootfs": "st:100/vm-100-disk-0.raw,size=8G"})
}

fn with(key: &str, value: Value) -> Value {
    let mut c = base();
    c[key] = value;
    c
}

fn reasons(config: &Value) -> Vec<Refusal> {
    parse(config).unwrap_err().reasons().to_vec()
}

/// The config less the keys that are exposed rather than carried.
fn carried(config: &Value) -> Map<String, Value> {
    let mut m = config.as_object().unwrap().clone();
    for n in NOT_CARRIED {
        m.remove(n.key);
    }
    m
}

fn assert_round_trip(config: &Value) {
    let l = parse(config).unwrap_or_else(|e| panic!("{config}: {e}"));
    assert_eq!(l.expose_config(), carried(config));
    // And again through the groups a caller writes: nothing is in two, or none.
    let mut keys: Vec<String> = l
        .parameters()
        .into_iter()
        .chain(l.volume_parameters())
        .map(|p| {
            let original = &config[&p.key];
            let text = original
                .as_str()
                .map_or_else(|| original.to_string(), str::to_string);
            assert_eq!(p.value.expose(), text, "{}", p.key);
            p.key
        })
        .collect();
    keys.extend(l.unused().map(|(i, _)| format!("unused{i}")));
    if config.get("lxc").is_some() {
        keys.push("lxc".into());
    }
    keys.sort();
    let expected: Vec<String> = carried(config).keys().cloned().collect();
    assert_eq!(keys, expected);
}

/// A config with every key and every option.
fn full() -> Value {
    json!({
        "arch": "amd64", "digest": "d", "ostype": "debian", "parent": "before",
        "rootfs": "st:100/vm-100-disk-0.raw,size=8G,acl=1,mountoptions=noatime;discard,ro=0,quota=0,replicate=1,shared=0,idmap=passthrough",
        "mp0": "st:100/vm-100-disk-1.raw,mp=/data,backup=1,size=4G,keepattrs=1",
        "mp1": "/srv/media,mp=/media,ro=1,shared=1",
        "mp2": "/dev/sdx1,mp=/disk",
        "mp10": "volume=st:subvol-100-disk-2,mp=/x y, ,backup=No,,",
        "net0": "name=eth0,bridge=vmbr0,firewall=1,gw=192.0.2.1,gw6=2001:db8::1,host-managed=1,hwaddr=02:00:00:00:00:01,ip=192.0.2.9/24,ip6=auto,link_down=0,mtu=1500,rate=1.5,tag=5,trunks=2;3,type=veth",
        "dev0": "/dev/net/tun,mode=0660,uid=0,gid=44,deny-write=0",
        "unused0": "st:100/vm-100-disk-9.raw",
        "features": "nesting=1,keyctl=1,fuse=0,mknod=0,force_rw_sys=0,mount=nfs;cifs",
        "hostname": "guest", "onboot": 1, "startup": "order=2,up=30", "tags": "b;a",
        "description": "line one\n\n  \u{e9} = 'two' \"x\"\r\n", "unprivileged": 1, "cores": 2,
        "cpulimit": "1.50", "cpuunits": 100, "memory": 512, "swap": 0,
        "nameserver": "192.0.2.1 192.0.2.2", "searchdomain": "example.org",
        "timezone": "host", "hookscript": "st:snippets/h.pl", "protection": 0,
        "entrypoint": "/bin/sh -c 'exec  \"$0\"'", "env": "A=1\0B=\0C=x=y\t z",
        "cmode": "console", "console": 1, "tty": 2, "debug": 0, "template": 0,
        "lxc": [["lxc.init.uid", "1000"], ["lxc.cap.drop", ""],
                ["lxc.mount.entry", "/dev/net/tun dev/net/tun none bind,create=file"],
                ["lxc.signal.halt", "SIGTERM"], ["lxc.cap.drop", "sys_admin"]],
    })
}

#[test]
fn full_config_round_trips() {
    assert_round_trip(&base());
    assert_round_trip(&full());
    assert_round_trip(&with("lxc", json!([])));
    let used: BTreeSet<String> = full().as_object().unwrap().keys().cloned().collect();
    for (key, _) in PLAIN {
        assert!(used.contains(*key), "{key} is untested");
    }
}

#[test]
fn captured_configs_round_trip() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../concord-pve/tests/fixtures");
    let mut seen = 0;
    for set in std::fs::read_dir(root).unwrap() {
        for file in std::fs::read_dir(set.unwrap().path()).unwrap() {
            let path = file.unwrap().path();
            let name = path.file_name().unwrap().to_str().unwrap();
            if name.contains("_lxc_") && name.ends_with("_config.json") {
                let text = std::fs::read_to_string(&path).unwrap();
                let v: Value = serde_json::from_str(&text).unwrap();
                // Captured refusals (403) carry a message instead.
                if v.get("digest").is_some() {
                    assert_round_trip(&v);
                    seen += 1;
                }
            }
        }
    }
    assert!(seen >= 4, "{seen} captured container configs");
}

#[test]
fn layout_is_typed() {
    let l = parse(&full()).unwrap();
    let mounts: Vec<(String, &str, char)> = l
        .mounts()
        .iter()
        .map(|m| {
            let class = match m.source {
                MountSource::Volume(_) => 'v',
                MountSource::Bind(_) => 'b',
                MountSource::Device(_) => 'd',
            };
            (m.slot.key(), m.target(), class)
        })
        .collect();
    let expected = [
        ("rootfs", "/", 'v'),
        ("mp0", "/data", 'v'),
        ("mp1", "/media", 'b'),
        ("mp2", "/disk", 'd'),
        ("mp10", "/x y", 'v'),
    ];
    assert_eq!(mounts.len(), expected.len());
    for (got, want) in mounts.iter().zip(expected) {
        assert_eq!((got.0.as_str(), got.1, got.2), want);
    }
    let mp0 = &l.mounts()[1];
    assert_eq!(
        (mp0.backup(), mp0.size(), mp0.read_only()),
        (Some(true), Some("4G"), None)
    );
    assert_eq!(l.mounts()[2].read_only(), Some(true));
    assert_eq!(l.mounts()[2].shared(), Some(true));
    assert_eq!(l.mounts()[4].backup(), Some(false));
    let names: Vec<&str> = mp0.property.options().iter().map(|o| o.name).collect();
    assert_eq!(names, ["volume", "mp", "backup", "size", "keepattrs"]);
    assert_eq!(l.flag("unprivileged"), Some(true));
    assert_eq!(l.flag("protection"), Some(false));
    assert_eq!((l.digest(), l.parent()), ("d", Some("before")));
    assert_eq!(l.devs().count(), 1);
    assert_eq!(l.nets().count(), 1);
}

#[test]
fn volumes_are_never_among_the_declared_parameters() {
    let l = parse(&full()).unwrap();
    let declared: Vec<String> = l.parameters().into_iter().map(|p| p.key).collect();
    for key in ["rootfs", "mp0", "mp10", "unused0", "lxc"] {
        assert!(!declared.iter().any(|k| k == key), "{key}");
    }
    let volumes: Vec<String> = l.volume_parameters().into_iter().map(|p| p.key).collect();
    assert_eq!(volumes, ["rootfs", "mp0", "mp10"]);
}

#[test]
fn image_candidates_are_grouped() {
    let l = parse(&full()).unwrap();
    let mut lxc = Vec::new();
    let mut other = 0;
    for c in l.image_candidates() {
        match c {
            ImageCandidate::Lxc(i, line) => lxc.push((i, line.key.as_str())),
            _ => other += 1,
        }
    }
    assert_eq!(lxc, [(0, "lxc.init.uid"), (3, "lxc.signal.halt")]);
    // entrypoint, env, cmode, net0's host-managed
    assert_eq!(other, 4);
    assert!(parse(&base()).unwrap().image_candidates().is_empty());
}

#[test]
fn every_schema_key_is_carried_or_accounted_for() {
    // Transcribed from pve-container 6.1.14, apart from the table it checks.
    let schema = "arch cmode console cores cpulimit cpuunits debug description dev digest \
        entrypoint env features hookscript hostname lock lxc memory mp nameserver net onboot \
        ostype parent protection rootfs searchdomain snaptime startup swap tags template \
        timezone tty unprivileged unused \
        pending snapshots";
    let schema: BTreeSet<&str> = schema.split_whitespace().collect();
    assert_eq!(ours(), schema);
    for n in NOT_CARRIED {
        assert!(!n.reason.is_empty());
        assert!(!PLAIN.iter().any(|(k, _)| *k == n.key), "{}", n.key);
        let mut c = base();
        c[n.key] = json!("d");
        assert_eq!(
            parse(&c).is_ok(),
            n.fate == NotCarried::Exposed,
            "{}",
            n.key
        );
    }
    let options: [(&Schema, &str); 6] = [
        (&ROOTFS, "acl idmap mountoptions quota replicate ro shared size volume"),
        (&MP, "acl backup idmap keepattrs mountoptions mp quota replicate ro shared size volume"),
        (&UNUSED, "volume"),
        (&NET, "bridge firewall gw gw6 host-managed hwaddr ip ip6 link_down mtu name rate tag trunks type"),
        (&DEV, "deny-write gid mode path uid"),
        (&FEATURES, "force_rw_sys fuse keyctl mknod mount nesting"),
    ];
    for (schema, expected) in options {
        assert_eq!(option_names(schema), expected);
    }
}

fn ours() -> BTreeSet<&'static str> {
    let mut ours: BTreeSet<&str> = PLAIN.iter().map(|(k, _)| *k).collect();
    ours.extend(INDEXED.iter().map(|(k, _, _)| *k));
    ours.extend(NOT_CARRIED.iter().map(|n| n.key));
    ours.extend(["features", "rootfs", "lxc"]);
    ours
}

fn option_names(s: &Schema) -> String {
    let mut names: Vec<&str> = s.options.iter().map(|(n, _)| *n).collect();
    names.sort_unstable();
    names.join(" ")
}

/// Compares with the installed PVE. Run by hand when PVE is updated.
#[test]
#[ignore = "needs a PVE host"]
fn installed_schema_matches() {
    let script = r#"use PVE::LXC::Config; my $p = PVE::LXC::Config->json_config_properties({});
        for (sort keys %$p) { my $f = $p->{$_}->{format};
        print "$_ $p->{$_}->{type} ", (ref $f ? join(' ', sort keys %$f) : ''), "\n" }"#;
    let out = std::process::Command::new("perl")
        .args(["-e", script])
        .output()
        .unwrap();
    assert!(out.status.success());
    let mut theirs: BTreeSet<String> = [
        "digest",
        "lxc",
        "parent",
        "snaptime",
        "pending",
        "snapshots",
    ]
    .map(String::from)
    .into();
    for line in String::from_utf8(out.stdout).unwrap().lines() {
        let mut parts = line.splitn(3, ' ');
        let (key, kind, options) = (
            parts.next().unwrap(),
            parts.next().unwrap(),
            parts.next().unwrap(),
        );
        let stem = key.trim_end_matches(|c: char| c.is_ascii_digit());
        theirs.insert(stem.to_string());
        let schema = match stem {
            "rootfs" => &ROOTFS,
            "mp" => &MP,
            "unused" => &UNUSED,
            "net" => &NET,
            "dev" => &DEV,
            "features" => &FEATURES,
            _ => {
                assert_eq!(options, "", "{key} is structured");
                if let Some((_, s)) = PLAIN.iter().find(|(k, _)| *k == key) {
                    use crate::keys::Scalar::*;
                    let ours = match s {
                        Bool => "boolean",
                        Int => "integer",
                        Number => "number",
                        Line | Text | Env => "string",
                    };
                    assert_eq!(ours, kind, "{key}");
                }
                continue;
            }
        };
        assert_eq!(option_names(schema), options, "{key}");
    }
    assert_eq!(
        ours()
            .into_iter()
            .map(String::from)
            .collect::<BTreeSet<_>>(),
        theirs
    );
}

#[test]
fn every_reason_is_listed() {
    let c = json!({"arch": "amd64", "lock": "backup", "newkey": 1, "mp0": "what", "cores": [2], "tags": ""});
    let e = Layout::parse(ConfigSource {
        config: &c,
        pending: None,
        env: EnvVisibility::Unknown,
    })
    .unwrap_err();
    for r in [
        Refusal::EnvVisibilityUnknown,
        Refusal::PendingUnknown,
        Refusal::Locked,
        Refusal::UnknownKey("newkey".into()),
        Refusal::Missing("rootfs"),
        Refusal::Missing("digest"),
        Refusal::Missing("ostype"),
        Refusal::MissingOption {
            key: "mp0".into(),
            option: "mp",
        },
        Refusal::Shape {
            key: "cores".into(),
        },
        Refusal::Empty { key: "tags".into() },
    ] {
        assert!(e.reasons().contains(&r), "{r:?} not in {e}");
    }
    assert_eq!(e.reasons().len(), 10);
    let core: concord_core::Error = e.into();
    assert!(matches!(core, concord_core::Error::NotSupported { .. }));
}

#[test]
fn unknown_and_malformed_input_is_refused() {
    let cases = [
        ("newkey", json!("x")),
        ("mp256", json!("st:v,mp=/a")),
        ("mp01", json!("st:v,mp=/a")),
        ("mp", json!("st:v,mp=/a")),
        ("mp+1", json!("st:v,mp=/a")),
        ("net32", json!("name=eth0")),
        ("dev256", json!("/dev/a")),
        ("unused256", json!("st:v")),
        ("snapshots", json!({})),
        ("snaptime", json!(1)),
        ("pending", json!({})),
        ("template", json!(1)),
        ("onboot", json!(2)),
        ("onboot", json!(true)),
        ("onboot", json!(null)),
        ("cores", json!(-1)),
        ("cores", json!(1.5)),
        ("cores", json!("two")),
        ("cpulimit", json!("1.")),
        ("hostname", json!(5)),
        ("hostname", json!({"a": 1})),
        ("hostname", json!("a\nrootfs: st:other")),
        ("env", json!("A=1\0\0B=2")),
        ("env", json!("A=1\0")),
        ("env", json!("noequals")),
        ("env", json!("A-B=1")),
        ("env", json!("A=1\nB=2")),
        ("net0", json!("eth0,bridge=vmbr0")),
        ("net0", json!("bridge=vmbr0")),
        ("net0", json!("name=eth0,tag=x")),
        ("net0", json!("name=eth0,new=1")),
        ("net0", json!("name=eth0,=1")),
        ("net0", json!("name=eth0,ip=")),
        ("net0", json!("name=eth0, ip=dhcp")),
        ("net0", json!("name=eth0,name=eth1")),
        ("features", json!("nesting=1,newfeature=1")),
        ("rootfs", json!("st:vm-100-disk-0,mp=/x")),
        ("rootfs", json!("/srv/root")),
        ("rootfs", json!("/dev/sdx")),
        ("mp0", json!("st:vm-100-disk-0,volume=st:x,mp=/a")),
        ("dev0", json!("/srv/x")),
        ("dev0", json!("mode=0660")),
        ("dev0", json!("/dev/../etc")),
        ("unused0", json!("/srv/x")),
        ("unused0", json!("st:v,size=1G")),
        ("lxc", json!({"lxc.init.uid": "1"})),
        ("lxc", json!([["lxc.init.uid"]])),
        ("lxc", json!([["lxc.init.uid", 5]])),
        ("lxc", json!([["lxc.init.uid", "5", "6"]])),
        ("lxc", json!([["rootfs", "5"]])),
        ("lxc", json!([["lxc.", "5"]])),
        ("lxc", json!([["lxc.environment.runtime", "A=1"]])),
        ("lxc", json!([["lxc.init.cwd", "a\nb"]])),
    ];
    for (key, value) in cases {
        let c = with(key, value);
        assert!(parse(&c).is_err(), "accepted {key}: {}", c[key]);
    }
    assert_eq!(reasons(&json!([])), [Refusal::NotAnObject]);
}

#[test]
fn ambiguous_mounts_are_refused() {
    for source in [
        "data",
        "//dev/sda",
        "/./dev/sda",
        "/srv/../dev/sda",
        "/srv/.",
        "/dev",
        "/dev/",
        "/..",
        "dev/sda",
        "./x",
        "st:",
        ":v",
        "s:v",
        "-st:v",
        "st-:v",
        "st:a b",
        "st:../v",
        "http://x",
        "1st:v",
    ] {
        let r = reasons(&with("mp0", json!(format!("{source},mp=/a"))));
        assert_eq!(
            r,
            [Refusal::AmbiguousSource { key: "mp0".into() }],
            "{source}"
        );
    }
    for source in ["st:8", "st:0.5"] {
        let r = reasons(&with("mp0", json!(format!("{source},mp=/a"))));
        assert_eq!(r, [Refusal::Allocation { key: "mp0".into() }]);
    }
    for key in ["mp0", "unused0"] {
        let v = "st:100/vm-100-disk-0.raw";
        let v = if key == "mp0" {
            format!("{v},mp=/a")
        } else {
            v.into()
        };
        assert!(matches!(
            reasons(&with(key, json!(v)))[..],
            [Refusal::SharedVolume { .. }]
        ));
    }
}

#[test]
fn a_config_alone_is_not_enough() {
    let c = base();
    let check = |pending: Option<&Value>, env| {
        Layout::parse(ConfigSource {
            config: &c,
            pending,
            env,
        })
        .map(|_| ())
        .map_err(|r| r.reasons().to_vec())
    };
    let ok = EnvVisibility::Established;
    let good = pending("d");
    assert_eq!(check(Some(&good), ok), Ok(()));
    assert_eq!(
        check(Some(&good), EnvVisibility::Unknown),
        Err(vec![Refusal::EnvVisibilityUnknown])
    );
    assert_eq!(check(None, ok), Err(vec![Refusal::PendingUnknown]));
    assert_eq!(
        check(Some(&pending("other")), ok),
        Err(vec![Refusal::PendingStale])
    );
    assert_eq!(
        check(Some(&json!([])), ok),
        Err(vec![Refusal::PendingShape])
    );
    assert_eq!(
        check(Some(&json!({})), ok),
        Err(vec![Refusal::PendingShape])
    );
    for extra in [
        json!({"key": "memory", "value": 1, "pending": 2}),
        json!({"key": "memory", "pending": 2}),
        json!({"key": "memory", "delete": 1}),
        json!({"key": "memory", "delete": "2"}),
        json!({"key": "memory", "delete": null}),
    ] {
        let mut p = pending("d");
        p.as_array_mut().unwrap().push(extra.clone());
        assert_eq!(
            check(Some(&p), ok),
            Err(vec![Refusal::PendingChange {
                key: "memory".into()
            }]),
            "{extra}"
        );
    }
    let mut p = pending("d");
    p.as_array_mut()
        .unwrap()
        .push(json!({"key": "memory", "value": 1, "new": 1}));
    assert_eq!(check(Some(&p), ok), Err(vec![Refusal::PendingShape]));
}

#[test]
fn nothing_prints_a_value() {
    let c = json!({
        "arch": "SECRET", "digest": "d", "ostype": "SECRET",
        "rootfs": "SECRET:SECRET,size=SECRET", "mp0": "/SECRET,mp=/SECRET",
        "mp1": "/dev/SECRET,mp=/SECRET", "dev0": "/dev/SECRET", "unused0": "SECRET:SECRET2",
        "net0": "name=SECRET,host-managed=1", "features": "mount=SECRET", "env": "SECRET=SECRET",
        "description": "SECRET", "entrypoint": "SECRET", "lxc": [["lxc.init.cwd", "SECRET"]],
    });
    let l = parse(&c).unwrap();
    let mut out = format!("{l:?} {:?}", l.mounts());
    out += &format!("{:?} {:?}", l.parameters(), l.volume_parameters());
    out += &format!("{:?} {:?}", l.raw_lxc(), l.image_candidates());
    out += &format!("{:?} {:?}", l.setting("env"), l.features());
    out += &format!("{:?}", l.unused().collect::<Vec<_>>());
    assert!(out.contains("redacted") && !out.contains("SECRET"), "{out}");

    let bad = json!({
        "arch": ["SECRET"], "cores": "SECRET", "env": "SECRET", "onboot": "SECRET",
        "rootfs": "SECRET", "mp0": "st:v,SECRET=1,mp=/a", "mp1": "st:v,SECRET",
        "net0": "name=e,tag=SECRET", "dev0": "SECRET", "features": "SECRET", "hostname": "SECRET\n",
        "lxc": [["SECRET", "SECRET"], "SECRET", ["lxc.SECRET", "x"]], "lock": "SECRET",
        "unused0": "SECRET",
    });
    let e = parse(&bad).unwrap_err();
    assert!(e.reasons().len() > 12);
    let out = format!("{e} {e:?} {}", concord_core::Error::from(e.clone()));
    assert!(!out.contains("SECRET"), "{out}");
}

/// xorshift: enough spread for generating configs, and repeatable.
struct Rng(u64);

impl Rng {
    fn next(&mut self, n: usize) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 % n as u64) as usize
    }

    fn text(&mut self, alphabet: &str) -> String {
        let chars: Vec<char> = alphabet.chars().collect();
        (0..1 + self.next(12))
            .map(|_| chars[self.next(chars.len())])
            .collect()
    }

    /// Options in random order and spelling, with blank parts.
    fn property(&mut self, schema: &Schema, mandatory: &[(&str, String)]) -> String {
        use crate::property::Kind;
        let mut parts: Vec<String> = Vec::new();
        for (name, value) in mandatory {
            let bare = schema.default == Some(*name) && self.next(2) == 0;
            parts.push(if bare {
                value.clone()
            } else {
                format!("{name}={value}")
            });
        }
        for (name, kind) in schema.options {
            if mandatory.iter().any(|(m, _)| m == name) || self.next(2) == 0 {
                continue;
            }
            let value = match kind {
                Kind::Text => self.text("aZ9 .;:/='\"\\é%#-_"),
                Kind::Bool => ["0", "1", "on", "No", "TRUE"][self.next(5)].into(),
                Kind::Int => self.text("0123456789"),
                Kind::Number => format!("{}.{}", self.text("0123456789"), self.next(10)),
            };
            parts.push(format!("{name}={value}"));
        }
        for i in (1..parts.len()).rev() {
            parts.swap(i, self.next(i + 1));
        }
        if self.next(4) == 0 {
            parts.insert(self.next(parts.len() + 1), [" ", ""][self.next(2)].into());
        }
        parts.join(",")
    }

    fn config(&mut self) -> Value {
        use crate::keys::Scalar;
        let line = "aZ9 .,;:/='\"\\é%#\t-_";
        let mut c = base();
        for (key, kind) in PLAIN {
            if self.next(2) == 0 || *key == "template" {
                continue;
            }
            c[*key] = match kind {
                Scalar::Bool => {
                    [json!(0), json!(1), json!("1"), json!("yes")][self.next(4)].clone()
                }
                Scalar::Int => {
                    [json!(self.next(9999)), json!(self.text("0123456789"))][self.next(2)].clone()
                }
                Scalar::Number => {
                    [json!(self.next(99)), json!(0.25), json!("2.50")][self.next(3)].clone()
                }
                Scalar::Line => json!(self.text(line)),
                Scalar::Text => json!(self.text("a \n\r\té#%\"\\")),
                Scalar::Env => {
                    let entries: Vec<String> = (0..1 + self.next(4))
                        .map(|_| format!("{}={}", self.text("aZ_9"), self.text(line)))
                        .collect();
                    json!(entries.join("\0"))
                }
            };
        }
        for i in 0..self.next(6) {
            let n = i * 40 + self.next(40);
            let source = match self.next(3) {
                0 => format!("st:{n}/v"),
                1 => format!("/srv/{n}/"),
                _ => format!("/dev/x{n}"),
            };
            let path = format!("/{}", self.text("ab /"));
            c[format!("mp{n}")] = json!(self.property(&MP, &[("volume", source), ("mp", path)]));
            c[format!("unused{n}")] = json!(format!("st:u{n}"));
            c[format!("net{i}")] = json!(self.property(&NET, &[("name", format!("eth{i}"))]));
            c[format!("dev{n}")] = json!(self.property(&DEV, &[("path", format!("/dev/y{n}"))]));
        }
        let rootfs = [("volume", "st:root".to_string())];
        c["rootfs"] = json!(self.property(&ROOTFS, &rootfs));
        c["features"] = json!(self.property(&FEATURES, &[("nesting", "1".into())]));
        if self.next(2) == 0 {
            let lines: Vec<Value> = (0..self.next(5))
                .map(|_| json!([format!("lxc.{}", self.text("ab_-.9")), self.text(line)]))
                .collect();
            c["lxc"] = json!(lines);
        }
        c
    }
}

#[test]
fn generated_configs_round_trip() {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for _ in 0..2000 {
        assert_round_trip(&rng.config());
    }
}

/// Removing or damaging any one key is noticed: the result is refused, or
/// carries exactly what was given.
#[test]
fn generated_damage_is_never_dropped() {
    let mut rng = Rng(0xdead_beef_cafe_f00d);
    for _ in 0..2000 {
        let mut c = rng.config();
        let keys: Vec<String> = c.as_object().unwrap().keys().cloned().collect();
        let key = &keys[rng.next(keys.len())];
        let odd = [
            json!(null),
            json!(true),
            json!([]),
            json!({}),
            json!(""),
            json!(" "),
            json!("a\0b"),
            json!("a,b=c,d"),
            json!(1e300),
            json!(-3),
            json!(","),
            json!("x=1"),
        ];
        c[key] = odd[rng.next(odd.len())].clone();
        if parse(&c).is_ok() {
            assert_round_trip(&c);
        }
    }
}

#[test]
fn two_spellings_of_a_volume_are_refused() {
    for v in ["st:100//v", "st:100/v/", "st:/100/v", "st:"] {
        assert_eq!(
            reasons(&with("mp0", json!(format!("{v},mp=/x")))),
            [Refusal::AmbiguousSource { key: "mp0".into() }],
            "{v}"
        );
    }
}

#[test]
fn a_hostile_pending_key_is_quoted() {
    let r = Refusal::PendingChange {
        key: "\u{1b}[2Jx\nroot".into(),
    };
    assert!(!r.to_string().chars().any(char::is_control));
}

#[test]
fn every_repeat_of_an_option_is_refused_once() {
    let n = 50_000;
    let raw = format!("st:100/v,{}{}", "acl=1,".repeat(n), "mp=/x,".repeat(n));
    let start = std::time::Instant::now();
    // Identical reasons are reported once, so one for `acl` and one for `mp`.
    assert_eq!(reasons(&with("mp0", json!(raw))).len(), 2);
    // Keeping the repeats gives the same reasons, but takes over 15 s here.
    assert!(start.elapsed().as_secs() < 8);
}
