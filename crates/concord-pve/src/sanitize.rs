//! Turns a real PVE response into one that is safe to commit.
//!
//! The aim is to keep everything that makes a fixture useful (field names,
//! types, enum values, number formats, nesting) and replace everything that
//! names the estate. Replacements are stable within one [`Sanitizer`], so a
//! node called `x` is `node1` in the node list, in a UPID and in a guest's
//! `node` field alike.
//!
//! Names are only half of it: [`crate::normalise`] then replaces the values
//! (guest ids, dates, sizes, counters, hardware) that identify a host too.
//! [`Sanitizer::set`] does both.
//!
//! Two layers for names, because neither alone is safe:
//! * rules by key name for the fields known to carry identity (`name`,
//!   `description`, `path`, `sshkeys`, ...), and
//! * a scrub of every other string for things that look like identifiers
//!   whatever field they sit in (IPs, MACs, UUIDs, users, tokens, known names).
//!
//! [`LeakScanner`] is the independent check: it works from patterns, not from
//! the mapping, so it still catches what a rule forgot. The capture tool
//! refuses to write a set it flags, and a test runs it over every committed
//! fixture.

use std::collections::{HashMap, HashSet};

use serde_json::Value;

use crate::capture::Entry;

/// Words that appear as legitimate values in PVE responses and must never be
/// treated as the name of something in the estate, whatever it is called.
const KEEP: &[&str] = &[
    "local",
    "local-lvm",
    "local-zfs",
    "pve",
    "pam",
    "root",
    "current",
    "running",
    "stopped",
    "online",
    "offline",
    "unknown",
    "lxc",
    "qemu",
    "node",
    "storage",
    "pool",
    "none",
    "yes",
    "no",
];

/// Scrubbing placeholders for fields whose value is arbitrary text.
const TEXT: &str = "placeholder text";

/// Placeholder address ranges (RFC 5737). Already-sanitised data stays put on
/// a second pass.
const DOC_NETS: &[[u8; 3]] = &[[192, 0, 2], [198, 51, 100], [203, 0, 113]];

#[derive(Default)]
pub struct Sanitizer {
    /// (original, placeholder) for names learned from the capture, longest
    /// original first so a name that contains another is replaced whole.
    known: Vec<(String, String)>,
    /// category -> original -> placeholder
    maps: HashMap<&'static str, HashMap<String, String>>,
}

#[derive(Clone, Default)]
struct Ctx {
    snapshot: bool,
    tasks: bool,
    vmid: Option<String>,
}

impl Sanitizer {
    pub fn new() -> Self {
        Self::default()
    }

    fn map(&mut self, cat: &'static str, orig: &str, make: impl Fn(usize) -> String) -> String {
        let m = self.maps.entry(cat).or_default();
        if let Some(v) = m.get(orig) {
            return v.clone();
        }
        let v = make(m.len() + 1);
        m.insert(orig.to_string(), v.clone());
        v
    }

    /// Learns the names to replace everywhere from the raw capture. Must run
    /// over the whole capture before any [`Sanitizer::entry`] call, so that a
    /// name first seen in the node list is also replaced inside a task log.
    pub fn learn(&mut self, entries: &[Entry]) {
        // Sorted so numbering does not depend on API ordering quirks.
        let mut nodes = Vec::new();
        let mut storages = Vec::new();
        let mut pools = Vec::new();
        let mut guests: Vec<(String, String)> = Vec::new();
        let mut plugins = Vec::new();
        for e in entries {
            let Ok(v) = &e.result else { continue };
            collect(
                v,
                &e.path,
                &mut nodes,
                &mut storages,
                &mut pools,
                &mut guests,
                &mut plugins,
            );
            // Path segments name things too: `/nodes/{n}/storage/{s}/content`.
            let segs: Vec<String> = e.path.split('/').map(decode).collect();
            for w in segs.windows(2) {
                match w[0].as_str() {
                    "nodes" => nodes.push(w[1].clone()),
                    "storage" if segs.len() > 4 => storages.push(w[1].clone()),
                    "pools" => pools.push(w[1].clone()),
                    _ => {}
                }
            }
        }
        for (cat, list, prefix) in [
            ("node", nodes, "node"),
            ("storage", storages, "storage"),
            ("pool", pools, "pool"),
            ("plugin", plugins, "plugin-"),
        ] {
            let mut list: Vec<String> = list.into_iter().filter(|s| !is_kept(s)).collect();
            list.sort();
            list.dedup();
            for orig in list {
                let p = self.map(cat, &orig, |n| format!("{prefix}{n}"));
                self.known.push((orig, p));
            }
        }
        guests.sort();
        guests.dedup();
        for (name, vmid) in guests {
            if is_kept(&name) {
                continue;
            }
            let p = self.map("guest", &name, |_| format!("guest-{vmid}"));
            self.known.push((name, p));
        }
        self.known
            .sort_by(|a, b| b.0.len().cmp(&a.0.len()).then(a.0.cmp(&b.0)));
        self.known.dedup_by(|a, b| a.0 == b.0);
    }

    /// Sanitises a whole capture: names first, then the values
    /// ([`crate::normalise`]).
    pub fn set(&mut self, entries: &mut [Entry]) {
        self.learn(entries);
        for e in entries.iter_mut() {
            self.entry(e);
        }
        crate::normalise::normalise(entries);
    }

    /// Sanitises an entry in place: path, params and body.
    pub fn entry(&mut self, e: &mut Entry) {
        let segs: Vec<String> = e.path.split('/').map(decode).collect();
        let cleaned: Vec<String> = segs.iter().map(|s| self.string(s)).collect();
        e.path = cleaned
            .iter()
            .filter(|s| !s.is_empty())
            .map(|s| format!("/{}", encode(s)))
            .collect();
        let mut ctx = Ctx::default();
        // `/nodes/{n}/(qemu|lxc)/{vmid}/...` carries the vmid, which names the
        // guest in its own config.
        for w in cleaned.windows(2) {
            if w[0] == "qemu" || w[0] == "lxc" {
                ctx.vmid = Some(w[1].clone());
            }
        }
        ctx.tasks = cleaned.iter().any(|s| s == "tasks");
        ctx.snapshot = cleaned.last().is_some_and(|s| s == "snapshot");
        for (_, v) in e.params.iter_mut() {
            *v = self.string(v);
        }
        match &mut e.result {
            Ok(v) => self.walk(None, &ctx, v),
            Err(b) => {
                b.message = self.string(&b.message);
                if let Some(v) = &mut b.errors {
                    self.walk(None, &ctx, v);
                }
            }
        }
    }

    fn walk(&mut self, key: Option<&str>, ctx: &Ctx, v: &mut Value) {
        match v {
            Value::Object(m) => {
                for (k, child) in m.iter_mut() {
                    self.walk(Some(k), ctx, child);
                }
            }
            Value::Array(a) => {
                for child in a {
                    self.walk(key, ctx, child);
                }
            }
            Value::String(s) => {
                if let Some(k) = key {
                    if let Some(r) = self.by_key(k, s, ctx) {
                        *s = r;
                        return;
                    }
                }
                *s = self.string(s);
            }
            _ => {}
        }
    }

    /// Replacement for fields known to carry identity, or None to fall through
    /// to the general scrub.
    fn by_key(&mut self, key: &str, val: &str, ctx: &Ctx) -> Option<String> {
        if val.is_empty() {
            return None;
        }
        let r = match key {
            "description" | "notes" | "comment" | "title" => TEXT.to_string(),
            "sshkeys" | "ssh-public-keys" => "placeholder-ssh-key".to_string(),
            "cipassword" | "password" | "secret" => "placeholder-secret".to_string(),
            "ciuser" | "username" | "user_name" => "placeholder-user".to_string(),
            "searchdomain" | "domain" => "example.invalid".to_string(),
            "name" | "hostname" if ctx.snapshot => {
                if val == "current" {
                    return None;
                }
                self.map("snapshot", val, |n| format!("snapshot-{n}"))
            }
            "parent" => {
                if val == "current" {
                    return None;
                }
                self.map("snapshot", val, |n| format!("snapshot-{n}"))
            }
            "name" | "hostname" => {
                if is_kept(val) {
                    return None;
                }
                match &ctx.vmid {
                    Some(vmid) => {
                        let vmid = vmid.clone();
                        self.map("guest", val, |_| format!("guest-{vmid}"))
                    }
                    None => self.map("guest", val, |n| format!("guest-name-{n}")),
                }
            }
            "tags" => val
                .split([';', ','])
                .map(|t| {
                    if t.is_empty() {
                        String::new()
                    } else {
                        self.map("tag", t, |n| format!("tag-{n}"))
                    }
                })
                .collect::<Vec<_>>()
                .join(";"),
            // A task's subject: a vmid usually, but a domain for ACME, a unit
            // for service reloads, and so on.
            "id" if ctx.tasks && !val.bytes().all(|b| b.is_ascii_digit()) => {
                self.map("taskid", val, |n| format!("task-id-{n}"))
            }
            "volid" => return self.volid(val),
            // The host's CPU (`cpuinfo.model`), and the local-version suffix a
            // custom kernel carries.
            "model" => "Placeholder CPU".to_string(),
            "release" | "kversion" | "version" if is_kernel_text(val) => stock_kernel(val),
            k if is_disk_key(k) => {
                let (vol, opts) = val
                    .split_once(',')
                    .map_or((val, None), |(v, o)| (v, Some(o)));
                // A bind mount names a host path.
                let vol = if vol.starts_with('/') {
                    self.map("path", vol, |n| format!("/srv/placeholder-{n}"))
                } else {
                    self.volid(vol)?
                };
                match opts {
                    Some(o) => {
                        let o: Vec<String> = o
                            .split(',')
                            .map(|kv| match kv.strip_prefix("mp=") {
                                // Where it appears inside the container.
                                Some(p) => {
                                    let m = self.map("mp", p, |n| format!("/mnt/placeholder-{n}"));
                                    format!("mp={m}")
                                }
                                None => self.string(kv),
                            })
                            .collect();
                        format!("{vol},{}", o.join(","))
                    }
                    None => vol,
                }
            }
            k if matches!(
                k.trim_end_matches(|c: char| c.is_ascii_digit()),
                "usb" | "hostpci" | "serial" | "parallel"
            ) && k.len() > k.trim_end_matches(|c: char| c.is_ascii_digit()).len() =>
            {
                let base = k.trim_end_matches(|c: char| c.is_ascii_digit());
                self.passthrough(base, val)
            }
            // A bridge named for an SDN vnet names the estate's network; the
            // stock `vmbrN` does not.
            k if k.starts_with("net") && val.contains("bridge=") => val
                .split(',')
                .map(|kv| match kv.strip_prefix("bridge=") {
                    Some(b) if !b.starts_with("vmbr") => {
                        let b = self.map("bridge", b, |n| format!("vnet{n}"));
                        format!("bridge={b}")
                    }
                    _ => self.string(kv),
                })
                .collect::<Vec<_>>()
                .join(","),
            "tokenid" => self.map("token", val, |n| format!("token-{n}")),
            "path" | "mountpoint" | "export" | "share" | "datastore" | "monhost" | "server" => {
                self.map("path", val, |n| format!("/srv/placeholder-{n}"))
            }
            "is_mountpoint" if !matches!(val, "yes" | "no" | "0" | "1") => {
                self.map("path", val, |n| format!("/srv/placeholder-{n}"))
            }
            "digest" => self.map("digest", val, |n| format!("{n:040x}")),
            "ssl_fingerprint" | "fingerprint" => self.fingerprint(val),
            _ => return None,
        };
        Some(r)
    }

    /// `storage:content/file`. The storage id is always mapped, whatever the
    /// file is called. Files PVE names itself (disks, vzdump archives) keep
    /// their names, which carry only vmids and dates; anything a person named
    /// (ISOs, templates, imports, hand-made backups) becomes `file-N` with a
    /// known extension, since such names say what the estate runs.
    fn volid(&mut self, val: &str) -> Option<String> {
        let (st, rest) = val.split_once(':')?;
        let st = if is_kept(st) {
            st.to_string()
        } else {
            self.map("storage", st, |n| format!("storage{n}"))
        };
        let (dir, file) = rest.rsplit_once('/').map_or(("", rest), |(d, f)| (d, f));
        let generic = ["vzdump-", "vm-", "base-", "subvol-"]
            .iter()
            .any(|p| file.starts_with(p));
        let name = if generic {
            file.to_string()
        } else {
            let ext = file_suffix(file);
            self.map("file", file, |n| format!("file-{n}{ext}"))
        };
        Some(if dir.is_empty() {
            format!("{st}:{name}")
        } else {
            format!("{st}:{dir}/{name}")
        })
    }

    /// `usbN`, `hostpciN`, `serialN`, `parallelN`: option lists whose `host=`,
    /// `mapping=` or device values name hardware or host paths. The shape
    /// (which options, how many devices) stays.
    fn passthrough(&mut self, base: &str, val: &str) -> String {
        let parts: Vec<String> = val
            .split(',')
            .map(|kv| {
                if let Some(h) = kv.strip_prefix("host=") {
                    return format!("host={}", self.hw_id(base, h));
                }
                if let Some(m) = kv.strip_prefix("mapping=") {
                    let m = self.map("mapping", m, |n| format!("mapping-{n}"));
                    return format!("mapping={m}");
                }
                if base == "hostpci" && !kv.contains('=') && kv.contains(':') {
                    // The leading bare PCI address.
                    return self.hw_id(base, kv);
                }
                if matches!(base, "serial" | "parallel") && kv.starts_with('/') {
                    let p = self.map("devpath", kv, |n| format!("/dev/placeholder-{n}"));
                    return p;
                }
                self.string(kv)
            })
            .collect();
        parts.join(",")
    }

    /// A USB vendor:product id or port path, or a PCI address, as a numbered
    /// placeholder of the same shape.
    fn hw_id(&mut self, base: &str, id: &str) -> String {
        match base {
            "hostpci" => self.map("pci", id, |n| format!("0000:{n:02x}:00.0")),
            _ if id.contains(':') => self.map("usbid", id, |n| format!("1234:{n:04x}")),
            _ => self.map("usbport", id, |n| format!("1-{n}")),
        }
    }

    fn fingerprint(&mut self, orig: &str) -> String {
        self.map("fp", orig, |n| {
            (0..32)
                .map(|i| format!("{:02X}", (n * 16 + i) % 256))
                .collect::<Vec<_>>()
                .join(":")
        })
    }

    /// The general scrub applied to every string that no key rule claimed.
    pub fn string(&mut self, s: &str) -> String {
        if s.contains("ssh-ed25519")
            || s.contains("ssh-rsa")
            || s.contains("ecdsa-sha2")
            || s.contains("ssh-dss")
            || s.contains("sk-ssh")
        {
            return "placeholder-ssh-key".to_string();
        }
        let mut out = self.upid_subject(s);
        let known = self.known.clone();
        for (orig, repl) in &known {
            out = replace_token(&out, orig, repl);
        }
        out = self.users(&out);
        out = self.domains(&out);
        out = self.uuids(&out);
        out = self.hex_colon(&out);
        self.ipv4(&out)
    }

    /// The subject field of a UPID (`UPID:node:pid:pstart:start:type:ID:user:`)
    /// is free text for some task types, so it is mapped like a task `id`.
    fn upid_subject(&mut self, s: &str) -> String {
        let mut f: Vec<String> = s.split(':').map(str::to_string).collect();
        if f.len() == 9
            && f[0] == "UPID"
            && !f[6].is_empty()
            && !f[6].bytes().all(|b| b.is_ascii_digit())
        {
            let id = f[6].clone();
            f[6] = self.map("taskid", &id, |n| format!("task-id-{n}"));
            return f.join(":");
        }
        s.to_string()
    }

    /// `name@realm[!token]` anywhere in a string. `root@pam` alone is generic
    /// and kept; anything else, and any token, is mapped.
    fn users(&mut self, s: &str) -> String {
        let b = s.as_bytes();
        let mut out = String::new();
        let mut i = 0;
        let user_char = |c: u8| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.');
        while i < b.len() {
            if b[i] != b'@' || i == 0 || !user_char(b[i - 1]) {
                let ch_len = utf8_len(b[i]);
                out.push_str(&s[i..i + ch_len]);
                i += ch_len;
                continue;
            }
            // Walk back over the user part already pushed to `out`.
            let mut ustart = out.len();
            while ustart > 0 && user_char(out.as_bytes()[ustart - 1]) {
                ustart -= 1;
            }
            let user = out.split_off(ustart);
            let mut j = i + 1;
            let realm_char = |c: u8| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-');
            while j < b.len() && realm_char(b[j]) {
                j += 1;
            }
            let mut realm = s[i + 1..j].to_string();
            // `user@host.tld` is an email, not a PVE user: keep none of it.
            let mut email = false;
            while j < b.len() && b[j] == b'.' && j + 1 < b.len() && realm_char(b[j + 1]) {
                email = true;
                j += 1;
                while j < b.len() && realm_char(b[j]) {
                    j += 1;
                }
            }
            let mut token = None;
            if !email && j < b.len() && b[j] == b'!' {
                let mut k = j + 1;
                while k < b.len() && realm_char(b[k]) {
                    k += 1;
                }
                if k > j + 1 {
                    token = Some(s[j + 1..k].to_string());
                    j = k;
                }
            }
            if email {
                let u = self.map("email", &user, |n| format!("mail{n}"));
                out.push_str(&format!("{u}@example.invalid"));
            } else {
                if !matches!(realm.as_str(), "pam" | "pve" | "pbs" | "ldap" | "ad") {
                    realm = "pve".to_string();
                }
                // `root` stays root even in token form, so a token UPID names
                // the same user as the task's own `user` field.
                let u = if user == "root"
                    || user.starts_with("user") && user[4..].parse::<u32>().is_ok()
                {
                    user
                } else {
                    self.map("user", &user, |n| format!("user{n}"))
                };
                out.push_str(&format!("{u}@{realm}"));
                if let Some(t) = token {
                    let t = if t.starts_with("token-") {
                        t
                    } else {
                        self.map("token", &t, |n| format!("token-{n}"))
                    };
                    out.push_str(&format!("!{t}"));
                }
            }
            i = j;
        }
        out
    }

    /// Domain names in free text (an ACME failure message names the domain).
    /// Anything dotted that ends in letters and is not a file name or a public
    /// project domain counts.
    fn domains(&mut self, s: &str) -> String {
        const SUFFIX_KEEP: &[&str] = &[
            "iso", "raw", "img", "vma", "zst", "gz", "lzo", "tar", "xz", "bz2", "conf", "tmpl",
            "log", "txt", "json", "pem", "cfg", "sh", "pl", "pm", "service", "so", "py", "cfg",
            "invalid", "pbs", "fidx", "didx", "blob", "lock", "tmp", "bak", "ova", "ovf", "vmdk",
        ];
        const DOMAIN_KEEP: &[&str] =
            &["proxmox.com", "debian.org", "kernel.org", "pve.proxmox.com"];
        let b = s.as_bytes();
        let mut out = String::new();
        let mut last = 0;
        let mut i = 0;
        let run = |c: u8| c.is_ascii_alphanumeric() || c == b'.' || c == b'-';
        while i < b.len() {
            if !run(b[i]) {
                i += 1;
                continue;
            }
            let start = i;
            while i < b.len() && run(b[i]) {
                i += 1;
            }
            let tok = &s[start..i];
            let trimmed = tok.trim_matches(|c| c == '.' || c == '-');
            let off = tok.find(trimmed).unwrap_or(0);
            let labels: Vec<&str> = trimmed.split('.').collect();
            let tld = labels.last().copied().unwrap_or("");
            let lower = trimmed.to_ascii_lowercase();
            if labels.len() >= 2
                && labels.iter().all(|l| !l.is_empty())
                && (2..=24).contains(&tld.len())
                && tld.bytes().all(|c| c.is_ascii_alphabetic())
                // LXC config keys (`lxc.cgroup2.devices.allow`) are dotted too.
                && labels[0] != "lxc"
                // Privilege names in permission errors (`Sys.Modify`).
                && !matches!(
                    labels[0],
                    "Sys" | "VM" | "Datastore" | "Pool" | "SDN" | "Realm" | "Permissions"
                        | "User" | "Group" | "Mapping"
                )
                && !SUFFIX_KEEP.contains(&tld.to_ascii_lowercase().as_str())
                && !DOMAIN_KEEP.iter().any(|d| lower == *d || lower.ends_with(&format!(".{d}")))
            {
                let r = self.map("domain", &lower, |n| format!("host-{n}.example.invalid"));
                out.push_str(&s[last..start + off]);
                out.push_str(&r);
                last = start + off + trimmed.len();
            }
        }
        out.push_str(&s[last..]);
        out
    }

    fn uuids(&mut self, s: &str) -> String {
        let b = s.as_bytes();
        let mut out = String::new();
        let mut i = 0;
        while i < b.len() {
            if i + 36 <= b.len() && is_uuid(&b[i..i + 36]) && uuid_bounded(b, i) {
                let orig = &s[i..i + 36];
                if orig.starts_with(PLACEHOLDER_UUID_PREFIX) {
                    out.push_str(orig);
                } else {
                    let m = self.map("uuid", &orig.to_ascii_lowercase(), |n| {
                        format!("{PLACEHOLDER_UUID_PREFIX}{n:012x}")
                    });
                    out.push_str(&m);
                }
                i += 36;
            } else {
                let l = utf8_len(b[i]);
                out.push_str(&s[i..i + l]);
                i += l;
            }
        }
        out
    }

    /// MACs, SHA-256 fingerprints and IPv6 addresses: runs of hex digits and
    /// colons that stand alone.
    fn hex_colon(&mut self, s: &str) -> String {
        let mut out = String::new();
        let mut last = 0;
        for (start, end) in hex_colon_runs(s) {
            let tok = &s[start..end];
            let groups: Vec<&str> = tok.split(':').collect();
            let all2 = groups.iter().all(|g| g.len() == 2);
            let repl = if groups.len() == 6 && all2 {
                if tok.to_ascii_lowercase().starts_with("02:00:00") {
                    continue;
                }
                Some(self.map("mac", &tok.to_ascii_lowercase(), |n| {
                    format!("02:00:00:00:{:02x}:{:02x}", n / 256, n % 256)
                }))
            } else if groups.len() == 32 && all2 {
                Some(self.fingerprint(tok))
            } else if is_ipv6_shape(tok) {
                if tok.to_ascii_lowercase().starts_with("2001:db8:") {
                    continue;
                }
                Some(self.map("ipv6", &tok.to_ascii_lowercase(), |n| {
                    format!("2001:db8::{n:x}")
                }))
            } else {
                None
            };
            if let Some(r) = repl {
                out.push_str(&s[last..start]);
                out.push_str(&r);
                last = end;
            }
        }
        out.push_str(&s[last..]);
        out
    }

    fn ipv4(&mut self, s: &str) -> String {
        let mut out = String::new();
        let mut last = 0;
        for (start, end, oct) in ipv4_runs(s) {
            if is_generic_ip(oct) {
                continue;
            }
            let orig = &s[start..end];
            let r = self.map("ipv4", orig, |n| {
                let i = n - 1;
                let net = DOC_NETS[(i / 254) % DOC_NETS.len()];
                format!("{}.{}.{}.{}", net[0], net[1], net[2], i % 254 + 1)
            });
            out.push_str(&s[last..start]);
            out.push_str(&r);
            last = end;
        }
        out.push_str(&s[last..]);
        out
    }
}

/// A kernel release or banner, as `/nodes/{n}/status` reports it: `7.0.14-29-pve`,
/// `Linux 7.0.14-29-pve #1 SMP ... PMX 7.0.14-29 (date)`.
fn is_kernel_text(s: &str) -> bool {
    s.ends_with("-pve") || s.contains("-pve ") || s.contains(" PMX ")
}

/// Drops what a custom build adds to a stock kernel string: `-name` before
/// `-pve` in the release and `+name` in the package version.
fn stock_kernel(s: &str) -> String {
    s.split(' ')
        .map(|w| {
            let w = w.split_once('+').map_or(w, |(a, _)| a);
            match w.strip_suffix("-pve") {
                Some(stem) => {
                    let stock: Vec<&str> = stem
                        .split('-')
                        .filter(|p| p.bytes().all(|b| b.is_ascii_digit() || b == b'.'))
                        .collect();
                    format!("{}-pve", stock.join("-"))
                }
                None => w.to_string(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Config keys whose value starts with a volume id: `scsi0`, `ide2`, `mp1`...
fn is_disk_key(k: &str) -> bool {
    let base = k.trim_end_matches(|c: char| c.is_ascii_digit());
    matches!(
        base,
        "ide" | "sata" | "scsi" | "virtio" | "efidisk" | "tpmstate" | "unused" | "mp" | "rootfs"
    )
}

const PLACEHOLDER_UUID_PREFIX: &str = "00000000-0000-4000-8000-";

fn is_kept(s: &str) -> bool {
    s.len() < 3 || KEEP.contains(&s) || s.bytes().all(|b| b.is_ascii_digit())
}

/// The extension chain of a file name that is worth keeping: a known suffix
/// taken from the end, so a version in the middle of the name (`foo-1.2.iso`)
/// does not survive as part of the "extension".
fn file_suffix(file: &str) -> &str {
    const CHAINED: &[&str] = &[".tar", ".vma"];
    const COMPRESSED: &[&str] = &[".gz", ".xz", ".zst", ".lzo", ".bz2"];
    const SINGLE: &[&str] = &[
        ".iso", ".img", ".qcow2", ".raw", ".vmdk", ".tar", ".vma", ".ova", ".ovf",
    ];
    let lower = file.to_ascii_lowercase();
    for c in COMPRESSED {
        if let Some(stem) = lower.strip_suffix(c) {
            if let Some(b) = CHAINED.iter().find(|b| stem.ends_with(**b)) {
                return &file[file.len() - b.len() - c.len()..];
            }
        }
    }
    SINGLE
        .iter()
        .find(|s| lower.ends_with(**s))
        .map_or("", |s| &file[file.len() - s.len()..])
}

fn utf8_len(first: u8) -> usize {
    match first {
        0..=0x7f => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        _ => 4,
    }
}

pub(crate) fn decode(s: &str) -> String {
    percent_encoding::percent_decode_str(s)
        .decode_utf8_lossy()
        .into_owned()
}

pub(crate) fn encode(s: &str) -> String {
    // Same set `api_path` uses; a single segment cannot fail its checks here
    // because sanitised segments are never empty or dots.
    crate::api_path(&[s]).map_or_else(|_| s.to_string(), |p| p[1..].to_string())
}

fn collect(
    v: &Value,
    path: &str,
    nodes: &mut Vec<String>,
    storages: &mut Vec<String>,
    pools: &mut Vec<String>,
    guests: &mut Vec<(String, String)>,
    plugins: &mut Vec<String>,
) {
    match v {
        Value::Object(m) => {
            let vmid = m.get("vmid").map(|v| match v {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            });
            for (k, c) in m {
                if let Value::String(s) = c {
                    // A storage can be named only by a volume id (an unused
                    // disk on a storage that is no longer configured).
                    if k == "volid" || is_disk_key(k) {
                        if let Some(st) = volid_storage(s) {
                            storages.push(st.to_string());
                        }
                    }
                    match k.as_str() {
                        "node" => nodes.push(s.clone()),
                        "storage" => storages.push(s.clone()),
                        "poolid" | "pool" => pools.push(s.clone()),
                        "plugin" => plugins.push(s.clone()),
                        "name" | "hostname" => {
                            if let Some(id) = &vmid {
                                guests.push((s.clone(), id.clone()));
                            } else if let Some(id) = vmid_in_path(path) {
                                guests.push((s.clone(), id));
                            }
                        }
                        "nodes" => nodes.extend(s.split(',').map(str::to_string)),
                        _ => {}
                    }
                }
                collect(c, path, nodes, storages, pools, guests, plugins);
            }
        }
        Value::Array(a) => {
            for c in a {
                collect(c, path, nodes, storages, pools, guests, plugins);
            }
        }
        Value::String(s) => plugins.extend(acme_plugins(s)),
        _ => {}
    }
}

/// The storage id of a volume id or disk-key value (`st:vol,opts`), if the
/// value has that shape. Bind mounts (`/path`) and `none` have no storage.
fn volid_storage(val: &str) -> Option<&str> {
    let vol = val.split(',').next()?;
    let (st, _) = vol.split_once(':')?;
    (!st.is_empty() && !st.starts_with('/') && !st.contains(' ')).then_some(st)
}

/// ACME DNS plugin ids named in a string: `plugin=<id>` in a domain option
/// and the `proxmox-acme setup <id> <domain>` command in a task's log. The id
/// names the DNS provider, so it is estate data.
fn acme_plugins(s: &str) -> Vec<String> {
    let mut v = Vec::new();
    if let Some((_, rest)) = s.split_once("proxmox-acme setup ") {
        if let Some(id) = rest.split_whitespace().next() {
            v.push(id.to_string());
        }
    }
    for part in s.split(',') {
        if let Some(id) = part.trim().strip_prefix("plugin=") {
            v.push(id.to_string());
        }
    }
    v
}

fn vmid_in_path(path: &str) -> Option<String> {
    let segs: Vec<&str> = path.split('/').collect();
    segs.windows(2)
        .find(|w| w[0] == "qemu" || w[0] == "lxc")
        .map(|w| w[1].to_string())
        .filter(|id| id.bytes().all(|b| b.is_ascii_digit()))
}

/// Replaces `needle` where it stands as a whole token: not flanked by letters
/// or digits, so a guest called `foo` does not rewrite `food`.
fn replace_token(hay: &str, needle: &str, repl: &str) -> String {
    if needle.is_empty() {
        return hay.to_string();
    }
    let hb = hay.as_bytes();
    let word = |c: u8| c.is_ascii_alphanumeric();
    let mut out = String::new();
    let mut i = 0;
    while i < hay.len() {
        if hay[i..].starts_with(needle) {
            let before_ok = i == 0 || !word(hb[i - 1]);
            let end = i + needle.len();
            let after_ok = end >= hb.len() || !word(hb[end]);
            if before_ok && after_ok {
                out.push_str(repl);
                i = end;
                continue;
            }
        }
        let l = utf8_len(hb[i]);
        out.push_str(&hay[i..i + l]);
        i += l;
    }
    out
}

fn is_uuid(b: &[u8]) -> bool {
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_hexdigit(),
        })
}

fn uuid_bounded(b: &[u8], i: usize) -> bool {
    let word = |c: u8| c.is_ascii_alphanumeric();
    (i == 0 || !word(b[i - 1])) && (i + 36 >= b.len() || !word(b[i + 36]))
}

/// Maximal runs of hex digits and colons with no letter or digit touching
/// either end, trimmed of stray leading and trailing colons that belong to
/// the surrounding text (`ip=:`).
fn hex_colon_runs(s: &str) -> Vec<(usize, usize)> {
    let b = s.as_bytes();
    let mut v = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_hexdigit() || b[i] == b':' {
            let start = i;
            while i < b.len() && (b[i].is_ascii_hexdigit() || b[i] == b':') {
                i += 1;
            }
            let (mut st, mut en) = (start, i);
            // A single colon edge is punctuation, a doubled one is `::`.
            if b[st] == b':' && !(st + 1 < en && b[st + 1] == b':') {
                st += 1;
            }
            if en > st && b[en - 1] == b':' && !(en >= 2 && b[en - 2] == b':') {
                en -= 1;
            }
            let word = |c: u8| c.is_ascii_alphanumeric();
            let left_ok = st == 0 || !word(b[st - 1]);
            let right_ok = en >= b.len() || !word(b[en]);
            if en > st && left_ok && right_ok && s[st..en].contains(':') {
                v.push((st, en));
            }
        } else {
            i += 1;
        }
    }
    v
}

fn is_ipv6_shape(tok: &str) -> bool {
    let groups: Vec<&str> = tok.split(':').collect();
    let ok_groups = groups.iter().all(|g| g.len() <= 4);
    ok_groups && (tok.contains("::") || groups.len() == 8) && tok.len() >= 3
}

/// Dotted-quad runs, with their parsed octets. A run is a maximal stretch of
/// digits and dots, so `9.2.21` and `1.2.3.4.5` are not addresses.
fn ipv4_runs(s: &str) -> Vec<(usize, usize, [u8; 4])> {
    let b = s.as_bytes();
    let mut v = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_digit() {
            let start = i;
            while i < b.len() && (b[i].is_ascii_digit() || b[i] == b'.') {
                i += 1;
            }
            let mut end = i;
            while end > start && b[end - 1] == b'.' {
                end -= 1;
            }
            let word = |c: u8| c.is_ascii_alphanumeric();
            if start > 0 && word(b[start - 1]) && !b[start - 1].is_ascii_digit() {
                // `v1.2.3.4`: part of a name, not an address.
                continue;
            }
            let parts: Vec<&str> = s[start..end].split('.').collect();
            if parts.len() == 4 {
                let oct: Option<Vec<u8>> = parts
                    .iter()
                    .map(|p| {
                        if p.is_empty() || p.len() > 3 {
                            None
                        } else {
                            p.parse::<u8>().ok()
                        }
                    })
                    .collect();
                if let Some(o) = oct {
                    v.push((start, end, [o[0], o[1], o[2], o[3]]));
                }
            }
        } else {
            i += 1;
        }
    }
    v
}

/// Addresses that carry no information about the estate.
fn is_generic_ip(o: [u8; 4]) -> bool {
    o[0] == 0 || o[0] == 127 || o[0] == 255 || DOC_NETS.iter().any(|n| n[..] == o[..3])
}

/// Generic patterns that must never appear in a committed fixture:
/// case-insensitive substrings. No name of a real estate belongs here (a guard
/// against leaking names must not commit them); see [`ESTATE_DIGESTS_ENV`].
const DENY: &[&str] = &[
    "192.168.",
    "bc:24:11",
    "pveapitoken",
    "ssh-ed25519",
    "ssh-rsa",
    "-----begin",
];

/// Names the file with the local estate's digests: one SHA-256 (lowercase hex)
/// of a lowercase name per line, `#` comments allowed. The file is private and
/// stays out of the repository, because short names are trivially recovered
/// from their digests. Unset, only the generic patterns apply.
pub const ESTATE_DIGESTS_ENV: &str = "CONCORD_ESTATE_DIGESTS";

/// The longest joined name a digest is computed for; uuids have five parts.
const MAX_NAME_PARTS: usize = 8;

fn digest_hex(word: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(word.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// One thing in a text that looks like it names a real estate.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Leak {
    /// Byte offset of the match in the scanned text.
    pub offset: usize,
    /// Which rule fired. Never contains the matched text, so a report cannot
    /// itself spread the leak.
    pub rule: &'static str,
    /// What matched, lowercased, for comparing with an allowlist. Reports
    /// leave it out.
    pub token: String,
}

/// The scanner behind the fixture checks and the repository scan: generic
/// patterns, plus the local estate's names when a digest list is given.
#[derive(Clone, Debug, Default)]
pub struct LeakScanner {
    digests: HashSet<String>,
}

impl LeakScanner {
    /// Generic patterns only.
    pub fn patterns_only() -> Self {
        Self::default()
    }

    /// Loads the list [`ESTATE_DIGESTS_ENV`] names. Set but unusable is an
    /// error: falling back to patterns would pass what the caller meant to
    /// catch.
    pub fn from_env() -> Result<Self, String> {
        Self::from_setting(std::env::var_os(ESTATE_DIGESTS_ENV).as_deref())
    }

    fn from_setting(path: Option<&std::ffi::OsStr>) -> Result<Self, String> {
        let Some(path) = path else {
            return Ok(Self::patterns_only());
        };
        let text = std::fs::read_to_string(path).map_err(|e| {
            format!(
                "{ESTATE_DIGESTS_ENV}: cannot read {}: {e}",
                path.to_string_lossy()
            )
        })?;
        Self::parse(&text).map_err(|e| format!("{ESTATE_DIGESTS_ENV}: {e}"))
    }

    fn parse(text: &str) -> Result<Self, String> {
        let mut digests = HashSet::new();
        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line.len() != 64 || !line.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
                return Err(format!("line {} is not a lowercase SHA-256", n + 1));
            }
            digests.insert(line.to_string());
        }
        if digests.is_empty() {
            return Err("the list holds no digests".to_string());
        }
        Ok(LeakScanner { digests })
    }

    /// The rules that fired, for fixtures, where nothing is allowed.
    pub fn find_leaks(&self, text: &str) -> Vec<String> {
        let mut hits: Vec<String> = self
            .scan(text)
            .into_iter()
            .map(|l| l.rule.to_string())
            .collect();
        hits.sort();
        hits.dedup();
        hits
    }

    /// Every match in `text`.
    pub fn scan(&self, text: &str) -> Vec<Leak> {
        let mut hits = Vec::new();
        let mut hit = |offset: usize, rule: &'static str, token: &str| {
            hits.push(Leak {
                offset,
                rule,
                token: token.to_ascii_lowercase(),
            });
        };
        // ASCII lowercasing keeps every byte offset.
        let lower = text.to_ascii_lowercase();
        for p in DENY {
            for (i, m) in lower.match_indices(p) {
                hit(i, "denied pattern", m);
            }
        }
        self.names(&lower, &mut hit);
        tokens_and_users(text, &mut hit);
        // The same in percent-encoded text (API paths). Offsets there are not
        // the file's, so the start of the text is reported.
        if text.contains('%') {
            let decoded = decode(text);
            if decoded != text {
                self.names(&decoded.to_ascii_lowercase(), &mut |_, r, t: &str| {
                    hit(0, r, t)
                });
                tokens_and_users(&decoded, &mut |_, r, t: &str| hit(0, r, t));
            }
        }
        for (st, en, o) in ipv4_runs(text) {
            if !is_generic_ip(o) {
                hit(st, "non-placeholder IPv4 address", &text[st..en]);
            }
        }
        for (st, en) in hex_colon_runs(text) {
            let tok = &text[st..en];
            let groups: Vec<&str> = tok.split(':').collect();
            let all2 = groups.iter().all(|g| g.len() == 2);
            if groups.len() == 6 && all2 && !tok.to_ascii_lowercase().starts_with("02:00:00") {
                hit(st, "non-placeholder MAC address", tok);
            } else if groups.len() == 32 && all2 {
                // Placeholders only if produced by `fingerprint`.
                if !is_placeholder_fingerprint(&groups) {
                    hit(st, "non-placeholder SHA-256 fingerprint", tok);
                }
            } else if is_ipv6_shape(tok) && !tok.to_ascii_lowercase().starts_with("2001:db8:") {
                hit(st, "non-placeholder IPv6 address", tok);
            }
        }
        let b = text.as_bytes();
        let mut i = 0;
        while i + 36 <= b.len() {
            if is_uuid(&b[i..i + 36]) && uuid_bounded(b, i) {
                let tok = String::from_utf8_lossy(&b[i..i + 36]);
                if !tok.starts_with(PLACEHOLDER_UUID_PREFIX) {
                    hit(i, "UUID-shaped value", &tok);
                }
                i += 36;
            } else {
                i += 1;
            }
        }
        hits.sort();
        hits.dedup();
        hits
    }

    /// Estate names, by digest: every word, and every run of words joined by
    /// underscores, dashes or dots, so a name that contains them can be listed.
    fn names(&self, lower: &str, hit: &mut impl FnMut(usize, &'static str, &str)) {
        if self.digests.is_empty() {
            return;
        }
        let known = |w: &str| w.len() >= 4 && self.digests.contains(&digest_hex(w));
        let mut at = 0;
        for piece in lower
            .split_inclusive(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')))
        {
            let start = at;
            at += piece.len();
            let run = piece
                .trim_end_matches(|c: char| {
                    !(c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
                })
                .trim_matches('.');
            // Every stretch of whole parts, so a name joined to something else by
            // a separator (`node_NAME`, `NAME-2`) is still seen. All of them, so
            // that one allowed name does not hide another beside it.
            let sep = |c: char| matches!(c, '_' | '-' | '.');
            let mut starts = vec![0];
            starts.extend(run.match_indices(sep).map(|(i, _)| i + 1));
            let mut ends: Vec<usize> = run.match_indices(sep).map(|(i, _)| i).collect();
            ends.push(run.len());
            for (n, a) in starts.iter().enumerate() {
                for b in ends.iter().skip(n).take(MAX_NAME_PARTS) {
                    let w = &run[*a..*b];
                    if known(w) {
                        hit(start, "known estate name", w);
                    }
                }
            }
        }
    }
}

/// `user@realm` and `user@realm!token` forms other than the placeholders
/// (`root`, `userN`, `token-N`).
fn tokens_and_users(text: &str, hit: &mut impl FnMut(usize, &'static str, &str)) {
    let word = |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.');
    let numbered = |s: &str, prefix: &str| {
        s.strip_prefix(prefix)
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
    };
    for (i, _) in text.match_indices('@') {
        let ustart = text[..i].rfind(|c: char| !word(c)).map_or(0, |p| {
            p + text[p..].chars().next().map_or(1, char::len_utf8)
        });
        let user = &text[ustart..i];
        let rest = &text[i + 1..];
        let rend = rest.find(|c: char| !word(c)).unwrap_or(rest.len());
        let realm = &rest[..rend];
        if user.is_empty() || !matches!(realm, "pam" | "pve" | "pbs" | "ldap" | "ad") {
            continue;
        }
        if user != "root" && !numbered(user, "user") {
            hit(
                ustart,
                "user that is not a placeholder",
                &text[ustart..i + 1 + rend],
            );
        }
        if let Some(t) = rest[rend..].strip_prefix('!') {
            let tend = t
                .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '-')))
                .unwrap_or(t.len());
            if !numbered(&t[..tend], "token-") {
                let end = i + 1 + rend + 1 + tend;
                hit(
                    ustart,
                    "API token id that is not `token-N`",
                    &text[ustart..end],
                );
            }
        }
    }
}

/// The fingerprints [`Sanitizer`] emits are 32 consecutive byte values.
fn is_placeholder_fingerprint(groups: &[&str]) -> bool {
    let vals: Option<Vec<u8>> = groups
        .iter()
        .map(|g| u8::from_str_radix(g, 16).ok())
        .collect();
    vals.is_some_and(|v| v.windows(2).all(|w| w[1] == w[0].wrapping_add(1)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn find_leaks(text: &str) -> Vec<String> {
        LeakScanner::patterns_only().find_leaks(text)
    }

    /// A scanner that knows made-up names.
    fn knowing(names: &[&str]) -> LeakScanner {
        let list: Vec<String> = names.iter().map(|n| digest_hex(n)).collect();
        LeakScanner::parse(&list.join("\n")).unwrap()
    }

    fn entry(path: &str, v: Value) -> Entry {
        Entry {
            path: path.to_string(),
            params: vec![],
            result: Ok(v),
        }
    }

    #[test]
    fn mapping_is_stable_across_fields_and_paths() {
        let mut es = vec![
            entry(
                "/nodes",
                json!([{"node":"alpha-host","id":"node/alpha-host","ssl_fingerprint":
                "9C:41:E7:0D:B2:6A:F5:38:1E:C9:74:A0:2B:D6:83:5F:E1:17:CA:4D:90:3B:68:F2:A5:0E:D7:59:C3:86:1B:42"}]),
            ),
            entry(
                "/nodes/alpha-host/tasks/UPID%3Aalpha-host%3A00000001%3A00000002%3A00000003%3Aqmstart%3A100%3Aroot%40pam%21tok%3A/status",
                json!({"upid":"UPID:alpha-host:00000001:00000002:00000003:qmstart:100:root@pam!tok:","node":"alpha-host"}),
            ),
        ];
        let mut s = Sanitizer::new();
        s.learn(&es);
        for e in &mut es {
            s.entry(e);
        }
        let n = es[0].result.as_ref().unwrap();
        assert_eq!(n[0]["node"], "node1");
        assert_eq!(n[0]["id"], "node/node1");
        assert!(es[1].path.starts_with("/nodes/node1/tasks/UPID%3Anode1%3A"));
        assert!(
            es[1].path.contains("root%40pam%21token-1"),
            "{}",
            es[1].path
        );
        let d = es[1].result.as_ref().unwrap();
        assert_eq!(
            d["upid"],
            "UPID:node1:00000001:00000002:00000003:qmstart:100:root@pam!token-1:"
        );
        assert!(find_leaks(&es[0].result.clone().unwrap().to_string()).is_empty());
    }

    #[test]
    fn identifiers_are_replaced_whatever_field_they_sit_in() {
        let mut s = Sanitizer::new();
        let mut e = entry(
            "/nodes/x/qemu/100/config",
            json!({
                "name": "secretbox",
                "description": "my private box",
                "net0": "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,ip=203.0.114.9/24",
                "ipconfig0": "ip=172.16.4.5/24,gw=172.16.4.1,ip6=fe80::1234:5678",
                "smbios1": "uuid=0a1b2c3d-1111-2222-3333-444455556666,base64=1",
                "sshkeys": "ssh-ed25519%20AAAAC3Nz%20me%40example.org",
                "tags": "alpha;beta",
                "vmid": 100,
                "memory": 2048,
                "digest": "0123456789abcdef0123456789abcdef01234567"
            }),
        );
        s.learn(std::slice::from_ref(&e));
        s.entry(&mut e);
        let v = e.result.unwrap();
        assert_eq!(v["name"], "guest-100");
        assert_eq!(v["vmid"], 100);
        assert_eq!(v["memory"], 2048);
        assert_eq!(v["tags"], "tag-1;tag-2");
        assert_eq!(
            v["net0"],
            "virtio=02:00:00:00:00:01,bridge=vmbr0,ip=192.0.2.3/24"
        );
        assert_eq!(
            v["ipconfig0"],
            "ip=192.0.2.1/24,gw=192.0.2.2,ip6=2001:db8::1"
        );
        assert_eq!(
            v["smbios1"],
            "uuid=00000000-0000-4000-8000-000000000001,base64=1"
        );
        let text = v.to_string();
        assert!(find_leaks(&text).is_empty(), "{text}");
        assert!(!text.contains("secretbox") && !text.contains("private"));
    }

    #[test]
    fn sanitising_twice_changes_nothing() {
        let mut e = entry(
            "/nodes/x/lxc/101/config",
            json!({"hostname":"foo-bar","net0":"name=eth0,hwaddr=BC:24:11:00:00:01,ip=10.20.0.5/24"}),
        );
        let mut s = Sanitizer::new();
        s.learn(std::slice::from_ref(&e));
        s.entry(&mut e);
        let once = e.result.clone();
        let mut s2 = Sanitizer::new();
        s2.learn(std::slice::from_ref(&e));
        s2.entry(&mut e);
        assert_eq!(e.result, once);
    }

    #[test]
    fn leak_scan_flags_each_pattern_class() {
        for bad in [
            "192.168.1.5",
            "192.168.1.x",
            "10.20.30.40",
            "100.64.1.2",
            "bc:24:11:aa:bb:cc",
            "someone@pve",
            "someone%40pve",
            "root@pam!tok",
            "root%40pam%21tok",
            "PVEAPIToken=x",
            "12345678-1234-1234-1234-123456789abc",
            "fe80::1",
        ] {
            assert!(!find_leaks(bad).is_empty(), "missed {bad}");
        }
        for ok in [
            "192.0.2.4",
            "02:00:00:00:00:01",
            "00000000-0000-4000-8000-000000000001",
            "UPID:node1:00002F9D:000DC5EA:57500527:vzcreate:602:root@pam:",
            "UPID:node1:00002F9D:000DC5EA:57500527:vzcreate:602:root@pam!token-12:",
            "9.2.21",
            "user1@pve",
            "2001:db8::1",
        ] {
            assert!(find_leaks(ok).is_empty(), "false hit on {ok}");
        }
    }

    #[test]
    fn estate_names_are_matched_by_digest_only() {
        let s = knowing(&["examplehost"]);
        assert!(!s.find_leaks("x http://ExampleHost:8006 y").is_empty());
        assert!(!s.find_leaks("a.examplehost.b").is_empty());
        assert!(!s.find_leaks("/nodes/a%2Fexamplehost%3A1").is_empty());
        assert!(s.find_leaks("examplehosts and example").is_empty());
        assert!(s.find_leaks("example host").is_empty());
        assert!(find_leaks("examplehost").is_empty());
    }

    #[test]
    fn underscore_and_dotted_names_are_matched() {
        let s = knowing(&["made_up_store", "made.up.name"]);
        assert!(!s.find_leaks("rootfs: Made_Up_Store:vm-1-disk-0").is_empty());
        assert!(!s.find_leaks("host made.up.name:8006").is_empty());
        assert!(s.find_leaks("made up store, made_up").is_empty());
        assert!(!s.find_leaks("x_made_up_store-2").is_empty());
        let s = knowing(&["examplehost", "othername"]);
        for text in [
            "node_examplehost",
            "examplehost-2",
            "pre-examplehost_x.y",
            "a%5Fexamplehost",
        ] {
            assert_eq!(s.find_leaks(text).len(), 1, "{text}");
        }
        // An allowed name must not hide the one joined to it.
        assert_eq!(s.scan("examplehost-othername").len(), 2);
    }

    #[test]
    fn a_leak_reports_where_and_which_rule_but_not_what() {
        let text = "line one\nat examplehost now";
        let l = knowing(&["examplehost"]).scan(text);
        assert_eq!(l.len(), 1);
        assert_eq!(&text[l[0].offset..][..11], "examplehost");
        assert!(!l[0].rule.contains("examplehost"));
        // Offsets hold after multi-byte characters.
        let text = "\u{2014}\u{e9} 198.18.0.1";
        let l = LeakScanner::patterns_only().scan(text);
        assert_eq!(&text[l[0].offset..], "198.18.0.1");
    }

    #[test]
    fn digest_list_setting_fails_closed() {
        let dir = std::env::temp_dir().join(format!("concord-digests-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("list");
        let load = || LeakScanner::from_setting(Some(p.as_os_str()));
        // Unset: patterns only.
        assert!(LeakScanner::from_setting(None).unwrap().digests.is_empty());
        // Set to nothing, or to a file that is not there.
        assert!(LeakScanner::from_setting(Some(std::ffi::OsStr::new(""))).is_err());
        assert!(load().is_err());
        for bad in ["", "# only a comment\n\n", "abc", &"A".repeat(64)] {
            std::fs::write(&p, bad).unwrap();
            assert!(load().is_err(), "{bad:?}");
        }
        std::fs::write(&p, format!("# c\n{}\n", digest_hex("examplehost"))).unwrap();
        assert!(!load().unwrap().find_leaks("examplehost").is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn storage_only_in_an_unused_disk_is_mapped() {
        let mut e = entry(
            "/nodes/x/lxc/100/config",
            json!({
                "rootfs": "local-lvm:vm-100-disk-0,size=8G",
                "unused0": "gone-storage:vm-100-disk-1",
                "mp0": "other-store:100/subvol-100-disk-2.raw,mp=/data",
            }),
        );
        let mut s = Sanitizer::new();
        s.learn(std::slice::from_ref(&e));
        s.entry(&mut e);
        let v = e.result.unwrap();
        assert_eq!(v["rootfs"], "local-lvm:vm-100-disk-0,size=8G");
        assert_eq!(v["unused0"], "storage1:vm-100-disk-1");
        assert_eq!(
            v["mp0"],
            "storage2:100/subvol-100-disk-2.raw,mp=/mnt/placeholder-1"
        );
        let text = v.to_string();
        assert!(
            !text.contains("gone") && !text.contains("other-store"),
            "{text}"
        );
    }

    #[test]
    fn acme_plugin_id_is_mapped_in_task_text() {
        let log = "command 'setpriv --reuid nobody -- /bin/bash /usr/share/proxmox-acme/proxmox-acme setup myprovider box.example.org' failed";
        let mut e = entry(
            "/nodes/x/tasks/UPID%3Ax%3A1%3A2%3A3%3Aacmerenew%3A%3Aroot%40pam%3A/status",
            json!({"exitstatus": log, "id": "myprovider", "upid": "UPID:x:1:2:3:acmerenew:myprovider:root@pam:"}),
        );
        let mut s = Sanitizer::new();
        s.learn(std::slice::from_ref(&e));
        s.entry(&mut e);
        let text = e.result.unwrap().to_string() + &e.path;
        assert!(
            !text.contains("myprovider") && !text.contains("example.org"),
            "{text}"
        );
        assert!(
            text.contains("setup plugin-1 host-1.example.invalid"),
            "{text}"
        );
    }

    #[test]
    fn sdn_bridge_names_are_mapped_but_vmbr_is_kept() {
        let mut e = entry(
            "/nodes/x/qemu/100/config",
            json!({"net0": "virtio=AA:BB:CC:DD:EE:FF,bridge=mynet,tag=5", "net1": "virtio=AA:BB:CC:DD:EE:00,bridge=vmbr0"}),
        );
        let mut s = Sanitizer::new();
        s.learn(std::slice::from_ref(&e));
        s.entry(&mut e);
        let v = e.result.unwrap();
        assert_eq!(v["net0"], "virtio=02:00:00:00:00:01,bridge=vnet1,tag=5");
        assert_eq!(v["net1"], "virtio=02:00:00:00:00:02,bridge=vmbr0");
    }

    #[test]
    fn passthrough_devices_keep_shape_and_lose_ids() {
        let mut e = entry(
            "/nodes/x/qemu/100/config",
            json!({
                "usb0": "host=0abc:0def,usb3=1",
                "usb1": "host=1-2.3",
                "hostpci0": "0000:01:00.0,pcie=1",
                "hostpci1": "mapping=gpu-secret,pcie=1",
                "serial0": "/dev/serial/by-id/usb-secret",
            }),
        );
        let mut s = Sanitizer::new();
        s.learn(std::slice::from_ref(&e));
        s.entry(&mut e);
        let v = e.result.unwrap();
        assert_eq!(v["usb0"], "host=1234:0001,usb3=1");
        assert_eq!(v["usb1"], "host=1-1");
        assert_eq!(v["hostpci0"], "0000:01:00.0,pcie=1");
        assert_eq!(v["hostpci1"], "mapping=mapping-1,pcie=1");
        assert_eq!(v["serial0"], "/dev/placeholder-1");
    }

    #[test]
    fn cpu_model_and_custom_kernel_names_are_dropped() {
        let mut e = entry(
            "/nodes/x/status",
            json!({
                "cpuinfo": {"model": "Some CPU 9000", "cores": 4},
                "current-kernel": {"release": "7.0.14-29-mykernel-pve",
                    "version": "#1 SMP PREEMPT_DYNAMIC PMX 7.0.14-29+mykernel-1 (2026-01-01T00:00Z)"},
                "kversion": "Linux 7.0.14-29-mykernel-pve #1 SMP",
            }),
        );
        let mut s = Sanitizer::new();
        s.learn(std::slice::from_ref(&e));
        s.entry(&mut e);
        let v = e.result.unwrap();
        assert_eq!(v["cpuinfo"]["model"], "Placeholder CPU");
        assert_eq!(v["current-kernel"]["release"], "7.0.14-29-pve");
        assert_eq!(
            v["current-kernel"]["version"],
            "#1 SMP PREEMPT_DYNAMIC PMX 7.0.14-29 (2026-01-01T00:00Z)"
        );
        assert_eq!(v["kversion"], "Linux 7.0.14-29-pve #1 SMP");
    }

    #[test]
    fn file_placeholders_keep_only_a_known_suffix_chain() {
        assert_eq!(file_suffix("foo-1.1.271.iso"), ".iso");
        assert_eq!(file_suffix("pkg-3.1-2_amd64.tar.zst"), ".tar.zst");
        assert_eq!(file_suffix("backup-1.2.vma.gz"), ".vma.gz");
        assert_eq!(file_suffix("Thing.ISO"), ".ISO");
        assert_eq!(file_suffix("v1.2.3"), "");
        assert_eq!(file_suffix("noext"), "");
    }

    #[test]
    fn real_root_token_upid_keeps_root() {
        let mut e = entry(
            "/nodes/x/tasks",
            json!([{"user": "root@pam", "upid": "UPID:x:1:2:3:qmstart:100:root@pam!realtok:"}]),
        );
        let mut s = Sanitizer::new();
        s.learn(std::slice::from_ref(&e));
        s.entry(&mut e);
        let v = e.result.unwrap();
        assert_eq!(v[0]["user"], "root@pam");
        assert_eq!(v[0]["upid"], "UPID:x:1:2:3:qmstart:100:root@pam!token-1:");
    }
}
