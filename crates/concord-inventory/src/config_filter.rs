//! Which of a guest's `/config` keys enter the inventory.
//!
//! The snapshot is served by an API with no authentication yet, so this is an
//! allowlist: a key PVE adds later stays out until someone has looked at it.
//! The names are those of the PVE 9.2 schema (`PVE::QemuServer`,
//! `PVE::LXC::Config`), plus the few its GET adds (`digest`, `meta`, `parent`).

use serde_json::{Map, Value};

const PLAIN: &[&str] = &[
    "acpi",
    "affinity",
    "agent",
    "allow-ksm",
    "arch",
    "autostart",
    "balloon",
    "bios",
    "boot",
    "bootdisk",
    "cdrom",
    "citype",
    "ciupgrade",
    "cmode",
    "console",
    "cores",
    "cpu",
    "cpulimit",
    "cpuunits",
    "debug",
    "digest",
    "features",
    "freeze",
    "hostname",
    "hotplug",
    "hugepages",
    "ivshmem",
    "keephugepages",
    "keyboard",
    "kvm",
    "localtime",
    "lock",
    "machine",
    "memory",
    "meta",
    "migrate_downtime",
    "migrate_speed",
    "name",
    "nameserver",
    "numa",
    "onboot",
    "ostype",
    "parent",
    "protection",
    "reboot",
    "rootfs",
    "scsihw",
    "searchdomain",
    "shares",
    "smp",
    "sockets",
    "startdate",
    "startup",
    "swap",
    "tablet",
    "tags",
    "tdf",
    "template",
    "timezone",
    "tty",
    "unprivileged",
    "vcpus",
    "vga",
    "vmgenid",
    "vmstatestorage",
    "watchdog",
];

/// Families followed by an index: `net0`, `scsi3`.
const INDEXED: &[&str] = &[
    "audio", "dev", "efidisk", "hostpci", "ide", "ipconfig", "mp", "net", "numa", "parallel",
    "rng", "sata", "scsi", "serial", "tpmstate", "unused", "usb", "virtio", "virtiofs",
];

/// Known keys kept out. Credentials (`cipassword`, which PVE masks already;
/// `ciuser`, `sshkeys`), what can contain them (environments, command lines,
/// raw lxc.conf, user-supplied snippets) and free text (`description`,
/// `smbios1`'s strings); the rest is of no use to the inventory. Named here only
/// so the omission can be reported by name.
const OMITTED: &[&str] = &[
    "amd-sev",
    "args",
    "cicustom",
    "cipassword",
    "ciuser",
    "description",
    "entrypoint",
    "env",
    "hookscript",
    "intel-tdx",
    "lxc",
    "smbios1",
    "spice_enhancements",
    "sshkeys",
];

/// Stands in for a key whose name is not one of PVE's. Its name is as much
/// guest data as its value, so it is not repeated.
const UNRECOGNISED: &str = "(unrecognised)";

/// Splits a `/config` body into what may be shown and the names of what was
/// left out, sorted.
pub(crate) fn filter(raw: Map<String, Value>) -> (Map<String, Value>, Vec<String>) {
    let mut omitted = Vec::new();
    let mut kept = Map::new();
    for (k, v) in raw {
        // Every schema value is a scalar. A structure under an allowed name is
        // not what was reviewed, as `lxc` (an array of pairs) shows.
        let scalar = matches!(v, Value::String(_) | Value::Number(_) | Value::Bool(_));
        let allowed = is_allowed(&k);
        if allowed && scalar {
            kept.insert(k, v);
        } else if allowed || OMITTED.contains(&k.as_str()) {
            omitted.push(k);
        } else {
            omitted.push(UNRECOGNISED.to_string());
        }
    }
    omitted.sort();
    omitted.dedup();
    (kept, omitted)
}

fn is_allowed(key: &str) -> bool {
    if PLAIN.contains(&key) {
        return true;
    }
    let family = key.trim_end_matches(|c: char| c.is_ascii_digit());
    // PVE's indexes stop at 255; digits without limit could be a number that
    // means something.
    (1..=3).contains(&(key.len() - family.len())) && INDEXED.contains(&family)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn run(v: Value) -> (Map<String, Value>, Vec<String>) {
        match v {
            Value::Object(m) => filter(m),
            _ => unreachable!(),
        }
    }

    #[test]
    fn useful_keys_pass_unchanged() {
        let v = json!({
            "net0": "virtio=02:00:00:00:00:01,bridge=vmbr0", "scsi30": "s:vm-1-disk-0",
            "virtio1": "a", "sata0": "a", "ide2": "a", "mp255": "a", "rootfs": "a",
            "unused0": "a", "cores": 2, "memory": "2048", "hostname": "ct1", "name": "vm1",
            "onboot": 1, "ostype": "debian", "features": "nesting=1", "tags": "a;b",
            "unprivileged": true, "digest": "0",
        });
        let (kept, omitted) = run(v.clone());
        assert_eq!(Value::Object(kept), v);
        assert!(omitted.is_empty());
    }

    #[test]
    fn each_sensitive_key_is_named_but_not_shown() {
        for k in OMITTED {
            let (kept, omitted) = run(json!({ (*k): "hunter2", "cores": 1 }));
            assert_eq!(kept.keys().collect::<Vec<_>>(), ["cores"], "{k}");
            assert_eq!(omitted, [*k]);
        }
        let raw = json!({"lxc": [["lxc.environment", "API_KEY=hunter2"]]});
        assert_eq!(run(raw), (Map::new(), vec!["lxc".to_string()]));
    }

    #[test]
    fn unknown_names_and_odd_shapes_reveal_nothing() {
        let (kept, omitted) = run(json!({
            "hunter2": 1, "API_KEY=hunter2": "x", "net": "x", "net1234567": "x",
            "net0x": "x", "Cores": 1, "": 1, "env0": "x",
            "cores": {"hunter2": 1}, "net1": ["hunter2"], "memory": null,
        }));
        assert!(kept.is_empty(), "{kept:?}");
        assert_eq!(omitted, [UNRECOGNISED, "cores", "memory", "net1"]);
    }

    #[test]
    fn the_lists_do_not_overlap() {
        assert!(OMITTED.iter().all(|k| !is_allowed(k)));
    }
}
