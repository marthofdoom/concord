//! The config schema: which keys exist, what each holds, and what becomes of it.

/// The type of a plain key's value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Scalar {
    Bool,
    Int,
    Number,
    /// One line.
    Line,
    /// Any text, newlines included (`description`).
    Text,
    /// `NAME=value` entries separated by NUL.
    Env,
}

/// Plain keys that are carried. Enumerations (`arch`, `ostype`, `cmode`) are
/// lines: a value PVE adds later is carried as it is.
pub(crate) const PLAIN: &[(&str, Scalar)] = &[
    ("arch", Scalar::Line),
    ("cmode", Scalar::Line),
    ("console", Scalar::Bool),
    ("cores", Scalar::Int),
    ("cpulimit", Scalar::Number),
    ("cpuunits", Scalar::Int),
    ("debug", Scalar::Bool),
    ("description", Scalar::Text),
    ("entrypoint", Scalar::Line),
    ("env", Scalar::Env),
    ("hookscript", Scalar::Line),
    ("hostname", Scalar::Line),
    ("memory", Scalar::Int),
    ("nameserver", Scalar::Line),
    ("onboot", Scalar::Bool),
    ("ostype", Scalar::Line),
    ("protection", Scalar::Bool),
    ("searchdomain", Scalar::Line),
    ("startup", Scalar::Line),
    ("swap", Scalar::Int),
    ("tags", Scalar::Line),
    ("template", Scalar::Bool),
    ("timezone", Scalar::Line),
    ("tty", Scalar::Int),
    ("unprivileged", Scalar::Bool),
];

/// What becomes of a key that is not carried.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotCarried {
    /// Readable on the layout, but not a parameter.
    Exposed,
    /// Its presence refuses the config.
    Refused,
}

/// A key that is deliberately not carried, and why.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotCarriedKey {
    pub key: &'static str,
    pub fate: NotCarried,
    pub reason: &'static str,
}

pub const NOT_CARRIED: &[NotCarriedKey] = &[
    NotCarriedKey {
        key: "digest",
        fate: NotCarried::Exposed,
        reason: "PVE's checksum of this version of the config; the new one has its own",
    },
    NotCarriedKey {
        key: "parent",
        fate: NotCarried::Exposed,
        reason: "names the latest snapshot; PVE sets it, and it is not a parameter",
    },
    NotCarriedKey {
        key: "lock",
        fate: NotCarried::Refused,
        reason: "another operation owns the container, so the config may be in flux",
    },
    NotCarriedKey {
        key: "snaptime",
        fate: NotCarried::Refused,
        reason: "only a snapshot's config has it",
    },
    NotCarriedKey {
        key: "pending",
        fate: NotCarried::Refused,
        reason: "PVE returns pending changes separately",
    },
    NotCarriedKey {
        key: "snapshots",
        fate: NotCarried::Refused,
        reason: "PVE removes snapshot sections from this response",
    },
];

pub(crate) const REQUIRED: &[&str] = &["arch", "digest", "ostype", "rootfs"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Indexed {
    Mp,
    Net,
    Dev,
    Unused,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Key {
    Plain(Scalar),
    Features,
    Rootfs,
    Indexed(Indexed, u16),
    Lxc,
    NotCarried,
    Unknown,
}

pub(crate) const INDEXED: &[(&str, Indexed, u16)] = &[
    ("mp", Indexed::Mp, 256),
    ("net", Indexed::Net, 32),
    ("dev", Indexed::Dev, 256),
    ("unused", Indexed::Unused, 256),
];

pub(crate) fn classify(key: &str) -> Key {
    if let Some((_, s)) = PLAIN.iter().find(|(k, _)| *k == key) {
        return Key::Plain(*s);
    }
    if NOT_CARRIED.iter().any(|n| n.key == key) {
        return Key::NotCarried;
    }
    match key {
        "features" => return Key::Features,
        "rootfs" => return Key::Rootfs,
        "lxc" => return Key::Lxc,
        _ => {}
    }
    for (prefix, kind, limit) in INDEXED {
        let Some(n) = key.strip_prefix(prefix) else {
            continue;
        };
        // "mp01" is not a key of PVE's.
        if let Ok(i) = n.parse::<u16>() {
            if i < *limit && i.to_string() == n {
                return Key::Indexed(*kind, i);
            }
        }
    }
    Key::Unknown
}
