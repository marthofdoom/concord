//! PVE's property strings: `value,key=value,...`.

use crate::refusal::Refusal;
use crate::secret::Secret;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Text,
    Bool,
    Int,
    Number,
}

pub(crate) struct Schema {
    /// The option a part without `=` sets.
    pub default: Option<&'static str>,
    pub required: &'static [&'static str],
    pub options: &'static [(&'static str, Kind)],
}

pub(crate) const ROOTFS: Schema = Schema {
    default: Some("volume"),
    required: &["volume"],
    options: &[
        ("volume", Kind::Text),
        ("size", Kind::Text),
        ("acl", Kind::Bool),
        ("mountoptions", Kind::Text),
        ("idmap", Kind::Text),
        ("ro", Kind::Bool),
        ("quota", Kind::Bool),
        ("replicate", Kind::Bool),
        ("shared", Kind::Bool),
    ],
};

pub(crate) const MP: Schema = Schema {
    default: Some("volume"),
    required: &["volume", "mp"],
    options: &[
        ("volume", Kind::Text),
        ("mp", Kind::Text),
        ("backup", Kind::Bool),
        ("keepattrs", Kind::Bool),
        ("size", Kind::Text),
        ("acl", Kind::Bool),
        ("mountoptions", Kind::Text),
        ("idmap", Kind::Text),
        ("ro", Kind::Bool),
        ("quota", Kind::Bool),
        ("replicate", Kind::Bool),
        ("shared", Kind::Bool),
    ],
};

pub(crate) const UNUSED: Schema = Schema {
    default: Some("volume"),
    required: &["volume"],
    options: &[("volume", Kind::Text)],
};

pub(crate) const NET: Schema = Schema {
    default: None,
    required: &["name"],
    options: &[
        ("type", Kind::Text),
        ("name", Kind::Text),
        ("bridge", Kind::Text),
        ("hwaddr", Kind::Text),
        ("mtu", Kind::Int),
        ("ip", Kind::Text),
        ("gw", Kind::Text),
        ("ip6", Kind::Text),
        ("gw6", Kind::Text),
        ("firewall", Kind::Bool),
        ("tag", Kind::Int),
        ("trunks", Kind::Text),
        ("rate", Kind::Number),
        ("link_down", Kind::Bool),
        ("host-managed", Kind::Bool),
    ],
};

pub(crate) const DEV: Schema = Schema {
    default: Some("path"),
    // Optional in PVE's schema, but a device without a path says nothing.
    required: &["path"],
    options: &[
        ("path", Kind::Text),
        ("mode", Kind::Text),
        ("uid", Kind::Int),
        ("gid", Kind::Int),
        ("deny-write", Kind::Bool),
    ],
};

pub(crate) const FEATURES: Schema = Schema {
    default: None,
    required: &[],
    options: &[
        ("mount", Kind::Text),
        ("nesting", Kind::Bool),
        ("keyctl", Kind::Bool),
        ("fuse", Kind::Bool),
        ("mknod", Kind::Bool),
        ("force_rw_sys", Kind::Bool),
    ],
};

/// One option of a property string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opt {
    pub name: &'static str,
    pub value: Secret,
}

/// A parsed property string. The text it came from is what is written back, so
/// the order of the options and their spelling survive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Property {
    raw: Secret,
    options: Vec<Opt>,
}

impl Property {
    pub fn raw(&self) -> &Secret {
        &self.raw
    }

    /// In the order they were written.
    pub fn options(&self) -> &[Opt] {
        &self.options
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.options
            .iter()
            .find(|o| o.name == name)
            .map(|o| o.value.expose())
    }

    /// `None` if the option is absent: PVE's default then applies.
    pub fn flag(&self, name: &str) -> Option<bool> {
        self.get(name).and_then(parse_bool)
    }

    /// `None` after adding at least one reason to `refusals`.
    pub(crate) fn parse(
        key: &str,
        raw: &str,
        schema: &Schema,
        refusals: &mut Vec<Refusal>,
    ) -> Option<Property> {
        let before = refusals.len();
        let key = || key.to_string();
        let mut options: Vec<Opt> = Vec::new();
        for (position, part) in raw.split(',').enumerate() {
            // PVE ignores blank parts; `raw` keeps them.
            if part.chars().all(|c| c.is_ascii_whitespace()) {
                continue;
            }
            let position = position + 1;
            let (name, value) = match part.split_once('=') {
                Some((name, value)) if !name.is_empty() && !value.is_empty() => (Some(name), value),
                Some(_) => {
                    refusals.push(Refusal::MalformedOption {
                        key: key(),
                        position,
                    });
                    continue;
                }
                None => (schema.default, part),
            };
            let Some((name, kind)) =
                name.and_then(|n| schema.options.iter().copied().find(|(o, _)| *o == n))
            else {
                refusals.push(Refusal::UnknownOption {
                    key: key(),
                    position,
                });
                continue;
            };
            if options.iter().any(|o| o.name == name) {
                refusals.push(Refusal::DuplicateOption {
                    key: key(),
                    option: name,
                });
            }
            if let Err(expected) = check(kind, value) {
                refusals.push(Refusal::BadOption {
                    key: key(),
                    option: name,
                    expected,
                });
            }
            options.push(Opt {
                name,
                value: Secret::new(value),
            });
        }
        for option in schema.required {
            if !options.iter().any(|o| o.name == *option) {
                refusals.push(Refusal::MissingOption { key: key(), option });
            }
        }
        (refusals.len() == before).then(|| Property {
            raw: Secret::new(raw),
            options,
        })
    }
}

pub(crate) fn check(kind: Kind, value: &str) -> Result<(), &'static str> {
    let (ok, expected) = match kind {
        Kind::Text => (true, "text"),
        Kind::Bool => (parse_bool(value).is_some(), "boolean"),
        Kind::Int => (is_digits(value), "integer"),
        Kind::Number => (
            match value.split_once('.') {
                Some((whole, fraction)) => is_digits(whole) && is_digits(fraction),
                None => is_digits(value),
            },
            "number",
        ),
    };
    if ok {
        Ok(())
    } else {
        Err(expected)
    }
}

/// The spellings PVE accepts, in any case.
pub(crate) fn parse_bool(v: &str) -> Option<bool> {
    match v.to_ascii_lowercase().as_str() {
        "1" | "on" | "yes" | "true" => Some(true),
        "0" | "off" | "no" | "false" => Some(false),
        _ => None,
    }
}

fn is_digits(v: &str) -> bool {
    !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit())
}
