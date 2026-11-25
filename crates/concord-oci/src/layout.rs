use std::collections::BTreeMap;

use serde_json::{Map, Value};

use crate::keys::{classify, Indexed, Key, Scalar, REQUIRED};
use crate::property::{self, check, parse_bool, Kind, Property};
use crate::refusal::{Refusal, Refusals};
use crate::secret::Secret;

/// Whether `env` would be in the config if the container had one.
///
/// Without `VM.Config.Options`, pve-container before 6.1.16 answers 403 and
/// later versions leave `env` out, which looks the same as there being none.
/// So the config cannot say; whoever fetched it must.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvVisibility {
    /// The token that fetched the config holds `VM.Config.Options` on the guest.
    Established,
    Unknown,
}

/// Everything a layout is read from. All of it must come from the same token.
#[derive(Clone, Copy)]
pub struct ConfigSource<'a> {
    /// `GET .../lxc/{vmid}/config`.
    pub config: &'a Value,
    /// `GET .../lxc/{vmid}/pending`. The config alone does not show a pending
    /// change: PVE merges it in, or with `current=1` leaves it out.
    pub pending: Option<&'a Value>,
    pub env: EnvVisibility,
}

/// A volume that exists on a storage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VolumeId {
    pub storage: Secret,
    pub volume: Secret,
}

/// Where a mount point's data lives, which decides what may be done with it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MountSource {
    /// Preserved and attached again, never recreated.
    Volume(VolumeId),
    /// A host directory: declared again.
    Bind(Secret),
    /// A host block device: declared again.
    Device(Secret),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum MountSlot {
    Rootfs,
    Mp(u16),
}

impl MountSlot {
    pub fn key(&self) -> String {
        match self {
            MountSlot::Rootfs => "rootfs".into(),
            MountSlot::Mp(i) => format!("mp{i}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountPoint {
    pub slot: MountSlot,
    pub source: MountSource,
    pub property: Property,
}

impl MountPoint {
    /// The path inside the container.
    pub fn target(&self) -> &str {
        match self.slot {
            MountSlot::Rootfs => "/",
            MountSlot::Mp(_) => self.property.get("mp").unwrap_or_default(),
        }
    }

    pub fn backup(&self) -> Option<bool> {
        self.property.flag("backup")
    }

    pub fn size(&self) -> Option<&str> {
        self.property.get("size")
    }

    pub fn read_only(&self) -> Option<bool> {
        self.property.flag("ro")
    }

    pub fn shared(&self) -> Option<bool> {
        self.property.flag("shared")
    }
}

/// A plain key's value, with the JSON type PVE gave it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Setting {
    text: Secret,
    numeric: bool,
}

impl Setting {
    pub fn text(&self) -> &Secret {
        &self.text
    }
}

/// One raw `lxc.*` line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawLxc {
    pub key: String,
    pub value: Secret,
}

/// A parameter of PVE's create and set calls.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Parameter {
    pub key: String,
    pub value: Secret,
}

/// A value that PVE may have taken from the image when it created the
/// container, or that the user may have set. The config does not say which;
/// deciding is a later step's work, with both images' configs at hand.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImageCandidate<'a> {
    Entrypoint(&'a Secret),
    Env(&'a Secret),
    /// Creation sets `cmode` beside a custom entrypoint.
    Cmode(&'a Secret),
    /// Creation adds `host-managed` beside a custom entrypoint.
    HostManaged {
        net: u16,
        value: &'a str,
    },
    /// Position in the raw lines, and the line.
    Lxc(usize, &'a RawLxc),
}

/// The raw keys PVE's OCI create writes. Any raw line is the user's otherwise.
const IMAGE_LXC: &[&str] = &[
    "lxc.init.uid",
    "lxc.init.gid",
    "lxc.init.groups",
    "lxc.init.cwd",
    "lxc.signal.halt",
];

/// A container's config, in full.
#[derive(Clone, PartialEq, Eq)]
pub struct Layout {
    settings: BTreeMap<&'static str, Setting>,
    features: Option<Property>,
    mounts: Vec<MountPoint>,
    nets: BTreeMap<u16, Property>,
    devs: BTreeMap<u16, Property>,
    unused: BTreeMap<u16, (VolumeId, Property)>,
    /// `None` and an empty list are different configs.
    lxc: Option<Vec<RawLxc>>,
    digest: String,
    parent: Option<String>,
}

impl std::fmt::Debug for Layout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Keys only. `Secret` would redact the values anyway.
        f.debug_list().entries(self.keys()).finish()
    }
}

impl Layout {
    /// Reads a config, or lists every reason not to.
    pub fn parse(source: ConfigSource<'_>) -> Result<Layout, Refusals> {
        let mut p = Parser::default();
        if source.env != EnvVisibility::Established {
            p.refuse(Refusal::EnvVisibilityUnknown);
        }
        match source.config {
            Value::Object(map) => p.config(map),
            _ => p.refuse(Refusal::NotAnObject),
        }
        p.pending(source.pending);
        p.finish()
    }

    /// Every carried key, in a stable order.
    pub fn keys(&self) -> Vec<String> {
        let mut keys: Vec<String> = self
            .parameters_of(|_| true)
            .into_iter()
            .map(|p| p.key)
            .collect();
        keys.extend(self.unused.keys().map(|i| format!("unused{i}")));
        if self.lxc.is_some() {
            keys.push("lxc".into());
        }
        keys
    }

    pub fn setting(&self, key: &str) -> Option<&Secret> {
        self.settings.get(key).map(|s| &s.text)
    }

    /// A boolean setting. `None` if unset: PVE's default then applies.
    pub fn flag(&self, key: &str) -> Option<bool> {
        self.setting(key).and_then(|s| parse_bool(s.expose()))
    }

    pub fn features(&self) -> Option<&Property> {
        self.features.as_ref()
    }

    /// The root filesystem first, then mount points by number.
    pub fn mounts(&self) -> &[MountPoint] {
        &self.mounts
    }

    pub fn nets(&self) -> impl Iterator<Item = (u16, &Property)> {
        self.nets.iter().map(|(i, p)| (*i, p))
    }

    pub fn devs(&self) -> impl Iterator<Item = (u16, &Property)> {
        self.devs.iter().map(|(i, p)| (*i, p))
    }

    /// Volumes the container owns but does not mount. PVE's create ignores
    /// `unusedN`, so they need attaching by another way.
    pub fn unused(&self) -> impl Iterator<Item = (u16, &VolumeId)> {
        self.unused.iter().map(|(i, (v, _))| (*i, v))
    }

    /// Raw lines in order. PVE's API cannot set them.
    pub fn raw_lxc(&self) -> &[RawLxc] {
        self.lxc.as_deref().unwrap_or_default()
    }

    /// For PVE's `digest` parameter, so a write fails if the config has moved.
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// The latest snapshot. If there is one, recreating the container would
    /// lose it.
    pub fn parent(&self) -> Option<&str> {
        self.parent.as_deref()
    }

    /// Parameters that are safe to declare on the new container: everything but
    /// storage volumes, `unusedN` and raw lines. Values are verbatim.
    pub fn parameters(&self) -> Vec<Parameter> {
        self.parameters_of(|m| !matches!(m.source, MountSource::Volume(_)))
    }

    /// Storage volumes, to be attached as they are. `rootfs` is among them.
    /// Never passed to a create call, which would own them if it failed.
    pub fn volume_parameters(&self) -> Vec<Parameter> {
        self.mounts
            .iter()
            .filter(|m| matches!(m.source, MountSource::Volume(_)))
            .map(mount_parameter)
            .collect()
    }

    fn parameters_of(&self, mount: impl Fn(&MountPoint) -> bool) -> Vec<Parameter> {
        let mut out: Vec<Parameter> = self
            .settings
            .iter()
            .map(|(k, s)| parameter(k, &s.text))
            .collect();
        out.extend(self.features.iter().map(|p| parameter("features", p.raw())));
        out.extend(self.mounts.iter().filter(|m| mount(m)).map(mount_parameter));
        out.extend(
            self.nets
                .iter()
                .map(|(i, p)| parameter(&format!("net{i}"), p.raw())),
        );
        out.extend(
            self.devs
                .iter()
                .map(|(i, p)| parameter(&format!("dev{i}"), p.raw())),
        );
        out
    }

    /// Values that may have come from the image. They are in
    /// [`Layout::parameters`] and [`Layout::raw_lxc`] too.
    pub fn image_candidates(&self) -> Vec<ImageCandidate<'_>> {
        let mut out = Vec::new();
        out.extend(self.setting("entrypoint").map(ImageCandidate::Entrypoint));
        out.extend(self.setting("env").map(ImageCandidate::Env));
        out.extend(self.setting("cmode").map(ImageCandidate::Cmode));
        for (net, p) in self.nets() {
            out.extend(
                p.get("host-managed")
                    .map(|value| ImageCandidate::HostManaged { net, value }),
            );
        }
        out.extend(
            self.raw_lxc()
                .iter()
                .enumerate()
                .filter(|(_, l)| IMAGE_LXC.contains(&l.key.as_str()))
                .map(|(i, l)| ImageCandidate::Lxc(i, l)),
        );
        out
    }

    /// The carried keys as PVE would return them, for comparing the recreated
    /// container with this one. Holds every value in clear.
    pub fn expose_config(&self) -> Map<String, Value> {
        let mut map = Map::new();
        for p in self.parameters_of(|_| true) {
            map.insert(p.key, Value::String(p.value.expose().to_string()));
        }
        for (key, s) in self.settings.iter().filter(|(_, s)| s.numeric) {
            if let Ok(n) = serde_json::from_str::<serde_json::Number>(s.text.expose()) {
                map.insert((*key).to_string(), Value::Number(n));
            }
        }
        for (i, (_, p)) in &self.unused {
            map.insert(format!("unused{i}"), p.raw().expose().into());
        }
        if let Some(lines) = &self.lxc {
            let lines = lines
                .iter()
                .map(|l| Value::from(vec![l.key.as_str(), l.value.expose()]))
                .collect();
            map.insert("lxc".into(), Value::Array(lines));
        }
        map
    }
}

fn parameter(key: &str, value: &Secret) -> Parameter {
    Parameter {
        key: key.to_string(),
        value: value.clone(),
    }
}

fn mount_parameter(m: &MountPoint) -> Parameter {
    parameter(&m.slot.key(), m.property.raw())
}

#[derive(Default)]
struct Parser {
    refusals: Vec<Refusal>,
    settings: BTreeMap<&'static str, Setting>,
    features: Option<Property>,
    mounts: Vec<MountPoint>,
    nets: BTreeMap<u16, Property>,
    devs: BTreeMap<u16, Property>,
    unused: BTreeMap<u16, (VolumeId, Property)>,
    lxc: Option<Vec<RawLxc>>,
    digest: Option<String>,
    parent: Option<String>,
}

impl Parser {
    fn refuse(&mut self, r: Refusal) {
        self.refusals.push(r);
    }

    fn config(&mut self, map: &Map<String, Value>) {
        for key in REQUIRED {
            if !map.contains_key(*key) {
                self.refuse(Refusal::Missing(key));
            }
        }
        for (key, value) in map {
            match classify(key) {
                Key::Unknown => self.refuse(Refusal::UnknownKey(key.clone())),
                Key::NotCarried => self.not_carried(key, value),
                Key::Plain(kind) => self.plain(key, kind, value),
                Key::Features => {
                    self.features = self.property(key, value, &property::FEATURES);
                }
                Key::Rootfs => self.mount(MountSlot::Rootfs, value),
                Key::Indexed(Indexed::Mp, i) => self.mount(MountSlot::Mp(i), value),
                Key::Indexed(Indexed::Net, i) => {
                    if let Some(p) = self.property(key, value, &property::NET) {
                        self.nets.insert(i, p);
                    }
                }
                Key::Indexed(Indexed::Dev, i) => self.dev(key, i, value),
                Key::Indexed(Indexed::Unused, i) => self.unused(key, i, value),
                Key::Lxc => self.lxc(value),
            }
        }
        self.mounts.sort_by_key(|m| m.slot);
        self.shared_volumes();
    }

    fn not_carried(&mut self, key: &str, value: &Value) {
        match key {
            "digest" => self.digest = self.line(key, value),
            "parent" => self.parent = self.line(key, value),
            "lock" => self.refuse(Refusal::Locked),
            "pending" => self.refuse(Refusal::PendingChange { key: key.into() }),
            // "snaptime", "snapshots"
            _ => self.refuse(Refusal::SnapshotConfig),
        }
    }

    /// A string that fits on one config line.
    fn line(&mut self, key: &str, value: &Value) -> Option<String> {
        let key = || key.to_string();
        let Value::String(s) = value else {
            self.refuse(Refusal::Shape { key: key() });
            return None;
        };
        if s.is_empty() {
            self.refuse(Refusal::Empty { key: key() });
            return None;
        }
        if s.chars().any(is_forbidden) {
            self.refuse(Refusal::ControlCharacter { key: key() });
            return None;
        }
        Some(s.clone())
    }

    fn property(
        &mut self,
        key: &str,
        value: &Value,
        schema: &property::Schema,
    ) -> Option<Property> {
        let s = self.line(key, value)?;
        Property::parse(key, &s, schema, &mut self.refusals)
    }

    fn plain(&mut self, key: &str, kind: Scalar, value: &Value) {
        let Some((name, _)) = crate::keys::PLAIN.iter().find(|(k, _)| *k == key) else {
            return self.refuse(Refusal::UnknownKey(key.into()));
        };
        let (text, numeric) = match (kind, value) {
            // PVE returns what it checked as a number as a JSON number, and
            // the rest as strings.
            (Scalar::Bool | Scalar::Int | Scalar::Number, Value::Number(n)) => {
                (n.to_string(), true)
            }
            // Any character: PVE encodes the notes on disk.
            (Scalar::Text, Value::String(s)) if !s.is_empty() => (s.clone(), false),
            (Scalar::Env, Value::String(s)) if !s.is_empty() => {
                // PVE drops an empty entry on write, and its API refuses one
                // without a plain name.
                if !s.split('\0').all(is_env_entry) {
                    return self.refuse(Refusal::BadValue {
                        key: key.into(),
                        expected: "list of NAME=value entries",
                    });
                }
                (s.clone(), false)
            }
            _ => match self.line(key, value) {
                Some(s) => (s, false),
                None => return,
            },
        };
        let checked = match kind {
            Scalar::Bool => check(Kind::Bool, &text),
            Scalar::Int => check(Kind::Int, &text),
            Scalar::Number => check(Kind::Number, &text),
            Scalar::Line | Scalar::Text | Scalar::Env => Ok(()),
        };
        if let Err(expected) = checked {
            return self.refuse(Refusal::BadValue {
                key: key.into(),
                expected,
            });
        }
        // A template has no guest to update, and its volumes are base images.
        if key == "template" && parse_bool(&text) == Some(true) {
            self.refuse(Refusal::Template);
        }
        self.settings.insert(
            name,
            Setting {
                text: Secret::new(text),
                numeric,
            },
        );
    }

    fn mount(&mut self, slot: MountSlot, value: &Value) {
        let key = slot.key();
        let schema = match slot {
            MountSlot::Rootfs => &property::ROOTFS,
            MountSlot::Mp(_) => &property::MP,
        };
        let Some(property) = self.property(&key, value, schema) else {
            return;
        };
        match source(&key, property.get("volume").unwrap_or_default()) {
            // The new image is unpacked into the root filesystem, which must
            // not be a host directory.
            Ok(MountSource::Bind(_) | MountSource::Device(_)) if slot == MountSlot::Rootfs => {
                self.refuse(Refusal::RootfsNotVolume);
            }
            Ok(source) => self.mounts.push(MountPoint {
                slot,
                source,
                property,
            }),
            Err(r) => self.refuse(r),
        }
    }

    fn unused(&mut self, key: &str, i: u16, value: &Value) {
        let Some(property) = self.property(key, value, &property::UNUSED) else {
            return;
        };
        match source(key, property.get("volume").unwrap_or_default()) {
            Ok(MountSource::Volume(v)) => {
                self.unused.insert(i, (v, property));
            }
            Ok(_) => self.refuse(Refusal::AmbiguousSource { key: key.into() }),
            Err(r) => self.refuse(r),
        }
    }

    fn dev(&mut self, key: &str, i: u16, value: &Value) {
        let Some(property) = self.property(key, value, &property::DEV) else {
            return;
        };
        match source(key, property.get("path").unwrap_or_default()) {
            Ok(MountSource::Device(_)) => {
                self.devs.insert(i, property);
            }
            _ => self.refuse(Refusal::BadOption {
                key: key.into(),
                option: "path",
                expected: "device path",
            }),
        }
    }

    fn lxc(&mut self, value: &Value) {
        let Value::Array(lines) = value else {
            return self.refuse(Refusal::Shape { key: "lxc".into() });
        };
        let mut out = Vec::new();
        for (i, line) in lines.iter().enumerate() {
            let at = format!("lxc[{i}]");
            let pair = line.as_array().map(Vec::as_slice);
            let Some([Value::String(key), Value::String(value)]) = pair else {
                self.refuse(Refusal::Shape { key: at });
                continue;
            };
            let named = key.strip_prefix("lxc.").is_some_and(|k| {
                !k.is_empty()
                    && k.bytes()
                        .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-' | b'.'))
            });
            // PVE moves this one into `env`, and drops it from here on write.
            if !named || key == "lxc.environment.runtime" {
                self.refuse(Refusal::BadValue {
                    key: at,
                    expected: "raw lxc key",
                });
            } else if value.chars().any(is_forbidden) {
                self.refuse(Refusal::ControlCharacter { key: at });
            } else {
                // An empty value is meaningful: it resets a list.
                out.push(RawLxc {
                    key: key.clone(),
                    value: Secret::new(value.as_str()),
                });
            }
        }
        self.lxc = Some(out);
    }

    /// One volume under two keys has no single owner, so neither key could be
    /// moved without changing the other.
    fn shared_volumes(&mut self) {
        let mut seen: BTreeMap<(String, String), String> = BTreeMap::new();
        let volumes = self
            .mounts
            .iter()
            .filter_map(|m| match &m.source {
                MountSource::Volume(v) => Some((m.slot.key(), v)),
                _ => None,
            })
            .chain(
                self.unused
                    .iter()
                    .map(|(i, (v, _))| (format!("unused{i}"), v)),
            );
        let mut found = Vec::new();
        for (key, v) in volumes {
            let id = (v.storage.expose().into(), v.volume.expose().into());
            match seen.get(&id) {
                Some(first) => found.push(Refusal::SharedVolume {
                    first: first.clone(),
                    second: key,
                }),
                None => {
                    seen.insert(id, key);
                }
            }
        }
        self.refusals.extend(found);
    }

    fn pending(&mut self, pending: Option<&Value>) {
        let Some(pending) = pending else {
            return self.refuse(Refusal::PendingUnknown);
        };
        let Value::Array(items) = pending else {
            return self.refuse(Refusal::PendingShape);
        };
        let mut digest = None;
        for item in items {
            let (Some(item), Some(Value::String(key))) = (item.as_object(), item.get("key")) else {
                self.refuse(Refusal::PendingShape);
                continue;
            };
            let known = ["key", "value", "pending", "delete"];
            if item.keys().any(|k| !known.contains(&k.as_str())) {
                self.refuse(Refusal::PendingShape);
            }
            if key == "digest" {
                digest = item.get("value").and_then(Value::as_str);
            }
            let deleted = match item.get("delete") {
                None => false,
                Some(v) => v.as_u64() != Some(0) && v.as_str() != Some("0"),
            };
            if deleted || item.contains_key("pending") {
                self.refuse(Refusal::PendingChange { key: key.clone() });
            }
        }
        match (digest, self.digest.as_deref()) {
            (Some(a), Some(b)) if a != b => self.refuse(Refusal::PendingStale),
            // PVE lists the digest among the options, so a list without it is
            // not this response. A config without one is refused already.
            (None, _) => self.refuse(Refusal::PendingShape),
            _ => {}
        }
    }

    fn finish(mut self) -> Result<Layout, Refusals> {
        self.refusals.dedup();
        match self.digest {
            Some(digest) if self.refusals.is_empty() => Ok(Layout {
                settings: self.settings,
                features: self.features,
                mounts: self.mounts,
                nets: self.nets,
                devs: self.devs,
                unused: self.unused,
                lxc: self.lxc,
                digest,
                parent: self.parent,
            }),
            _ => Err(Refusals(self.refusals)),
        }
    }
}

/// Control characters, less tab: PVE's own rule for `entrypoint` and `env`.
/// Elsewhere only a line break is impossible, but nothing legitimate uses the
/// others.
fn is_forbidden(c: char) -> bool {
    c != '\t' && c.is_ascii_control()
}

fn is_env_entry(e: &str) -> bool {
    e.split_once('=').is_some_and(|(name, value)| {
        !name.is_empty()
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            && !value.chars().any(is_forbidden)
    })
}

/// PVE's rule, made strict: it goes by the first characters of the text, so a
/// path that only means a device once normalised passes there as a bind.
fn source(key: &str, v: &str) -> Result<MountSource, Refusal> {
    let ambiguous = || Refusal::AmbiguousSource { key: key.into() };
    if v.starts_with('/') {
        let odd = v.contains("//") || v.split('/').any(|c| c == "." || c == "..");
        if odd || v == "/dev" || v == "/dev/" {
            return Err(ambiguous());
        }
        return Ok(if v.starts_with("/dev/") {
            MountSource::Device(Secret::new(v))
        } else {
            MountSource::Bind(Secret::new(v))
        });
    }
    let (storage, volume) = v.split_once(':').ok_or_else(ambiguous)?;
    if check(Kind::Number, volume).is_ok() {
        return Err(Refusal::Allocation { key: key.into() });
    }
    let s = storage.as_bytes();
    let valid = s.len() >= 2
        && s.first().is_some_and(u8::is_ascii_alphabetic)
        && s.last().is_some_and(u8::is_ascii_alphanumeric)
        && s.iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
    // A leading slash would be a URL, or a path with a stray prefix.
    let bad_volume = volume.is_empty()
        || volume.starts_with('/')
        || volume.chars().any(char::is_whitespace)
        || volume.split('/').any(|c| c == "." || c == "..");
    if !valid || bad_volume {
        return Err(ambiguous());
    }
    Ok(MountSource::Volume(VolumeId {
        storage: Secret::new(storage),
        volume: Secret::new(volume),
    }))
}
