use std::fmt;

/// Why a config cannot be turned into a layout.
///
/// A refusal names keys, never values. An option name is named only if the
/// schema has it: an unknown one is part of a value, and may be a secret.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    #[error("the config is not a JSON object")]
    NotAnObject,
    #[error("unknown key {0:?}")]
    UnknownKey(String),
    #[error("{key}: unexpected shape")]
    Shape { key: String },
    #[error("{key}: not a valid {expected}")]
    BadValue { key: String, expected: &'static str },
    #[error("{key}: empty, which PVE cannot store")]
    Empty { key: String },
    #[error("{key}: contains a control character")]
    ControlCharacter { key: String },
    #[error("{key}: option {position} is unknown")]
    UnknownOption { key: String, position: usize },
    #[error("{key}: option {position} is malformed")]
    MalformedOption { key: String, position: usize },
    #[error("{key}: option {option} is given twice")]
    DuplicateOption { key: String, option: &'static str },
    #[error("{key}: option {option} is missing")]
    MissingOption { key: String, option: &'static str },
    #[error("{key}: option {option} is not a valid {expected}")]
    BadOption {
        key: String,
        option: &'static str,
        expected: &'static str,
    },
    #[error("{key}: cannot tell whether this is a volume, a bind mount or a device")]
    AmbiguousSource { key: String },
    /// `storage:8` asks PVE to create a new, empty volume.
    #[error("{key}: this asks for a new volume rather than naming one")]
    Allocation { key: String },
    #[error("rootfs is a host path, not a storage volume")]
    RootfsNotVolume,
    #[error("{first} and {second} name the same volume")]
    SharedVolume { first: String, second: String },
    #[error("{0} is missing, although PVE always returns it")]
    Missing(&'static str),
    #[error("the container is locked")]
    Locked,
    #[error("the container is a template")]
    Template,
    #[error("the config is a snapshot's, not the container's current one")]
    SnapshotConfig,
    #[error("{key} has a pending change")]
    PendingChange { key: String },
    #[error("pending changes were not checked; the config alone does not show them")]
    PendingUnknown,
    #[error("the pending-changes response has an unexpected shape")]
    PendingShape,
    #[error("the config changed between reading it and checking its pending changes")]
    PendingStale,
    #[error("env may be hidden: the token is not known to hold VM.Config.Options")]
    EnvVisibilityUnknown,
}

/// Every reason found, not only the first. Never empty.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusals(pub(crate) Vec<Refusal>);

impl Refusals {
    pub fn reasons(&self) -> &[Refusal] {
        &self.0
    }
}

impl fmt::Display for Refusals {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, r) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str("; ")?;
            }
            write!(f, "{r}")?;
        }
        Ok(())
    }
}

impl std::error::Error for Refusals {}

impl From<Refusals> for concord_core::Error {
    fn from(r: Refusals) -> Self {
        concord_core::Error::NotSupported {
            operation: "replacing the container's image",
            reason: r.to_string(),
        }
    }
}
