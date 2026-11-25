use std::fmt;

use zeroize::Zeroizing;

/// A config value, byte for byte as PVE returned it.
///
/// Any of them can hold a credential (`env`, a raw `lxc` line, the notes), so
/// none prints: there is no `Display` and no serde, and `Debug` is redacted.
/// [`Secret::expose`] is the one way out, so that every use can be searched for.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(Zeroizing<String>);

impl Secret {
    pub(crate) fn new(s: impl Into<String>) -> Self {
        Secret(Zeroizing::new(s.into()))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}
