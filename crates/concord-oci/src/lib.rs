//! The part of a container that must survive recreating it from a new image.
//!
//! Pure: it reads the JSON of PVE's `lxc/{vmid}/config` and `/pending`, and
//! yields a [`Layout`] or every reason it will not. Whatever it fails to carry
//! is user data lost without a trace, so it never skips: a key, option or shape
//! it does not know is a [`Refusal`].
//!
//! Key names and grammar are those of pve-container 6.1.14
//! (`PVE::LXC::Config`).

#![cfg_attr(test, recursion_limit = "256")]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

mod keys;
mod layout;
mod property;
mod refusal;
mod secret;

pub use keys::{NotCarried, NotCarriedKey, NOT_CARRIED};
pub use layout::{
    ConfigSource, EnvVisibility, ImageCandidate, Layout, MountPoint, MountSlot, MountSource,
    Parameter, RawLxc, Setting, VolumeId,
};
pub use property::{Opt, Property};
pub use refusal::{Refusal, Refusals};
pub use secret::Secret;

#[cfg(test)]
mod tests;
