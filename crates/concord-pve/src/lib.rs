//! Proxmox VE API client for Concord.
//!
//! Lives apart from `concord-core` because that crate promises never to touch
//! the network. Everything Concord does to a host goes through [`PveApi`], so
//! subsystems depend on the trait and test against [`MockPve`] (feature
//! `mock`) rather than a live host.
//!
//! Security stance: the client carries an API token that is typically
//! root-equivalent, so TLS is never relaxed. The server certificate is pinned
//! by SHA-256 fingerprint (see [`Fingerprint`]); there is no option to skip
//! verification.

#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

mod api;
mod auth;
#[cfg(any(test, feature = "capture"))]
mod capture;
mod error;
#[cfg(any(test, feature = "capture"))]
mod fixtures;
mod http;
#[cfg(any(test, feature = "mock"))]
mod mock;
#[cfg(any(test, feature = "capture"))]
mod normalise;
#[cfg(any(test, feature = "capture"))]
mod sanitize;
mod task;
mod tls;

pub use api::{api_path, Method, NodeInfo, NodeStatus, PveApi, TaskState, TaskStatus, VersionInfo};
pub use auth::{ApiToken, Secret};
#[cfg(any(test, feature = "capture"))]
pub use capture::{capture_all, write_set, CaptureLimits, Entry, ErrBody, ReadOnly};
pub use error::PveError;
#[cfg(any(test, feature = "capture"))]
pub use fixtures::{FixtureSet, FIXTURE_ROOT};
pub use http::HttpPveClient;
#[cfg(any(test, feature = "mock"))]
pub use mock::{Call, MockPve};
#[cfg(any(test, feature = "capture"))]
pub use normalise::normalise;
#[cfg(any(test, feature = "capture"))]
pub use sanitize::{Leak, LeakScanner, Sanitizer, ESTATE_DIGESTS_ENV};
pub use task::{wait_for_task, TaskOutcome, Upid, MIN_POLL_INTERVAL};
pub use tls::Fingerprint;

#[cfg(test)]
mod fixture_tests;
#[cfg(test)]
mod tests;
