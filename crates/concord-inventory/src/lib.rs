//! Concord's read-only estate inventory (ARCHITECTURE "1. Inventory").
//!
//! One [`Poller`] reads every host through [`concord_pve::PveApi`] and
//! publishes an [`EstateSnapshot`] through an [`InventoryHandle`]. Everything
//! else reads the snapshot and never the API, so a decision is made against one
//! coherent picture. In-memory only; streaming to dormant instances is later.

#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

mod config_filter;
mod poller;
mod types;

pub use poller::{InventoryConfig, InventoryHandle, Poller};
pub use types::{Conflict, EstateSnapshot, Guest, Host, HostStatus, HostSummary};

#[cfg(test)]
mod tests;
