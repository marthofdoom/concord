# Concord

**Cluster behaviour for Proxmox VE hosts that are not in a cluster.**

Concord is meant to run as a single container on a PVE host and provide the capabilities
a standalone node gives up — live migration between hosts, replication,
resource-driven automatic placement, backup orchestration that repairs itself,
and update automation for OCI-based guests — by driving Proxmox's own public
API rather than by joining or reimplementing Corosync.

> **Status:** 0.1.1 — early. One feature works: a live, **read-only inventory**
> of several standalone hosts ([below](#what-works-today)). Everything else is
> designed ([docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)) but not built.

> **Unofficial.** Concord is not affiliated with, endorsed by, or connected to
> Proxmox Server Solutions GmbH. It talks to Proxmox VE through its documented
> HTTP API using credentials you supply. See [LICENSE](LICENSE)
> (AGPL-3.0-or-later).

## What it is meant to do

None of the capabilities in this table are built yet.

| Capability | How, without a cluster |
| --- | --- |
| **Live migration** | `qm remote-migrate` / `pct remote-migrate`, PVE's own cross-installation migration path — an API token and an endpoint, no shared cluster config |
| **Backup and replication** | Proxmox Backup Server, run as a guest on the managed hosts — no extra bare metal. Incremental via QEMU dirty bitmaps, deduplicated, verified, and synced between PBS instances, with every guest's backups kept on a host other than its own. Syncthing for templates, ISOs, and arbitrary data |
| **Recovery** | A guest that is down and shouldn't be is started again — on a single host too. From two hosts up, a host going dark has its guests restored elsewhere from a cross-host PBS backup — live restore for VMs — made safe by the dark host fencing itself on a deadline rather than by out-voting it |
| **Automatic placement** | Pressure on CPU/memory/IO on one host triggers a policy-driven migration of the cheapest guest that relieves it |
| **Backup control** | Owns the `vzdump` schedule for every guest, verifies each archive, and reconciles guests that a failed backup left powered off |
| **OCI guest updates** | Pulls a new image, snapshots first, migrates binds and volumes onto the new layout, and rolls back on a failed health check |
| **Web access** | A first-party UI for all of the above, beside the PVE UI on 8006 rather than replacing it |

## What works today

The controller polls every configured host and serves one picture of all hosts
and guests. A host that stops answering keeps its last-known guests, marked
stale; a guest disappears only when its host answers and no longer lists it.

1. On each host, create a token that can only read:

   ```sh
   pveum user add user1@pve
   pveum acl modify / --users user1@pve --roles PVEAuditor
   pveum user token add user1@pve token-1 --privsep 0
   ```

   The role must cover `/`: PVE leaves guests the token may not see out of its
   lists without an error, so Concord would take them for deleted.
2. Copy `concord.example.toml` to `concord.toml` and fill it in; not running as
   root, set `state_dir` to a directory you can create (say `"state"`); put the token
   secrets in the secrets file (mode 0600).
3. Add a user for yourself and a token for `concordctl`. There are no default
   credentials. Root on a tracked host needs none: it signs in to the web UI as
   `root@<host name>` with that host's root password (and its TOTP code or
   recovery key), checked by that host alone, for at most two hours. **That makes
   root on any tracked host an admin of the whole estate**; `pve_root_login =
   false` turns it off.

   ```sh
   export CONCORD_CONFIG=concord.toml
   concord user add user1@pve --role admin       # asks for the password
   (umask 077; concord token add ctl --role readonly > ctl.token)
   ```

   Roles are `admin` and `readonly`. `concord user list`, `user remove` and
   `token remove` manage them; a running server honours a change on its next
   request, and removing a user ends that user's sessions. Run these as
   the account Concord runs as: root is refused where that account controls the
   directory (`su -s /bin/sh concord -c 'concord user ...'`).
4. Run it, and query it:

   ```sh
   concord &
   export CONCORD_TOKEN_FILE=ctl.token
   concordctl hosts
   concordctl guests --status running
   concordctl guest pve1 100 --json
   ```

On loopback it speaks plain HTTP. On any other address it speaks HTTPS only, with
the certificate in `tls_cert`/`tls_key` or a self-signed one it generates under
`state_dir` on first run. It logs the certificate's SHA-256 fingerprint on start;
give that to `concordctl` as `--fingerprint` or `CONCORD_FINGERPRINT`. A reverse
proxy should connect to the HTTPS listener and pass the original `Host` on:
browsers' writes are checked against it.

## Layout

```
crates/concord-core     shared types; no network
crates/concord-server   orchestrator: HTTP API, web UI, jobs  → binary `concord`
crates/concord-config   configuration file and token secrets
crates/concord-inventory  polls the hosts; one snapshot of the estate
crates/concord-oci      what of a container must survive replacing its image
crates/concordctl       command-line client of the API        → binary `concordctl`
crates/concord-agent    host-side watchdog, no runtime deps   → binary `concord-agent`
crates/concord-pve      PVE API client: token auth, certificate pinning, mock
testbed/                nested-PVE test estate and its dashboard (docs/TESTBED.md)
docs/                   ARCHITECTURE.md (mechanism) · TESTBED.md (test estate)
```

The design runs both on **every** host: a small Concord container beside the guests, and
the agent on the hypervisor itself. One container is active and holds the full
host and guest inventory; the rest sit dormant, live-synced with that same
picture, costing almost nothing and ready to be promoted with nothing to
rebuild. Dormant instances will serve the UI read-only, so any host's address is a
working entry point.

`concord-agent` will be a single static binary on the PVE host, scoped to what the
container structurally cannot do (today it only logs a line) — restart the container Concord is running in,
and report host facts the PVE API does not expose, such as whether a
storage module built through DKMS actually resolves for the running kernel.

## Building

```sh
cargo build --release
```

Requires a stable Rust toolchain (see `rust-toolchain.toml`).

## Leak scan

`cargo run -p concord-pve --locked --features capture --example leakscan` checks
every tracked file for addresses, MACs, fingerprints, UUIDs and user names that
are not placeholders; CI runs it. Contributors with a PVE estate of their own can
also have their own names caught by pointing `CONCORD_ESTATE_DIGESTS` at a private
list (see `crates/concord-pve/ASSUMPTIONS.md`).

## Licence

AGPL-3.0-or-later — the same licence Proxmox VE itself carries. Concord
contains no Proxmox code; it is a client of the published API.
