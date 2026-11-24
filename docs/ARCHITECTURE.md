# Concord — architecture

This document is the mechanism. Choices that depart from the obvious first
design, and why, are listed under [Design review](#design-review).

## Shape

Concord runs on **every** host, not on one, at any estate size from a single
machine upward. Each host carries an agent on the hypervisor and a small,
low-resource Concord container beside its guests; the containers form a peer set
that elects a leader, and the leader is the only instance permitted to act on
the estate. Nothing runs off the PVE machines — there is no witness appliance
and no external dependency, which is what makes the failover rules below
arithmetic rather than configuration.

```
        PVE host A                    PVE host B                    PVE host C
 ┌────────────────────────┐    ┌────────────────────────┐    ┌────────────────────────┐
 │ concord-agent (systemd)│    │ concord-agent (systemd)│    │ concord-agent (systemd)│
 │   watchdog only        │    │   watchdog only        │    │   watchdog only        │
 │ ┌────────────────────┐ │    │ ┌────────────────────┐ │    │ ┌────────────────────┐ │
 │ │ concord (LXC)      │──┼────┼▶│ concord (LXC)      │──┼────┼▶│ concord (LXC)      │ │
 │ │  ACTIVE            │ │    │ │  dormant           │ │    │ │  dormant           │ │
 │ │  API + UI :8010    │ │    │ │  live-synced state │ │    │ │  live-synced state │ │
 │ └────────┬───────────┘ │    │ └────────────────────┘ │    │ └────────────────────┘ │
 └──────────┼─────────────┘    └────────────────────────┘    └────────────────────────┘
            │  live sync: full host + guest inventory · expected state · leases
            └──▶ pveproxy :8006 on every host, by API token
```

One instance is **active**; the rest sit **dormant** on their hosts, doing no
work but holding a live-synced copy of the whole picture — every host, every
guest, every expected state. A dormant instance costs almost nothing, which is
what lets one sit on every host. It exists to be promoted: when the active
instance goes away, a dormant one already has the state it needs to take over
immediately, with nothing to rebuild and nothing to rediscover.

Dormant instances serve the UI read-only and forward writes to the active one,
so any host's address is a working entry point. A guest is never touched by an
instance that is not active and holding that guest's lease.

### Why the agent is nearly empty

Anything the orchestrator can do over the API, it does over the API. The agent
exists for what the orchestrator structurally cannot do: start the container
the orchestrator is inside, and report facts about the host that the API does
not expose (see [Storage detection](#storage-detection)). Keeping its scope
that small means the component running on the hypervisor with root is small
enough to audit in one sitting.

## Recovery

Recovery comes in two tiers. They are not the same problem, they do not need
the same guarantees, and conflating them is what made an earlier draft of this
document claim a single-host estate could do nothing useful.

### Tier 1 — a guest is down and should not be (any estate, including one host)

The active instance holds the full inventory and each guest's *expected* state.
When a guest's observed state disagrees with its expected state and no job holds
its lease, Concord starts it. That is the whole mechanism, and it needs no
agreement with anybody: the host is right there, observably alive, and answering
its own API. Nothing about this requires a second machine.

This is the tier that repairs the failed-backup case. `vzdump` in stop mode
powers a guest off, a job that dies mid-run never powers it back on, and Concord
notices and does. **A single-host estate gets this in full.**

### Tier 2 — a whole host goes dark (two hosts and up)

The host stops answering entirely. Its guests are restored on a surviving host
from a backup held by a PBS instance that was *not* on the dark host (see
[Backup and replication](#4-backup-and-replication-through-pbs)). This needs
somewhere to go, so it starts at two hosts.

The danger is the one every HA system has: a host that has gone *quiet* is not
necessarily a host that has *stopped*. Restarting a guest whose original is
still running puts two kernels on one disk. With two machines and nothing off
the hypervisors, there is no third vote to settle it — so Concord does not
settle it by voting.

### Self-fencing is what makes tier 2 safe

Safety comes from the isolated host taking itself out, not from the survivors
out-voting it. This is the technique Proxmox's own HA stack uses, and it works
at any estate size:

- Every host's agent holds a **fence deadline**. If it cannot reach any peer for
  longer than that deadline, it stops the Concord-managed guests on its own host
  — regardless of what it believes about the rest of the estate.
- A survivor waits **longer than that deadline** before restoring anything.

By the time a restore begins, the dark host is in one of two states: genuinely
dead, or alive-but-isolated and therefore already stopped. Both are safe. The
invariant is a timing one and it is pinned in code —
`concord_core::restore_delay` is always greater than the fence deadline.

**A software timer cannot fence a wedged kernel.** A host whose kernel has hung
still has its guests on the disk and is running no timers. The completion is the
hardware watchdog: the agent pets `/dev/watchdog`
only while it can see a peer, so an isolated *or* hung host is reset by hardware
on the same deadline. This is exactly what `watchdog-mux` does for PVE HA, and
it is the difference between a fence that holds and one that holds most of the
time.

### What more hosts add

Three or more hosts do not unlock tier 2 — the fence deadline already did that.
What they add is choice and margin: more candidate targets for a restore, the
ability to lose a host and still have several places to put its guests, and a
majority that can settle disagreements the timer alone would resolve more
slowly. Two hosts is a working HA estate here, not a degraded one.

### Restore-anywhere is bounded by the last cross-host backup

A guest can only be restored from a backup that survived the host that ran it.
The data lost when a host dies is everything written since that guest's last
backup **to a PBS on a different host** — a backup that lived only on the dark
host died with it and does not count. Concord shows the current RPO per guest on
exactly that definition, rather than implying a guest is protected because a
backup of it exists somewhere.

Restoring from a backup is slower than booting a warm replica, and the
difference is honest to state. QEMU guests use PBS **live restore**: the guest
boots immediately and its data streams in behind it, so recovery time is close
to a cold boot. LXC guests have no live restore; they come back once the full
restore completes, so their recovery time scales with their size. Concord
reports expected recovery time per guest alongside RPO.

### Membership changes

Hosts get added, and the dormant set has to grow without an operator rebuilding
anything. A new host's agent registers, its container comes up dormant, and it
begins receiving the live state sync; it becomes a restore candidate once its
storage capability probe passes and it can reach a PBS holding the backups
it would restore from. Removing a host is the
reverse, and is explicit — a host that is merely dark is a failure, not a
departure.

## Storage detection

What backs guest storage is a **per-host probed capability**, not a configured
one. The agent probes and reports; the active instance plans against what is
actually there.

Since backup and restore moved onto PBS (§4), the filesystem no longer decides
*how* data crosses hosts — PBS reads through QEMU dirty bitmaps for VMs and at
file level for containers, independent of the filesystem underneath. The probe
still matters for two things: whether a host's storage is healthy enough to be a
restore target, and where a PBS datastore may safely live.

### bcachefs has no send/recv, and that no longer matters

bcachefs snapshots are cheap and consistent but it has no `send`/`receive`.
When replication was going to be built on the filesystem, that was the central
constraint. With PBS doing the transfer above the filesystem, it is not a
constraint at all — which is one of the stronger arguments for PBS on an estate
that uses bcachefs.

### An out-of-tree storage module is a health check

Where guest storage needs a module that is not in the kernel (the `bcachefs` DKMS
module, for example, since bcachefs was dropped from mainline), a kernel update
whose DKMS build fails leaves a host that boots fine and has no storage.

Concord treats "the storage module resolves for the *running* kernel" as a
first-class host health signal, checked by the agent, because two decisions
depend on it:

- A host failing that check is **excluded as a migration or restore target**
  before it can be chosen, rather than being discovered mid-migration.
- A host failing it while holding guests is a **degraded host**, reported as
  such — this is exactly the "restore on any available machine" trigger, and
  "available" has to mean storage works, not just that the host answers.

Such a check belongs before staging a boot too; Concord makes it continuously.

## Subsystems

### 1. Inventory

Polls each host's `/api2/json/nodes/{node}/qemu` and `/lxc`, plus per-guest
config, status, and the agent's host capability report. The result is one full
picture of the estate — every host and every guest — held by the active instance
and streamed live to the dormant ones, so a promotion is instant and loses
nothing.

Everything else reads inventory, never the API directly, so a decision is always
made against one coherent snapshot rather than a half-refreshed estate.

### 2. Expected state and reconciliation

Each guest carries an *expected* power state, separate from its observed one.
The reconciler acts on the difference. This is what repairs the failed-backup
case: `vzdump` in stop mode powers a guest off, and a job that dies mid-run
never powers it back on. Concord sees `expected=running, observed=stopped, no
job holds a lease` and starts it.

A guest an operator stopped deliberately must not be restarted, so a manual
stop through Concord's own UI *changes* the expected state. A stop performed
outside Concord is ambiguous, and the reconciler treats an unexplained
transition as a report, not an action, until an operator resolves it.

### 3. Migration

`qm remote-migrate` and `pct remote-migrate` are PVE's supported path for
moving a guest between *unrelated* installations, over an API token and a
fingerprint. Concord orchestrates that call; it does not implement migration.

Preconditions checked before a migration is offered: the target's storage
capability probe passes, the target storage exists and has room, bridges named
in the guest's netdevs exist there, no passthrough PCI/USB device is attached,
and the guest is not already held by a lease. Failing any of these raises
`NotSupported` with the reason.

### 4. Backup and replication through PBS

Proxmox Backup Server is the backbone for every guest's data: incremental backup
driven by QEMU dirty bitmaps, chunk-level deduplication, verification, pruning,
and chunk-incremental sync between PBS instances. Concord orchestrates PBS; it
does not reimplement any of it.

#### No extra bare metal

PBS runs **as a guest on the PVE hosts Concord manages** — never on a dedicated
machine. That creates the one hazard this section exists to handle: a PBS
running on a host it protects can die with that host and take the backups with
it. So Concord enforces a single placement rule:

> **A guest's backups never exist only on the host that runs it.**

Every guest backs up to a PBS on a *different* host, and PBS instances sync to
each other, so every backup exists on at least two hosts. What that means at each
estate size:

| Hosts | PBS instances | Host-loss coverage |
| --- | --- | --- |
| 1 | 1 | none possible — backups protect against bad updates and corruption, not host loss |
| 2+ | 1 | every host is covered **except the PBS host's own guests**, reported as unprotected |
| 2+ | 2+ | every guest covered; backups cross hosts and are synced between PBS instances |

Two PBS instances is the recommended shape from two hosts up. One is a
supported, honestly reported partial state, not a silent gap.

#### Running PBS as a guest correctly

- **Datastore on host storage, not inside a guest disk.** The datastore is bind-
  mounted from host storage into the PBS guest, so chunks are not written
  through a second copy-on-write layer on top of a copy-on-write filesystem.
- **PBS is infrastructure, not a workload.** A PBS guest is never backed up into
  itself, is started before the guests that depend on it, and is excluded from
  placement moves that would break the cross-host rule.
- **Losing a PBS host is its own recovery case.** Because every backup was synced
  to another PBS, nothing is lost; Concord re-establishes a second PBS on a
  surviving host so coverage returns to two copies. It fences first — a PBS
  host that has only gone quiet must not be duplicated while it may still write.

#### Arbitrary data

Archives outside PBS, templates, ISOs, and arbitrary operator data go through
**Syncthing**, driven by its REST API. That is what Syncthing is correct for, and
it keeps that job. Guest disks never go through it.

#### Cadence adapts to the guest, not to a schedule

One hour is the **maximum** interval, not the interval. Every guest is backed
up at least hourly; a guest that can afford to go more often, does.

Affordability is measured, not guessed. A PBS backup of a running VM reads
through its dirty bitmap, and every backup reports how much data actually
changed — so the cost of the *next* backup is known from the last one, for free.
Concord uses that number to place each guest on its own cadence:

- A **heavy-IO guest** produces a large delta each cycle. Backing it up more
  often would cost real bandwidth and IO for a modest RPO gain, so it stays at
  the hourly ceiling.
- A **quiet guest** produces almost nothing. Ten minutes of its delta is cheaper
  than one minute of the busy one's, so its interval is shortened and its RPO
  improves at no meaningful cost.

The estate holds a single backup budget, and cadence is allocated out of it
— so tightening a quiet guest never starves a busy one, and adding guests
degrades intervals gracefully instead of oversubscribing the link. A floor on
the interval stops a nearly-idle guest from backing up continuously, and the
resulting per-guest RPO is displayed, because a number the operator can see is
worth more than a policy they have to infer.

#### The budget is two controls, not one

Network and disk want different kinds of limit, and giving both the same
treatment is a common way to build something that either crawls or starves the
guests.

- **Network — a hard rate cap.** Predictable, easy to reason about, and the
  thing an operator actually wants to bound. The default is a fraction of the
  narrowest link on the backup and sync path, applied to PVE backup jobs and
  PBS sync jobs alike: **half of a 1GbE link (~50 MB/s)**,
  and **a quarter of 10GbE (~300 MB/s)**, floored at 30 MB/s. The fraction
  shrinks as the link grows because on a fast link the disks, not the wire,
  become the constraint — and because a 10GbE link is usually carrying guest
  traffic worth protecting.
- **Disk — a priority, not a cap.** Backup and PBS IO run at a low cgroup v2
  `io.weight`, so it consumes whatever the guests are not using and yields the
  instant they want it back. A fixed IO ceiling is the wrong instrument here:
  the correct number changes minute to minute with guest load, so any constant
  is either too low when the estate is idle or too high when it is not. A weight
  is self-correcting by construction.

#### Self-tuning is deferred, but its inputs are not

The intent is that Concord sets these itself — it can see the storage type from
the capability probe, the negotiated link speed from the agent, and the real
throughput it achieved on every cycle it has ever run. A heuristic is the right
end state and a poor thing to guess at early, so **the auto-tuner is deferred
until there is a fully functional beta** to measure against.

What is *not* deferred is the measurement. Link speed, device throughput,
achieved transfer rate, and per-backup delta size are recorded from the first
backup onward, so that when the heuristic is written it starts with a
history of the estate rather than with a blank slate and a fresh guess. Until
then the defaults above stand, and they are adjustable.

### 5. Placement

Sustained pressure on a host (CPU, memory, or IO, over a window, not an
instant) selects the guest whose migration relieves the most pressure for the
least transfer, and proposes it. Policy decides whether a proposal executes
automatically or waits for a human. A host failing its capability probe is
never a candidate.

### 6. Backups

Concord owns every guest's backup schedule, driving PVE backup jobs into PBS,
and records each job's outcome — including a job that died — so the reconciler
(§2) can repair the guests a failed job left powered off. Verification and
pruning run as PBS jobs that Concord schedules and reads back; the one rule
Concord adds on top is that the last verified backup of a guest is never pruned,
whatever the policy says.

### 7. OCI guest updates

Pull the new image, **snapshot the guest**, diff the declared volume and bind
layout against the running one, apply the migration, start, health-check, and
roll back to the snapshot on failure. The snapshot is a hard precondition: a
guest that cannot be snapshotted is not auto-updated.

## Design review

Findings about the original design intent, in order of how much they change the
build. That intent was an earlier private note, not published here; "the design"
below means that note.

**1. Syncthing cannot back guest-disk replication.** The design names Syncthing
as the replication layer. Syncthing converges eventually and has no notion of a
consistent point in time across a file set, so a running guest's disk image
synced through it is not reliably bootable. Guest data goes through PBS (§4);
Syncthing keeps its place in the design for the arbitrary data it is correct
for.

**2. Live migration already exists and does not need a cluster.**
`remote-migrate` (PVE 7.3+) does cross-installation live migration over an API
token. This is much better than the alternative — orchestrating QMP and NBD
drive-mirror by hand — and it is Proxmox's own supported code path, which also
disposes of most of the licence question.

**3. Replication should not be built; Proxmox already ships it.** An earlier
draft planned bespoke block-level replication over dirty bitmaps, forced by
bcachefs having no send/recv. That would have been a large, risky rebuild of
Proxmox Backup Server. PBS does dirty-bitmap incrementals, deduplication,
verification, and incremental sync between instances, sits above the filesystem
so bcachefs stops mattering, and is Proxmox's own AGPL component. It runs as a
guest on the managed hosts — no extra bare metal — under a cross-host placement
rule so it cannot take the backups down with the host it lives on (§4). The
cost is recovery time: restoring is slower than booting a warm replica, which
live restore largely closes for VMs but not for containers.

**4. The design does not say what makes a restore safe.** Restarting a lost
host's guests elsewhere is only safe if the original is definitely not running.
Resolved by self-fencing on a deadline, backed by the hardware watchdog, rather
than by voting — which means it works on two hosts, with everything on the
hypervisors and no witness. See [Recovery](#recovery).

**5. "Automatically fixing file layouts and binds" is the riskiest sentence in
the design.** Automated remediation that moves an operator's data is how data
is lost. Constrained to snapshot-first, roll-back-on-failure, and never
destructive without a verified snapshot (§7).

**6. Licence posture is clean, but trademark is separate.** Driving the public
HTTP API creates no derivative work; AGPL-3.0-or-later matches PVE's own
licence and covers the network-served UI. Proxmox's *marks* are a separate
question from its licence — the UI must not present itself as Proxmox.

**7. "All the abilities of the PVE web UI at 8006" is unbounded.** Console,
storage management, firewall, users and permissions, the task log, and the
shell are each a project. Concord listens on 8010 beside pveproxy rather than
replacing it, and grows its UI by need instead of by parity.

## Open questions

- What fence deadline? It is the floor on how long a restore takes, so it
  trades recovery speed against tolerance for a brief network blip.
- Is `/dev/watchdog` available and free? PVE HA claims it when enabled, and two
  things cannot pet the same watchdog; a host may also have only `softdog`,
  which is software and cannot fence a wedged kernel.
- Which interface carries replication? The rate cap is a fraction of the
  narrowest link on that path, so it needs to know the path.
- Where do credentials live? An API token per host, stored — but stored where,
  and unlocked how, given every instance must come up unattended?
  *Settled for now, with a known cost (CON-2):* token secrets live in a TOML
  file separate from the configuration, refused unless it is a regular file with
  no group or other permissions, or in per-host environment variables. Nothing
  is encrypted at rest. An instance that restarts with nobody present needs the
  unlocking key to hand, and a key readable by the same container protects the
  secret from nothing that can read that container. So whoever controls a
  container that holds a secret, its backups, or the host under it has the
  token; what limits the damage is the token's own privileges, and giving each
  container only the secrets it uses. How secrets reach containers on other
  hosts is still open.
- Is the agent allowed to act on anything other than Concord's own container?
- Does a Concord container get restarted on a surviving host too, or is one
  per surviving host already enough?
