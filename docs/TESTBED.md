# Nested-PVE test estate

> **If networking breaks** (the host loses its LAN, SSH or web UI after an SDN apply), from a
> local console or any shell that still works:
>
> ```
> sudo /var/lib/concord-nest/bin/net-rollback.sh --execute
> ```
>
> Always that path, never a copy in a worktree: `net-snapshot.sh` installs root-owned copies of the
> rollback tooling there (with a `SHA256SUMS` the script checks on start), so `sudo` never runs
> files an unprivileged account can edit, and the rollback survives the worktree being deleted or its
> filesystem being unavailable. Those copies come from `/root/concord-nest-stage/`, which you filled
> and verified first (see "Operator runbook").
>
> It needs no network and no PVE API. It restores the state saved by `net-snapshot.sh`, tries
> every step even if one fails, prints PASS or FAIL for every check and keeps a log in
> `/var/lib/concord-nest/rollback-<UTC>.log`. Run it without `--execute` first to see what it
> would do. A snapshot from the current boot must exist (see "Build order").
>
> It does **not** touch the host guard, `/etc/network/interfaces` or `/etc/frr/frr.conf` unless
> asked: it shows a `diff -u` of the last two, and `--restore-interfaces`, `--restore-frr` and
> `--remove-guard` (only if the snapshot recorded the guard as absent) opt in. It always prints the
> `diff -u` of `/etc/pve/sdn`, and leaves that directory alone (a FAILED step) if it holds SDN objects
> that are neither ours (`cnestz`, `cnest`, `cnestz-10.99.0.0-24`) nor in the snapshot, unless
> `--restore-sdn` is given.
>
> **Which snapshot.** Roll back to a snapshot taken *before* the estate network existed
> (`estate_present=0`, listed by the rollback and printed by `net-snapshot.sh`). A snapshot
> taken while cnest exists (`estate_present=1`, for example one taken after a reboot of a built
> estate) restores *to* "estate built": it keeps cnest. Choose another with `--snapshot DIR`.

Two or three real Proxmox VE 9 nodes running as VMs on one host, with scratch
storage and a private network, so that Concord's destructive paths (OCI
recreate, live migration, host loss and self-fencing) can be proven without
touching a production guest.

The estate is built by `build.sh`, `teardown.sh` and `darken.sh` in
`testbed/nested/` (API token, no root). Three more scripts protect the host and
need root: `net-snapshot.sh`, `net-rollback.sh` and `host-guard.sh`. A dashboard,
nestview (CT 9004), is described in `testbed/nestview/README.md`.

## Site settings

Everything specific to your host lives in `testbed/site.env`, which is gitignored:

```
cp testbed/site.env.example testbed/site.env && chmod 600 testbed/site.env
```

Fill in every key. `CONCORD_SITE_ENV=/path` points the scripts at another file. The file is
parsed, never sourced, and accepts only the documented keys: it cannot run code and cannot change
a safety constant (VMID range, pool, names, identity markers, all `readonly` in `lib.sh`). The
scripts stop with a message naming the key when a value is missing, malformed, or still the
example's placeholder. The file must be yours and not writable by group or others.

The root-run scripts (`net-snapshot.sh`, `net-rollback.sh`, `host-guard.sh`) never read it. They
need no site value: they work from the running host's own state and from constants in `lib.sh`.

The subnet (10.99.0.0/24), the VMIDs (9001-9004) and the object names are fixed defaults. Check
that they are free on your host before building. The scripts refuse to touch an existing guest, SDN
object, storage, pool or user that holds one of them. They do not look for 10.99.0.0/24 in use outside
SDN (a route, a bridge, another site), so check that yourself.

`CON-48` and `CON-51` in comments and descriptions are part of the identity markers the guards
compare (`lib.sh`), not references to look up; changing one orphans an estate built before.

## What the estate is

| Thing | Value |
|---|---|
| Host | one standalone PVE 9 host (not clustered), named in `site.env`; developed against PVE 9.2 |
| Nodes | VMIDs 9001-9003 = `nest1`-`nest3`, pool `concord-nest`, tag `concord-nest` |
| Per node | 2 vCPU (`cpu: host`, nested KVM is on), 7 GiB RAM, 64 GB qcow2 disk, no ballooning, `onboot=0` |
| Watchdog | `watchdog: model=i6300esb,action=reset` on every node: an emulated hardware watchdog, because a host may have only softdog |
| Storage | directory storage `concord-nest` at `<STORAGE_MOUNTPOINT>/concord-nest`, content `images,iso,import,rootdir`, restricted to that node, `is_mountpoint=<STORAGE_MOUNTPOINT>` (goes offline instead of filling the root disk if that is not mounted). `rootdir` is for CT 9004 (nestview). A storage built without it has `images,iso,import`: `build.sh` accepts that set as it is and does not add `rootdir`; the nestview deploy does (`testbed/nestview/README.md`, step 0) |
| Network | SDN **simple** zone `cnestz`, vnet `cnest`, subnet 10.99.0.0/24, gateway 10.99.0.1 on the host, SNAT on. No DHCP. nest1=10.99.0.11, nest2=.12, nest3=.13 |
| Base OS | Debian 13 genericcloud amd64, build 20261111-2659, pinned by URL and SHA512 (see `lib.sh`), imported with `import-from` |
| Provisioning | cloud-init built-in fields only: user `debian`, SSH key, static `ipconfig0`, nameservers 1.1.1.1 and 9.9.9.9, search domain `concord.test` (without it PVE copies the host's own search domain). No snippets (they cannot be uploaded through the API) |
| PVE install | `install-pve.sh` inside each node, following the Proxmox wiki page "Install Proxmox VE on Debian 13 Trixie" |
| API identity | user `concord@pve`, token `concord@pve!nest` (privilege separation on), for the test harness |

Names: `cnest` is the vnet. The zone is `cnestz` because SDN ids are 2-8
alphanumerics and a zone and vnet sharing one name invites confusion in the ACL
path (`/sdn/zones/cnestz/cnest`).

The nodes stay **standalone**, matching Concord's target (standalone hosts,
Concord supplies the cluster-like behaviour). They are not joined into a PVE
cluster. 

**Every VM or CT these scripts create carries its IPs and ports in its Proxmox Notes (the
`description` key).** `build.sh` writes them when it creates a node (it leaves an
existing node's notes alone); the nestview deploy writes CT 9004's in its step 4. Nothing guards on
that text beyond nestview's first-line marker.

Inside each node: the only storage is `local`, a directory on
the node's 64 GB disk with about 55 GiB free after the install. root@pam has a
password, so each node's own GUI at `https://10.99.0.1x:8006` can be logged into from the host (see
"Verify the estate"). SSH stays key-only.

**nest3.** `build.sh` creates nest3 but, by default, starts and installs only nest1 and nest2
(steps 8 and 9). To add nest3, start it and run `install-pve.sh` the way step 9 does it: copy the
script and the root password file to `/tmp` over SSH as `debian`, run `sudo bash /tmp/install-pve.sh
--hostname nest3 --ip 10.99.0.13 --gateway 10.99.0.1 --dns '1.1.1.1 9.9.9.9' --lan-probe HOST_LAN_IP
--root-password-file /tmp/concord-nest-root-password`, remove the password file, wait for the reboot
after each exit 10, repeat until exit 0 (three rounds). First confirm on the host that the isolation
check can fail: `HOST_LAN_IP` is the host's own LAN address (`ip -4 -o addr`; not on `lo`, not in
10.99.0.0/24) and `timeout 5 bash -c 'exec 3<>/dev/tcp/HOST_LAN_IP/22'` succeeds there. `build.sh`
checks this itself.

### Dry-run default and the guards

`build.sh` and `teardown.sh` do nothing but GET unless given `--execute`. In
dry-run they print every write as `DRY-RUN  METHOD /path params`. Both refuse
to proceed (before writing anything) when:

- a VMID in 9001-9003 exists and is not this estate's guest of that number
  (name, pool membership, tag and NIC bridge must all match);
- storage `concord-nest`, zone `cnestz`, vnet `cnest`, subnet, pool
  `concord-nest` or user `concord@pve` exists with a different config. A
  matching one is accepted and skipped, which is what makes a re-run safe (for the storage, the
  content set without `rootdir` also matches);
- (teardown only) VMID 9004 exists and is not nestview's CT, or nestview's volumes are not all on
  `concord-nest` (see "Tear down and rebuild");
- other SDN changes are already pending (an apply would apply them too):
  zones, vnets, other vnets' subnets, controllers and fabrics are all checked;
- a host network edit is staged (`GET /nodes/<node>/network` has `changes`, or
  `/etc/network/interfaces.new` exists). The SDN apply forks
  `pvesh set /nodes/<node>/network`, which renames that file over
  `/etc/network/interfaces` and runs `ifreload -a`, so it would apply the
  staged edit, `vmbr0` included;
- the token and its secret file disagree (PVE shows the secret once; the file
  is never overwritten, and a token without a file means teardown first);
- the API token in use lacks admin rights, or the endpoint is not a standalone
  node with the name in `site.env`.

All writes go through `api_write` in `lib.sh`, with one exception: the token
POST in build.sh step 5, which goes straight to `pve.sh` so the one-time secret
never reaches a log. They never call anything under `/cluster/firewall` except
a GET of its options, never touch `vmbr0`, other storages, other guests or other VMIDs (teardown's
one exception is a verified CT 9004), and
`darken.sh` is limited to 9001-9003 in code.

## Prerequisites

- Run on the host itself (the install step SSHes to 10.99.0.0/24, which only the host
  routes). Everything else could run anywhere that reaches the API.
- `bash`, `curl`, `jq`, `openssl`, `ssh`, `ssh-keygen`, `scp`.
- An administrator-capable API token in a 0600 file (`PVE_TOKEN_FILE`), holding one line,
  `USER@REALM!TOKENID=SECRET`. `pve.sh` sends it only over a connection pinned to
  `PVE_FINGERPRINT`, never on a command line. Needs Sys.Modify,
  Datastore.Allocate, SDN.Allocate, Permissions.Modify, User.Modify,
  VM.Allocate, Pool.Allocate on `/`. The build checks this first.
- A free directory name `<STORAGE_MOUNTPOINT>/concord-nest` (the API creates it).
- Outbound HTTPS from the host to cloud.debian.org (image download), and from the
  nodes to download.proxmox.com, enterprise.proxmox.com and the Debian mirrors.
- A directory for secrets (`SECRETS_DIR`). The scripts create, in that directory:
  `concord-nest_ed25519(.pub)`, `concord-nest-token.txt` (0600, content
  `concord@pve!nest=<secret>`) and `concord-nest_known_hosts`.
- A one-line 0600 file with the nested nodes' root password (`NODE_ROOT_PASSWORD_FILE`). There is
  no default password; the build refuses without it.

## Build order

`build.sh` and `teardown.sh` use only the API token and never need root. The scripts that need root
are run with `sudo`, always from a root-owned copy (below).

**Root never runs a file from the worktree.** The worktree is writable by an unprivileged account,
and `net-snapshot.sh` sources `lib.sh` as root and installs the other scripts as the "trusted"
rollback. So the first root step stages the four root-run files (`net-snapshot.sh`,
`net-rollback.sh`, `host-guard.sh`, `lib.sh`) into a root-owned 0700 directory and checks them
there against sha256 values obtained independently of the worktree (see "Where the hashes come
from"). `net-snapshot.sh` also refuses to run as root unless its
directory and those four files are root-owned and not group- or world-writable
(`--i-accept-user-writable-source` skips that check; do not use it, because root would then run
whatever the files hold at that moment and install it as the rollback).

```
./build.sh                                                  # 1. dry run, read the output
(stage and verify, "Operator runbook" steps 1-2)            # 2. copy the four files to /root/concord-nest-stage, check their hashes
sudo /root/concord-nest-stage/net-snapshot.sh               # 3. snapshot of the host network, this boot only
sudo /var/lib/concord-nest/bin/host-guard.sh install        # 4. host guard; blocks nodes from the LAN
./build.sh --execute                                        # 5. build; refuses without the guard
./build.sh --execute --yes-apply-sdn                        #    (the same, and the SDN apply; needs the snapshot)
```

- Step 3 refuses to run unless no host network edit is staged and
  `ifquery --check -a` passes on every line, and unless it can read the iptables SNAT and CT
  counts (it waits for a held xtables lock, then refuses; a count it cannot read is never
  recorded as 0). It writes
  `/var/lib/concord-nest/net-snapshot-<UTC>/` (mode 0700) and a `latest` link,
  and installs root-owned copies of `net-rollback.sh`, `lib.sh` and `host-guard.sh`
  with a `SHA256SUMS` into `/var/lib/concord-nest/bin/` (the hashes are printed and
  recorded in the snapshot's `meta`). If the snapshot
  already contains the estate network it says so loudly (`estate_present=1`).
  Because the directory is 0700 and `build.sh` is not root, it also writes a
  world-readable `net-snapshot-<UTC>.boot_id` beside it; `--yes-apply-sdn`
  needs one whose boot id equals the current boot's (ifdown relies on
  `/run/network` state, which lasts one boot). `teardown.sh`'s SDN apply has
  the same gate.
- Step 4 is the host guard (below), installed from the root-owned copy that step 3 made. It comes
  after the snapshot, so the snapshot records `guard_installed=0`. That is harmless: the default
  rollback keeps the guard, and only an explicit `--remove-guard` would remove it. `build.sh` only
  **checks** for the guard: it warns loudly when absent and refuses `--execute` unless given
  `--accept-no-host-guard`.
- Immediately before the `PUT /cluster/sdn`, both scripts print the rollback
  command.
- Take a fresh snapshot after every reboot, and after every rollback.

`--yes-apply-sdn` is required only if SDN objects need applying. **The SDN
apply (`PUT /cluster/sdn`) reloads the host's network configuration** (`ifreload
-a`) and runs on the machine that carries the LAN. It should not disturb
`vmbr0` (ifupdown2 reloads only what changed), and the script refuses if any
host network edit is staged. What it does change (PVE 9.2 and
`ifupdown2`): it creates bridge `cnest` with 10.99.0.1/24, sets
`net.ipv4.conf.cnest.forwarding=1` (runtime only; it goes away with the
interface), and adds a SNAT rule `10.99.0.0/24 -o vmbr0` plus a raw CT rule.
The global `net.ipv4.ip_forward` stays 0. Do it when a brief blip is acceptable.

What step 5 does, in order, and what to expect (all lines are logged with a
timestamp; a real run also writes `~/.local/state/concord-nest/build-*.log`):

1. `1/9` generate the local keypair (skipped if present).
2. `2/9` create storage `concord-nest`.
3. `3/9` create zone, vnet and subnet (pending, not live yet).
4. `4/9` SDN apply; waits until `/nodes/<node>/sdn/zones` reports `cnestz`
   `available`. Expected: `zone cnestz is available`.
5. `5/9` pool, user, token, ACLs. Expected: `token written to ... (mode 600)`.
   The secret is never printed or logged.
6. `6/9` download the image into `concord-nest` (checksum-verified by PVE).
   Expected: `task ok: UPID:...`. About 330 MB.
7. `7/9` create VMs 9001-9003 (disk imported, then resized to 64G).
8. `8/9` start nest1 and nest2.
9. `9/9` wait for SSH, copy `install-pve.sh`, run it. Each node reboots twice
   (into the PVE kernel; then after proxmox-ve and the network change) and the
   script re-runs after each. Expected last lines per node:
   `pve-manager/9.x.x ...`, `bridge: 10.99.0.11/24`, `watchdog: /dev/watchdog
   present, identity: i6300ESB timer`, `isolation: LAN and host services
   unreachable (ok)`, `ssh: key-only; the root password is not accepted over SSH (ok)`,
   `internet: reachable (ok)`, `apt: apt-get update has no errors (ok)`, `nest1: install complete`.
   Installing `proxmox-ve` adds `/etc/apt/sources.list.d/pve-enterprise.sources`, a pve-manager
   conffile for `https://enterprise.proxmox.com/debian/pve`, which answers 401 without a
   subscription, so every `apt-get update` ended in `E:` lines. The script adds `Enabled: no`
   (sources.list(5)) to each stanza of any `*.sources` file whose URIs name enterprise.proxmox.com,
   right after step 4 and again at the start of every final round, so nodes installed before the
   step existed heal on their next run. It edits rather than deletes, and APT's `--force-confold` keeps the
   edit when pve-manager ships a new version of the file. The final round then fails on any `E:`
   line from `apt-get update`.
   `install-pve.sh` is copied to each node on every round, because `/tmp` is a
   tmpfs on Debian 13 and is empty after each reboot.
   Expect 15-25 minutes per node (they install one after the other) on a normal link, and
   hours on a slow mirror (Stage B fetches about 450 MB).
   The SSH sessions send a keepalive every 15 s (`ServerAliveInterval`), and the node's ruleset lets
   sshd's non-SYN packets to 10.99.0.1 out: loading the ruleset mid-session used to stall the
   session that loaded it. A session that dies anyway ends with exit 255 after 2 minutes of silence,
   and build.sh stops without retrying, because the script may still be running in the node. Check
   that it has finished (`pgrep -f install-pve.sh` over SSH), then re-run `build.sh --execute`.
   The kernel is installed with `--no-install-recommends`: on the Debian cloud image the
   Proxmox kernel recommends `grub-pc`, which aborts without a configured install device (the
   image boots BIOS and manages GRUB through `grub-cloud-amd64`). A re-run purges a
   half-configured `grub-pc` left by such a failure. That purge deletes `/etc/default/grub`
   (grub-cloud-amd64's file, with the serial console settings), so the script saves a copy to
   `/var/lib/concord-nest/default-grub.saved` on every pass and restores it after the purge;
   it stops if the file is gone and no copy exists.
   Before the second reboot the script pins the uplink's name to `nic0` with
   `/usr/local/lib/systemd/network/50-pmx-nic0.link` (MAC match; the same file PVE 9's
   `pve-network-interface-pinning` writes) and bridges `nic0` on vmbr0. The image's `eth0` name
   comes only from netplan, which the script removes, so without the pin the next boot would call
   the NIC `ens18` and strand the node. It then asks udev (`udevadm test-builtin -a add
   net_setup_link`) what the NIC will be called after the reboot and stops before rebooting
   unless the answer is `nic0`. It also sets `WATCHDOG_MODULE=i6300esb` in
   `/etc/default/pve-ha-manager`, so watchdog-mux loads the i6300esb (proxmox-kernel blacklists
   it, so nothing else would) instead of softdog. The final round fails unless vmbr0 has `nic0`
   as a port and `/dev/watchdog` is the i6300esb.
   Before the reboot the generated `/etc/network/interfaces` is checked with
   `ifup --syntax-check --all --interfaces <copy>`, where the copy leaves out exactly the line
   `bridge-fd 0`. ifupdown2's syntax check declares `bridge-fd` as 2-255 and rejects that line,
   although it is what PVE itself writes for every STP-off bridge and a real `ifup`/`ifreload`
   accepts it. Any other `bridge-fd` value is still checked. The final round waits up to
   2 minutes for `pve-cluster`, `pvedaemon`, `pveproxy` and `watchdog-mux` to become active.
   Installing `proxmox-ve` always leaves a staged `/etc/network/interfaces.new`: ifupdown2's
   postinst (first install) rewrites the interfaces file through PVE's writer, which writes the
   `.new` shadow file, and `pvenetcommit.service` moves it over `/etc/network/interfaces` at the
   next boot. That would replace the script's vmbr0 config and strand the node, so Stage B
   deletes `interfaces.new` before writing `interfaces`. Stage B also disables cloud-init
   (`/etc/cloud/cloud-init.disabled`): PVE's cloud-init user-data sets `manage_etc_hosts: true`,
   which outranks the image-side setting, so every boot rewrote `/etc/hosts` to
   `127.0.1.1 nest1` and pve-cluster could not start. The last gate before the reboot refuses
   while `interfaces.new` exists, if `/etc/network/interfaces` differs from what the script
   wrote, if cloud-init is not disabled, or if the node name does not resolve to its address.
   The final round checks the name resolution too, and identifies the watchdog by
   `identity` = `i6300ESB timer`, the i6300esb module in use (refcnt at least 1, or the PCI
   device bound to the `i6300ESB timer` driver) and no softdog loaded. It does not read
   `watchdog0/device`, which the i6300esb does not have.

Options: `--no-install` stops after the VMs boot; `--no-start` does not start
any VM. A failed or interrupted run is safe to repeat.

### Verify the estate

From the host:

```
ssh -i "$SECRETS_DIR/concord-nest_ed25519" \
    -o UserKnownHostsFile="$SECRETS_DIR/concord-nest_known_hosts" \
    debian@10.99.0.11 'sudo pveversion; sudo systemctl is-active pveproxy; ls -l /dev/watchdog'
```

Each node's own web UI is at `https://10.99.0.11:8006` (`.12`, `.13`) from the host. Log in as
`root@pam` (realm "Linux PAM") with the password in `NODE_ROOT_PASSWORD_FILE`. `install-pve.sh`
sets it on every round from `--root-password-file` (required), which `build.sh` copies to the
node's `/tmp` next to the script and deletes in the same SSH session. It goes to
`chpasswd` on stdin, never on a command line. SSH is still key-only: the final round fails unless
`sshd -T` shows `passwordauthentication no`, `kbdinteractiveauthentication no` and a
`permitrootlogin` that refuses passwords.

Who can reach the node GUIs (a known, accepted exposure for a test estate):

- **The host**, directly: its route to 10.99.0.0/24 is `cnest`, source 10.99.0.1, and the node
  tables accept replies to connections the host opened.
- **A LAN machine that adds a route to 10.99.0.0/24 via the host**, if the host forwards on
  `vmbr0` (check `net.ipv4.conf.vmbr0.forwarding`). The in-node tables filter only what a node
  sends, not what it receives, and the host guard filters only traffic coming in from `cnest`. Its
  raw-table drops also hit the node's replies to a private LAN address, so while the guard's rules
  are loaded a TCP session (the GUI) should not complete; the request packets still reach the node.
  That reading is from the rule text, not tested from a LAN machine. Without the guard the GUI may
  be reachable from the LAN, so do not use a trivial root password.
- Anyone else only if something routes 10.99.0.0/24 to them.

Stage B disables cloud-init in the node, so from then on a later `qm set --sshkeys`, `--ipconfig0`
or `--nameserver` on the host, or a disk resize, no longer reaches the node (no key rotation, no
address change, no growpart). Make such changes inside the node over SSH or the guest agent.

With the root password a console login (`qm terminal`) should work on a node that has had its final
round, but that has not been tried. The QEMU guest agent is a way back in
while the node is booted, even with no network (`agent=1`, and `qemu-guest-agent` is installed in
Stage A). Through the host's API (`testbed/nested/pve.sh`):

- read a file: `GET /nodes/<node>/qemu/<vmid>/agent/file-read?file=/etc/network/interfaces`;
- run a command as root: `POST /nodes/<node>/qemu/<vmid>/agent/exec` with one `command` value per
  argument, then `GET .../agent/exec-status?pid=<pid>`.

For example, to make SSH work again for diagnosis, at runtime only (gone at the next boot), use
the NIC name the node has now (`ens18` without the pin, `nic0` with it):
`ip link set ens18 up; ip addr add 10.99.0.11/24 dev ens18; ip route add default via 10.99.0.1`.
`agent/exec` is a write. A node whose disk is
broken is still rebuilt (`teardown.sh`, then `build.sh`), not repaired; a node stopped short in
Stage B is finished by re-running `build.sh --execute` once SSH works.

## Operator runbook

Every path run as root is in `/root/concord-nest-stage/` or `/var/lib/concord-nest/bin/`, both
root-owned.

Use a **separate local terminal**, not one that runs automation or a coding agent under your uid.
sudo caches the credential (15 minutes per tty by default), so a sudo run in such a terminal can be
reused by the automation without a password. Nothing else should be editing the scripts while you do
steps 1-6. Times shown as `HH:MM:SS` and `<UTC>` vary.

This is a defence against accidental or concurrent edits to the four scripts. It is not a defence
against a hostile process running as your uid: `~/.bashrc`, `PATH` and shell functions are
writable by that uid too, and nothing short of a separate account can cover that.

**Where the hashes come from.** From a copy you reviewed or trust, read independently of the
worktree: for example `testbed/nested/SHA256SUMS` as shown on GitHub at the commit you reviewed.
Never from the worktree itself: whatever can edit a script there can edit its `SHA256SUMS` and make
the check pass. The block below holds placeholders; replace each `<...>` with the 64 hex characters.

1. **Stage.** Absolute paths, no `cd`:
   ```
   T=/path/to/concord/testbed/nested
   sudo install -d -m 0700 -o root -g root /root/concord-nest-stage
   sudo install -m 0755 -o root -g root "$T/net-snapshot.sh" "$T/net-rollback.sh" "$T/host-guard.sh" /root/concord-nest-stage/
   sudo install -m 0644 -o root -g root "$T/lib.sh" /root/concord-nest-stage/
   ```
   Expect no output. `SHA256SUMS` is not staged: `net-snapshot.sh` never reads it from its own
   directory.
2. **Verify** against the trusted hashes. Paste the whole block, including the `EOF` line:
   ```
   sudo sha256sum -c - <<'EOF'
   <net-snapshot.sh trusted hash>  /root/concord-nest-stage/net-snapshot.sh
   <net-rollback.sh trusted hash>  /root/concord-nest-stage/net-rollback.sh
   <host-guard.sh trusted hash>  /root/concord-nest-stage/host-guard.sh
   <lib.sh trusted hash>  /root/concord-nest-stage/lib.sh
   EOF
   echo rc=$?
   ```
   Expect exactly:
   ```
   /root/concord-nest-stage/net-snapshot.sh: OK
   /root/concord-nest-stage/net-rollback.sh: OK
   /root/concord-nest-stage/host-guard.sh: OK
   /root/concord-nest-stage/lib.sh: OK
   rc=0
   ```
   Any `FAILED`, or rc other than 0: stop. Optionally read what root will run, with the pager
   running as you, not as root (`sudo less` would give root's `!` and `v` escapes):
   ```
   sudo cat /root/concord-nest-stage/net-snapshot.sh /root/concord-nest-stage/lib.sh | less
   ```
3. **Snapshot**:
   ```
   sudo /root/concord-nest-stage/net-snapshot.sh; echo rc=$?
   ```
   Expect:
   ```
   HH:MM:SS gate ok: no staged edit, ifquery --check -a passes on every line
   HH:MM:SS snapshot written: /var/lib/concord-nest/net-snapshot-<UTC> (mode 0700)
   HH:MM:SS   boot_id            <this boot's id>
   HH:MM:SS   interfaces         <n> lines; interfaces.d/sdn existed: 0
   HH:MM:SS   cnest existed      0
   HH:MM:SS   ip_forward         0
   HH:MM:SS   SNAT / CT rules    0 / 0
   HH:MM:SS   /etc/pve/sdn       2 files
   HH:MM:SS   frr                enabled=disabled active=inactive
   HH:MM:SS   latest -> /var/lib/concord-nest/net-snapshot-<UTC>
   HH:MM:SS   rollback tools     /var/lib/concord-nest/bin (root-owned) sha256:
   HH:MM:SS     <net-rollback.sh hash>  net-rollback.sh
   HH:MM:SS     <lib.sh hash>  lib.sh
   HH:MM:SS     <host-guard.sh hash>  host-guard.sh
   HH:MM:SS next: the host guard, if wanted: sudo /var/lib/concord-nest/bin/host-guard.sh install   (it goes after this snapshot, so the snapshot records guard_installed=0; harmless)
   HH:MM:SS rollback if networking breaks: sudo /var/lib/concord-nest/bin/net-rollback.sh --execute
   rc=0
   ```
   The three hashes equal the ones from step 2. There must be **no**
   `!!!! WARNING ... INCLUDES the estate network` line. Any `ABORT`, or rc other than 0: stop (an
   xtables-lock ABORT is safe to retry). An `ABORT: running as root from files an unprivileged
   account could have edited` means step 1 was skipped; do not use
   `--i-accept-user-writable-source`.
4. **No-op proof** against the unchanged host (changes nothing):
   ```
   sudo /var/lib/concord-nest/bin/net-rollback.sh --dry-run; echo rc=$?
   ```
   Expect, in this order (the three tailscale lines only on a host that runs Tailscale):
   ```
   HH:MM:SS MODE: dry run (nothing is changed)
   HH:MM:SS snapshot: /var/lib/concord-nest/net-snapshot-<UTC>
   HH:MM:SS log file: /var/lib/concord-nest/rollback-<UTC>.log
   HH:MM:SS this snapshot has estate_present=0 (0 = taken without the estate network). Snapshots here (--snapshot DIR):
   HH:MM:SS     net-snapshot-<UTC>  estate_present=0  <- selected
   HH:MM:SS ---- 1/7 ifdown cnest
   HH:MM:SS cnest is not present
   HH:MM:SS ---- 2/7 iptables rules (loop-delete; never iptables-restore)
   HH:MM:SS DRY-RUN  delete 'iptables -w 10 -t nat -D POSTROUTING -s 10.99.0.0/24 -o vmbr0 -j SNAT --to-source HOST_LAN_IP' while count > 0 (now 0)
   HH:MM:SS DRY-RUN  delete 'iptables -w 10 -t raw -D PREROUTING -i fwbr+ -j CT --zone 1' while count > 0 (now 0)
   HH:MM:SS host guard left in place (--remove-guard removes it only if the snapshot recorded it absent)
   HH:MM:SS ---- 3/7 /etc/pve/sdn
   HH:MM:SS ---- 4/7 /etc/network/interfaces and interfaces.d/sdn
   HH:MM:SS ---- 5/7 ifreload -a
   HH:MM:SS no network file or link changed and ifquery --check -a passes: ifreload -a skipped
   HH:MM:SS ---- 6/7 net.ipv4.ip_forward (written only if it differs from the snapshot)
   HH:MM:SS unchanged (0); not written
   HH:MM:SS ---- 7/7 wireguard and frr
   HH:MM:SS dnsmasq enabled state: now not-found, snapshot not-found (compared only)
   HH:MM:SS ---- post-rollback checks (dry run: state has NOT been rolled back, so FAIL here may be expected)
   HH:MM:SS PASS  vmbr0 keeps its snapshot addresses
   HH:MM:SS PASS  default route is as snapshotted
   HH:MM:SS PASS  gateway GATEWAY_IP answers ping
   HH:MM:SS         PING GATEWAY_IP ... / 1 packets transmitted, 1 received, 0% packet loss ... / rtt ...   (ping's own lines, indented)
   HH:MM:SS PASS  cnest is gone
   HH:MM:SS         Device "cnest" does not exist.
   HH:MM:SS PASS  interfaces.d/sdn is gone
   HH:MM:SS PASS  SNAT rule count is 0
   HH:MM:SS PASS  CT rule count is 0
   HH:MM:SS PASS  forwarding sysctls match the snapshot (cnest lines aside)
   HH:MM:SS PASS  ifquery --check -a passes on every line
   HH:MM:SS PASS  guest bridge ports from the snapshot are still on vmbr0
   HH:MM:SS PASS  tailscaled is active
   HH:MM:SS PASS  tailscale has an IPv4 address
   HH:MM:SS PASS  ip rule has lookup 52
   HH:MM:SS PASS  /etc/network/interfaces matches the snapshot
   HH:MM:SS PASS  /etc/pve/sdn matches the snapshot
   HH:MM:SS full log: /var/lib/concord-nest/rollback-<UTC>.log
   HH:MM:SS RESULT: all steps and checks passed
   rc=0
   ```
   Notes on that output:
   - The dnsmasq line repeats whatever `systemctl is-enabled dnsmasq` printed. On a host
     without it that is `not-found` on both sides.
   - Indented `INFO gone since snapshot: ...` lines under a PASS are fine; they appear if a guest
     stopped between steps 3 and 4.
   - Stop and report if you see any of: a `!!!!` line, a `WARNING` line, a `DRY-RUN` line in
     steps 1, 3 or 4, a `DRY-RUN  ifreload`, a `STEP FAILED`, any `FAIL`, or rc other than 0.
   - If no `RESULT:` line appears at all, run the same command again; it is read-only.
5. **Host guard** (from the root-owned copy):
   ```
   sudo /var/lib/concord-nest/bin/host-guard.sh install; echo rc=$?
   /var/lib/concord-nest/bin/host-guard.sh status
   ```
   Expect:
   ```
   installed /etc/network/if-up.d/concord-nest-guard
   cnest is not up yet: the rules will be applied when it comes up
   rc=0
   hook: installed (/etc/network/if-up.d/concord-nest-guard)
   cnest: absent
   rules: not checked (needs root)
   ```
   The snapshot from step 3 recorded `guard_installed=0`; that is harmless, because the rollback
   keeps the guard unless you pass `--remove-guard`.
6. **Drop the sudo credential**, then close this terminal:
   ```
   sudo -k
   ```
7. **Build**, with the admin token, never as root:
   ```
   cd /path/to/concord/testbed/nested || exit 1
   ./build.sh
   ./build.sh --execute --yes-apply-sdn
   ```
   - The dry run must show `host guard hook present: /etc/network/if-up.d/concord-nest-guard`. If
     you skipped step 5, it shows the WARNING banner instead, and the execute needs
     `--accept-no-host-guard`.
   - The execute must log `network snapshot for this boot: /var/lib/concord-nest/net-snapshot-<UTC>`.
   - Just before the `PUT /cluster/sdn` it prints `ROLLBACK if networking breaks (run on the host, works
     offline): sudo /var/lib/concord-nest/bin/net-rollback.sh --execute`.
8. **Rollback**, only if networking breaks. Local console, works offline:
   ```
   sudo /var/lib/concord-nest/bin/net-rollback.sh --dry-run
   sudo /var/lib/concord-nest/bin/net-rollback.sh --execute; echo rc=$?
   sudo -k
   ```
   - If `latest` is not the snapshot from step 3, add
     `--snapshot /var/lib/concord-nest/net-snapshot-<UTC>` with the `estate_present=0` snapshot
     from step 3.
   - Keep the printed log path.
   - A `STEP FAILED ... not ours` means SDN objects you made since step 3 are present. Read the
     diff; `--restore-sdn` deletes them.
   - Take a fresh snapshot (steps 1-3: re-stage only if the hashes changed) before any rebuild.

## Make a node go dark

```
./darken.sh kill    nest2     # hard stop, no shutdown: host loss
./darken.sh pause   nest2     # suspend in memory: frozen CPU and clock
./darken.sh sever   nest2     # NIC link_down=1: alive but unreachable
./darken.sh restore nest2     # undo any of the above
./darken.sh status  nest2
./darken.sh kill nest2 --dry-run
```

Takes a name or a VMID. Acts immediately unless `--dry-run`. Refuses anything
outside 9001-9003, and anything in range that is not this estate's guest.

How these map to the failure Concord must survive:

- `kill`: the node vanishes mid-write. This is the closest to power loss.
- `pause`: nothing runs, including the watchdog poll. QEMU's i6300esb timer is
  frozen with the VM, so a paused guest does **not** reset itself. Use `kill`
  or `sever` to rehearse fencing; `pause` rehearses "unresponsive but not
  dead". `/cluster/resources` shows a paused VM as `status: paused`, so `darken.sh`
  reads the power state from `status/current` instead (`status` running while the QEMU
  process exists, `qmpstatus` paused). `restore` resumes a paused VM and does not start it.
- `sever`: the guest keeps running, so whatever feeds its watchdog keeps running; this
  is the scenario where self-fencing (not the other host) must decide.

What each mode does by power state (`status`, then `qmpstatus`, from `status/current`):

| state | kill | pause | sever | restore |
|---|---|---|---|---|
| running / running | stop | suspend | link_down=1 | nothing to restore, unless severed |
| running / paused, suspended, prelaunch | stop | refuses | link_down=1 | resume, then relink if severed |
| running / anything else | refuses | refuses | refuses | refuses |
| stopped | refuses | refuses | link_down=1 at next start | start, then relink if severed |

- `prelaunch` counts as paused, as PVE's `vm_is_paused` does: a VM started paused
  (a vzdump of a stopped VM, a live-restore) is left there by an interrupted job.
  PVE's resume sends `cont` for it and `system_wakeup` for a guest in S3 (`suspended`).
- Any other QMP state of a live process (`io-error`, `internal-error`,
  `guest-panicked`, `shutdown`, or one QEMU adds later) is a fault that darken did not
  cause. Every mode except `status` refuses it and names the state, because a stop,
  `cont` or config change would hide the fault. Look at the VM by hand. `status`
  reports the state and changes nothing.
- `restore` says "nothing to restore" only when the VM is running with `qmpstatus`
  running and the NIC linked.

The watchdog is armed from boot on every node. PVE's `watchdog-mux` opens
`/dev/watchdog` (the i6300esb, via `WATCHDOG_MODULE` in `/etc/default/pve-ha-manager`)
and keeps it fed, exactly as on any PVE host, until Concord's agent takes over. A node whose
watchdog-mux dies is reset by QEMU (`action=reset`). To rehearse the hardware watchdog
actually firing, stop whatever feeds `/dev/watchdog` inside the node (watchdog-mux
today, Concord's agent once it exists); the VM then resets itself after the timeout.
With the i6300esb armed, a crash of watchdog-mux or more than about 10 s of vCPU starvation (for example, a host under heavy load) hard-resets the node VM; it reboots into the same config, and during a build this shows up as a failed SSH round.

## Resource budget

| | Per node | nest1+nest2 running | all three |
|---|---|---|---|
| RAM | 7 GiB | 14 GiB | 21 GiB |
| vCPU | 2 | 4 | 6 |
| Disk (virtual) | 64 GB | 128 GB | 192 GB |
| Disk (real, after install) | about 6-10 GB | 12-20 GB | 18-30 GB |

Nodes use
`balloon=0`, so the full 7 GiB is committed while a node runs. Nested guests
inside the nodes come out of the node's 7 GiB.

## Isolation: what it guarantees and what it does not

**The goal:** the estate must not be on the production network path, and a
bug in a destructive test must not reach a real guest or the LAN.

What actually isolates it:

1. **No layer-2 path.** The vnet's simple zone is a bare Linux bridge on
   the host with no physical port and not enslaved to `vmbr0`. No frame crosses
   between the nodes and the LAN. No DHCP, no dnsmasq, no DNS service.
2. **The datacenter firewall is not touched.** The scripts only ever GET
   `/cluster/firewall/options` and report it. Enabling it
   on a standalone host risks locking the operator out, so LAN isolation is not
   attempted that way.
3. **Host guard** (`host-guard.sh install`, root; the strong
   one, because it does not depend on the nodes). An ifupdown hook
   `/etc/network/if-up.d/concord-nest-guard` that does nothing unless
   `IFACE=cnest`, so it never edits `vmbr0` or `/etc/network/interfaces`:
   - raw-table PREROUTING drops from `cnest` to 192.168/16, 172.16/12,
     100.64/10 (CGNAT, used by Tailscale) and 169.254/16, and to 10/8 except 10.99.0.0/24.
     tailscaled cannot reach the raw table, so it cannot undo this, and the
     rules are checked before every insert, so `ifreload` does not stack them;
   - INPUT rejects NEW non-ICMP connections from `cnest` to the host (SSH from
     the host into the nodes still works, because the host starts those connections);
   - `ip6tables INPUT -i cnest -j DROP`.

   `host-guard.sh remove` loop-deletes the rules and removes the hook; `status`
   shows both; `install` fails unless all 7 rules are present afterwards. Every
   iptables call uses `-w 10` (legacy iptables otherwise exits at once when the
   xtables lock is held, which would leave the guard silently absent after a
   reboot). `net-rollback.sh` leaves the guard in place (its rules only match
   `-i cnest`, so they are inert once cnest is gone) unless `--remove-guard` is
   given and the snapshot recorded the guard as absent.
4. **Per-node nftables** (installed by `install-pve.sh`, persisted in
   `/etc/nftables.conf`), a guard against mistakes, not against root in the
   node:
   - `table inet concord_nest`: the node itself (output chain) and routed
     traffic (forward) may reach 10.99.0.0/16 and public addresses; traffic to
     10/8, 172.16/12, 192.168/16, 169.254/16 and 100.64/10 (except 10.99/16)
     is rejected. Traffic to 10.99.0.1, which is the host, is rejected except ICMP
     echo and replies to connections the host started. IPv6 is dropped except
     neighbour discovery and loopback.
   - `table bridge concord_nest`: guests **inside** a node are bridged on its
     `vmbr0`, and PVE sets `net.bridge.bridge-nf-call-iptables=0`, so the inet
     forward chain never sees them. This table (forward hook, priority -150)
     drops their frames to the same private ranges, drops IPv6 frames, and
     allows only ICMP to 10.99.0.1.
   - The install ends with a self-test. It asserts both tables are loaded,
     runs a positive control (download.proxmox.com:443 must connect), then
     checks that ports which really listen on the far side are unreachable:
     the host's LAN address:22, 10.99.0.1:22 and 10.99.0.1:8006.
5. **Scoped credentials.** `concord@pve!nest` can see and change only the pool,
   the `concord-nest` storage and the `cnest` vnet (below).

What it does **not** guarantee:

- **There is an L3 path.** The host is the gateway, with forwarding on for `cnest`
  and SNAT out `vmbr0`. Without the host guard and the in-node tables a node
  could reach the whole LAN and the internet, appearing as the host.
  With only the in-node tables, root in a node (and the harness has root there)
  can remove them. The in-node inet table does not cover nested guests; the
  bridge table is what covers them.
- **Without the host guard, the host is reachable** at 10.99.0.1 and its LAN address
  from a node unless the in-node tables are in place. A node before the
  nftables step of `install-pve.sh`, or built with `--no-install`, has no
  guard at all; the first boot has a window of a few minutes. `build.sh
  --execute` therefore refuses to run without the host guard unless
  `--accept-no-host-guard` is given.
- **IPv6.** `cnest` gets a link-local (fe80) address, and the host's sshd (`[::]:22`)
  and pveproxy (`*:8006`) listen on it, so there **is** an IPv6 path to the host's
  services from a node. The host guard's ip6tables rule and the in-node IPv6
  drops close it; without them it is open.
- **Forwarding is not global.** The SDN apply sets
  `net.ipv4.conf.cnest.forwarding=1` (runtime only, gone with the interface).
  `net.ipv4.ip_forward` is not changed. The only new routed path is cnest to `vmbr0` with SNAT. Writing `net.ipv4.ip_forward` would reset
  every interface's forwarding, vmbr0's included, so nothing here writes it.
- Packets from the nodes to the internet leave as the host. Anything that
  logs source addresses sees the host.
- Nested nodes share the host's CPU, memory and disk I/O. A runaway test can slow
  production guests on the host (resources are budgeted above, not capped by
  cgroup beyond the VM sizes).

## Credentials: roles and ACLs

Privilege separation is on, so the token's rights are the intersection of the
token's ACLs and the user's. The same grants are therefore set on **both**
`concord@pve` and `concord@pve!nest`:

| Path | Role | Privileges that matter |
|---|---|---|
| `/pool/concord-nest` | `PVEVMAdmin` | VM.Allocate (create/destroy), VM.Snapshot(.Rollback), VM.Migrate, VM.PowerMgmt, VM.Config.*, VM.Backup, VM.Console, VM.Audit |
| `/pool/concord-nest` | `PVEPoolUser` | Pool.Audit (to list the pool and its members) |
| `/storage/concord-nest` | `PVEDatastoreUser` | Datastore.AllocateSpace, Datastore.Audit (disks and snapshots; no storage config changes) |
| `/sdn/zones/cnestz/cnest` | `PVESDNUser` | SDN.Use, SDN.Audit (attach a NIC to the vnet; no changes to SDN) |

Why these and not larger: `PVEVMAdmin` is the smallest built-in role that
includes allocate, snapshot, migrate, power and config together. No role at `/`
and no `Sys.*`, `Pool.Allocate`, `Datastore.Allocate` or `Permissions.Modify`.
`VM.Allocate` is checked on `/pool/<pool>` when a VM is created into the pool,
so the pool ACL is enough. The token cannot download images
(`Datastore.AllocateTemplate` plus `Sys.AccessNetwork` are required); the build
does that with the admin token.

With `rootdir` on the storage (for nestview), the same grants
(VM.Allocate on the pool, Datastore.AllocateSpace on `concord-nest`) would also let the token
create containers in the pool, given a template it can read. nestview has no route that does
this. A container in the pool makes `teardown.sh` abort (an unknown pool member) rather than
remove it.

Note for a test harness: this identity governs the **outer** VMs (create, snapshot,
go-dark, restore the estate). Destroying and migrating guests **inside** the
nested estate goes through the nested nodes' own APIs, with credentials that
do not exist yet.

## Tear down and rebuild

```
./teardown.sh                                   # dry run
./teardown.sh --execute --yes-apply-sdn
./build.sh --execute --yes-apply-sdn            # rebuild from nothing
```

Teardown removes, in reverse order, exactly what the build made: CT 9004 (nestview) first, when it
exists, then VMs 9001-9003
(stopped, then destroyed with `purge=1`; it does not pass
`destroy-unreferenced-disks`, which would reach every enabled storage), the ACLs, token, user,
pool, subnet, vnet and zone (then an SDN apply), the imported image, the
storage definition, and the local token file, SSH keypair and known_hosts.
Guards: every object must match the build's config, the storage may hold only
the image and disks of VMIDs 9001-9003, the pool may hold only those VMs and
the storage; otherwise it aborts before changing anything.

CT 9004 is not created by `build.sh` and is in no pool, so teardown finds it by VMID. It is
removed only if it is an `lxc` on the configured node, in no pool, not a template, with hostname `nestview` and a
description whose first line is `nestview (CON-51): dashboard for the CON-48 nested estate`. Any
VMID 9004 that fails one of these aborts the teardown. It is stopped, then destroyed with
`purge=1&destroy-unreferenced-disks=1`. For a container, PVE frees with that flag every volume
owned by VMID 9004 on every enabled storage with `rootdir` content
(`PVE::LXC::destroy_lxc_container` -> `PVE::Storage::vdisk_list`). So teardown first requires
that the CT has no pending config change (the destroy frees volumes from both the current
config and its pending section), that its `rootfs`/`mpN`/`unusedN` in both the current and the
pending-merged config are all on `concord-nest`, that no other active rootdir storage holds a 9004
disk volume (content `images` or `rootdir`; nestview's vzdump backups are not freed and do not
count), and that no enabled rootdir storage is inactive. The storage check
accepts `concord-nest:9004/vm-9004-*` only when the CT passed all of that. nestview's local files
(deploy key, passphrase, its known_hosts) stay in the secret store.

Left in place: the empty directory `<STORAGE_MOUNTPOINT>/concord-nest` (no API can remove
a directory; remove it as root if wanted) and the installed `~/.local/state`
logs.

Faster than a full rebuild: stop a node, snapshot its disk (qcow2 on a
directory storage supports snapshots) once PVE is installed, and roll back
between destructive runs.

## What a build changes on the host

- Storage `concord-nest` and its directory.
- SDN simple zone `cnestz`, vnet `cnest`, subnet 10.99.0.0/24; SDN applied. Host effects of the
  apply: bridge `cnest` with 10.99.0.1/24, `net.ipv4.conf.cnest.forwarding=1` (runtime only), a SNAT
  rule and a raw CT rule (`/etc/network/interfaces.d/sdn`), `/etc/pve/sdn/*`, and possibly an empty
  `/etc/wireguard/proxmox/`.
- The host guard hook and its rules; `/root/concord-nest-stage/`; `/var/lib/concord-nest/`.
- Pool `concord-nest`, user `concord@pve` (no password), token `concord@pve!nest` (privsep=1) and the
  ACLs above; the base image; VMs 9001-9003.
- In `SECRETS_DIR`: the SSH keypair, the token file and known_hosts.

Not changed, by design: `vmbr0`, `/etc/network/interfaces`, other storages, other guests, the
datacenter and node firewalls, `/etc/pve/datacenter.cfg`.

## Lessons and limits

Learned from real builds on PVE 9.2 and from the PVE and ifupdown2 sources:

1. On a `?pending=1` SDN listing, an object not yet applied has every key except its identity under
   `.pending`; the scripts read both places. The subnet id for delete is `cnestz-10.99.0.0-24`.
2. An SDN apply also applies any staged host network edit (refused here), and re-runs `post-up`
   lines on every `ifreload`, which may stack duplicate SNAT/CT rules (the rollback loop-deletes
   them).
3. Debian prunes old cloud image builds; update the pin in `lib.sh` when the dated directory
   disappears. `install-pve.sh` aborts if Proxmox rotates its archive key.
4. proxmox-kernel blacklists the i6300esb driver, so it is loaded through watchdog-mux's
   `WATCHDOG_MODULE`. `watchdog0` sits under `/sys/devices/virtual` with no `device` link.
5. A TCP flow open before the node's ruleset loads stalls as soon as the node side sends, even with
   `nf_conntrack` loaded on the host: conntrack hooks are registered per netns only when a rule
   needs them. Keepalives, or the `tcp sport 22 tcp flags & syn == 0` rule, carry the flow over.
6. `/cluster/resources` shows a paused VM as `paused`; read power state from `status/current`.

Not proven: that `action=reset` resets only its own VM; the nodes' bridge table against real
nested-guest traffic; `net-rollback.sh --execute` after a broken apply on a real host; and
teardown's abort cases beyond stubbed responses. Watch a first `--execute`.

## Open questions

- Should the nested nodes be joined into a PVE cluster for a real quorum
  scenario? Concord targets standalone hosts, so the estate is standalone.
- How should the harness authenticate to the nested nodes? root@pam now has a
  password (for the GUI); whether the harness uses it or per-node API tokens,
  created over SSH as `debian` + `sudo`, is open.
