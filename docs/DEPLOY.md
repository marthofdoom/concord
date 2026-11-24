# Deploying Concord in a Proxmox container

One unprivileged LXC per PVE host, running the static `concord` binary under
OpenRC. The container needs 128 MB of RAM, one core and about 1 GB of disk.
Everything lives in `deploy/ct/`.

## Install from a release

Each GitHub release holds `concord-X-amd64.tar.xz` (the template), its
`.sha256`, `deploy.sh`, `concord.ct.example.toml`, a static `concordctl`, and
`SHA256SUMS` over all of them. Download them into one new directory that
only root can write to (for example `install -d -m 0700 /root/concord-X`), so
the files cannot change between the check and their use. Check before running
anything:

    cd /root/concord-X && sha256sum -c SHA256SUMS

Run as root only files that check passed: `deploy.sh` runs as root and so does
everything it calls. The checksums come from the same place as the files, so
they show the download is intact, not who published it. Downloads lose the
executable bit, so run `bash ./deploy.sh ...` (or `chmod +x deploy.sh` first).
Then continue with [Deploy](#deploy), using the files from that directory. The
host agent is deliberately not shipped yet. Maintainers:
[RELEASING.md](RELEASING.md).

## Build the template

On any Linux machine with `rustup`, `fakeroot`, `xz` and `curl` (no root):

    rustup target add x86_64-unknown-linux-musl
    deploy/ct/build-template.sh        # -> target/ct/concord-<version>-amd64.tar.xz

The C compiler for `ring` is `musl-gcc` when installed (`musl-tools`, as in
CI), otherwise plain `gcc`, which works for ring's C and assembly. Override
with `CC_x86_64_unknown_linux_musl`. CI builds the same template and uploads it
as the `concord-ct-template` artifact.

The template is Alpine 3.24's minirootfs plus a handful of apks (OpenRC,
ifupdown-ng, libcap, busybox's OpenRC scripts). Alpine publishes no LXC image
for this release, and the minirootfs has no init system, so the template adds
the pieces PVE's Alpine support expects. All of it is pinned by SHA-256 in
`deploy/ct/alpine.lock`, and the build fails on any mismatch. Alpine's mirror
keeps only the newest revision of each package, so a 404 means the pin needs a
bump: take the new file name and hash from the mirror's `APKINDEX` and the
package, and update the lock. The build is reproducible for a given commit.

What is inside: root is locked (no password), no SSH server, no setuid or
setgid file (the build fails if one appears), user `concord` (uid/gid 900, no
login shell), `/etc/concord` root:concord 0750, `/var/lib/concord` concord
0700, and the marker `/etc/concord-ct` that `deploy.sh` checks. Concord pins
host certificates by fingerprint, so it does not use a CA bundle.

## Deploy

Copy the template and `deploy.sh` to the PVE host, then, as root there:

    bash ./deploy.sh --vmid 9100 --storage local-lvm --bridge vmbr0 \
        --ip 192.0.2.50/24 --gateway 192.0.2.1 \
        --template concord-0.1.1-amd64.tar.xz

This also creates what Concord needs to read this host, and writes the config:

- The user `concord-monitor` in the `pve` realm (no password), the role
  `PVEAuditor` on `/` with propagate, and a token without privilege separation.
  An existing user is only used if this installer created it (its comment says
  so), is in no group and has no other permission.
- The pin: the SHA-256 fingerprint of the certificate `pveproxy` serves, which
  must also be the certificate file `pveproxy` uses.
- Before the container is created, the API has to answer through that pin and
  the token has to have `VM.Audit` on `/`. A token that sees too little would
  make guests look deleted. The check is repeated from the container's network.

`--name` is the host's name in Concord (default: the short hostname).
`--api-address` is the address the container uses to reach this host (default:
the bridge's IPv4 address, if it has exactly one). It must be an IPv4 address or
a DNS name; the port is 8006. If anything fails, the container, token,
permission and user this run created are removed.

Each installation has its own token, named after `--install ID` (default
`concord`) plus a random suffix. Give a second container its own ID, with every
command that takes one. If the installation already has a token here, the script
stops; `--rotate-token` creates a new one and removes the old one once the new
container is healthy (a container still using the old one loses access).

### With your own config

    bash ./deploy.sh --vmid 9100 --storage local-lvm --bridge vmbr0 \
        --ip 192.0.2.50/24 --gateway 192.0.2.1 \
        --config concord.toml --secrets secrets.toml \
        --template concord-0.1.1-amd64.tar.xz

Here nothing is created in PVE. Use `--ip dhcp` to take an address from DHCP,
and `--dry-run` to print every mutating command without running it. Start from `deploy/ct/concord.ct.example.toml`
(listen on all interfaces, `secrets_file = "secrets.toml"`, `users_file` and
`state_dir` under `/var/lib/concord`). The secrets file must be mode 0600 on the
host.

`deploy.sh` refuses a VMID that exists anywhere in the cluster, creates the
container (unprivileged, onboot, no extra features, tag `concord`), pushes the
config (`/etc/concord/concord.toml`, root:concord 0640) and the secrets
(`/etc/concord/secrets.toml`, concord 0600), writes the IP, port and URL into
the container's Notes, starts it, and waits up to 90 s (`CONCORD_HEALTH_DEADLINE`)
for `/healthz`. If that fails, it destroys the container, but only one that
carries this run's mark. If `pct create` was cut off before it wrote the mark,
the script destroys nothing and says what to check: the container, and volumes
on the storage.

"Healthy" means the port is listening inside the container and `/healthz`
answers from the host (the template's busybox `wget` has no TLS, and the service
is HTTPS off loopback).

## Add another host

On the host with the container, as root (container 9100 here):

    ssh root@pve2 'bash -s -- --enroll --name pve2 --api-address 192.0.2.12' \
        < deploy.sh | bash ./deploy.sh --add-host 9100

`--enroll` creates the user, permission and token on pve2 in the same way and
writes one record to stdout; everything else goes to stderr. The record holds
the token's secret, so it refuses to write to a terminal without `--force`; do
not save it. If the record cannot be written, the token is taken back.
`--add-host` accepts only a record in exactly that form, checks the API,
certificate and token from inside the container's network namespace, replaces
the config and the secrets together, restarts Concord and waits for it to be
healthy. If not, both files are put back. A killed run is put back by the next
one.

### If `--add-host` fails

The new token stays on pve2 and nothing uses it. Which token Concord does use
is on this host (its files are put back on failure):

    pct exec 9100 -- grep -A4 pve2 /etc/concord/concord.toml

The part of `token_id` after `!` is the one to keep. If that shows no pve2, this
container uses no token there.

- Replacing a token or renewing a certificate: remove the new one with
  `--prune-tokens --keep OLD` on pve2, OLD being the name from the config. Never
  use `--unenroll` here: it also deletes the token Concord is using. Or try
  again with `--rotate-token`.
- Adding a host for the first time: `--unenroll` on pve2, with the same
  `--install` ID if you gave one, or try again with `--rotate-token`. Not if
  another node of pve2's cluster was enrolled under the same ID; then the first
  point applies, with that node's token.

Do not remove tokens while `/etc/concord/.prev` exists in the container: the
next run puts those older files back. Run `--add-host` until it succeeds first
(a run that stops at an error may have restored them already).

The namespace check uses the host's resolver, so prefer an IP address.

### Replace a token

    ssh root@pve2 'bash -s -- --enroll --rotate-token --name pve2 --api-address 192.0.2.12' \
        < deploy.sh | bash ./deploy.sh --add-host 9100 --replace

Only if that ended with `host pve2 is configured with token TOKEN`, use the
TOKEN of that line, not one seen earlier (with `--install ID` if you use one):

    ssh root@pve2 'bash -s -- --prune-tokens --keep TOKEN' < deploy.sh

The old token stays valid until then, so that a failed `--add-host` leaves
Concord working. `--replace` is also how to record a renewed certificate.

### One run at a time

On one host, runs that change the same container, or PVE users and tokens, refuse
to overlap (locks in `/run/concord-deploy`, gone with the run that holds them).
The locks do not reach other hosts. The nodes of a cluster share users and
permissions, so do not enroll, prune or unenroll on two nodes at the same time:
one run that fails may remove the permission or user just before the other
creates its token. That run then fails its check or, if it had already passed,
its token sees no guests; set the permission again or enroll again.

## Remove a host

    bash ./deploy.sh --remove-host 9100 pve2
    ssh root@pve2 'bash -s -- --unenroll' < deploy.sh

`--unenroll` deletes this installation's tokens, and the user when it has no
token left. It does not touch a user it did not create. The nodes of a cluster
share users, so there `--unenroll` on one is for all of them, and each node
needs its own `--install` ID.

These commands edit the config line by line, and stop if it uses multi-line
strings, an inline `hosts` list or another secrets file. `--dry-run` works with
all of them; it creates nothing, and `--enroll` then writes no record.

How secrets are handled: they are in shell variables, pipes, and mode 0600 files
on a tmpfs (which the kernel may swap) that are removed on every exit but
SIGKILL; never in arguments, the environment or output other than the record.

## First run

Create the first admin; the password is read from stdin:

    pct exec 9100 -- su -s /bin/sh concord -c '/usr/local/bin/concord user add NAME --role admin'

Open `https://<ip>:8010/`. The certificate is self-signed: compare the
fingerprint in the service log (`pct exec 9100 -- logread`) with the one your
browser shows before typing the password.

Where things land: config in `/etc/concord/`; users and state in
`/var/lib/concord/` (owned by `concord`, so back it up with the container);
logs go to busybox syslog's 512 KiB in-memory ring, read with
`pct exec 9100 -- logread`, so they cannot fill the disk and do not survive a
restart.

## Upgrade

Build or download the new template, then on the host:

    bash ./deploy.sh --upgrade 9100 --template concord-0.1.1-amd64.tar.xz

It checks the `concord` tag and the marker, takes a snapshot while the
container keeps running (a warning if the storage cannot), stops only the
service, swaps the two binaries, starts the service and checks health. If it is
unhealthy, the previous binaries are restored and checked again. Only the
binaries are upgraded: not Alpine packages, the init script, or the version in
`/etc/concord-ct`, which stays stale. To get those, deploy a new container from
the new template. The config, secrets and state are not touched. Remove the
snapshot afterwards with `pct delsnapshot`.

## Removal

    pct stop 9100 && pct destroy 9100 --purge

This deletes the users file and state with it. Then run `--unenroll` on every
host it tracked.

## Footprint

Measured on a nested PVE 9.2 node, polling three hosts every 3 s: about 8 MiB
resident for `concord` (7 MiB for the whole container's cgroup), under 1% of one
core, 23 MiB of root filesystem, 5.5 MB template.
