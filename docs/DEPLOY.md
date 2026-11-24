# Deploying Concord in a Proxmox container

One unprivileged LXC per PVE host, running the static `concord` binary under
OpenRC. The container needs 128 MB of RAM, one core and about 1 GB of disk.
Everything lives in `deploy/ct/`.

## Install from a release

Each GitHub release holds `concord-X-amd64.tar.xz` (the template), its
`.sha256`, `deploy.sh`, `concord.ct.example.toml`, a static `concordctl`, and
`SHA256SUMS` over all of them. Download them into one empty directory on the
PVE host (or copy them there) and check before running anything:

    sha256sum -c SHA256SUMS

Do this as an ordinary user, and run as root only files that check passed:
`deploy.sh` runs as root and so does everything it calls. A checksum file
fetched from the same place as the files shows they arrived intact, not that
they are the ones you meant; compare `SHA256SUMS` against the copy in the
release page's notes or another channel when that matters. Then continue with
[Deploy](#deploy), using the files from that directory. The host agent is
deliberately not shipped yet. Maintainers: [RELEASING.md](RELEASING.md).

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

Copy the template, `deploy.sh`, a config and a secrets file to the PVE host,
then, as root there:

    deploy.sh --vmid 9100 --storage local-lvm --bridge vmbr0 \
        --ip 192.0.2.50/24 --gateway 192.0.2.1 \
        --config concord.toml --secrets secrets.toml \
        --template concord-0.1.0-amd64.tar.xz

Use `--ip dhcp` to take an address from DHCP, and `--dry-run` to print every
mutating command without running it. Start from `deploy/ct/concord.ct.example.toml`
(listen on all interfaces, `secrets_file = "secrets.toml"`, `users_file` and
`state_dir` under `/var/lib/concord`). The secrets file must be mode 0600 on the
host.

`deploy.sh` refuses a VMID that exists anywhere in the cluster, creates the
container (unprivileged, onboot, no extra features, tag `concord`), pushes the
config (`/etc/concord/concord.toml`, root:concord 0640) and the secrets
(`/etc/concord/secrets.toml`, concord 0600), writes the IP, port and URL into
the container's Notes, starts it, and waits up to 90 s (`CONCORD_HEALTH_DEADLINE`)
for `/healthz`. If the wait fails, it destroys only the container it created in
that run.

"Healthy" means the port is listening inside the container and `/healthz`
answers from the host (the template's busybox `wget` has no TLS, and the service
is HTTPS off loopback).

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

    deploy.sh --upgrade 9100 --template concord-0.1.1-amd64.tar.xz

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

This deletes the users file and state with it.

## Footprint

Measured on a nested PVE 9.2 node, polling three hosts every 3 s: about 8 MiB
resident for `concord` (7 MiB for the whole container's cgroup), under 1% of one
core, 23 MiB of root filesystem, 5.5 MB template.
