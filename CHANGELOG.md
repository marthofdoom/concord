# Changelog

## 0.1.0

First release.

- Read-only inventory of several standalone Proxmox VE hosts: every host and
  guest in one view, polled through each host's own API. A host that stops
  answering keeps its last-known guests, marked stale, and a VMID used on two
  hosts is reported.
- Web console served over HTTPS.
- Login with local users, API tokens, or a tracked host's root login
  (`root@HOST`, with TOTP or recovery codes; `pve_root_login = false` turns it
  off).
- LXC template for a Proxmox host, with `deploy.sh` to create a container and to
  upgrade it, rolling back to the previous binaries if the new ones are unhealthy.
- `deploy.sh` creates the read-only PVE user and token it needs, checks them, and
  writes the configuration. `--enroll` with `--add-host` adds another host,
  `--remove-host` and `--unenroll` take one out, and `--rotate-token` replaces a
  token. Whatever a failed run created is removed again.
- `concordctl`, the command-line client, shipped as a static binary.

Limits:

- One Concord instance; there is no high availability for Concord itself.
- Read-only: Concord does not change anything on your hosts yet.
- No persistence of inventory history; state is rebuilt from the hosts on start.
- Not tested: addressing the container by DHCP, and taking a snapshot during an
  upgrade.
- Hosts are pinned by certificate fingerprint, so a renewed certificate must be
  updated in the configuration.
- The host agent is not part of this release.
