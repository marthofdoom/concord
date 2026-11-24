# Changelog

## 0.1.0

First release.

- Read-only inventory of several standalone Proxmox VE hosts: nodes, guests and
  storage in one view, polled through each host's own API.
- Web console served over HTTPS.
- Login with local users and API tokens.
- LXC template for a Proxmox host, with `deploy.sh` to create a container and to
  upgrade it, rolling back to the previous binaries if the new ones are unhealthy.
- `concordctl`, the command-line client, shipped as a static binary.

Limits:

- One Concord instance; there is no high availability for Concord itself.
- Read-only: Concord does not change anything on your hosts yet.
- No persistence of inventory history; state is rebuilt from the hosts on start.
- Not tested: addressing the container by DHCP, and taking a snapshot during an
  upgrade.
- The host agent is not part of this release.
