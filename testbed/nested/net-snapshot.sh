#!/usr/bin/env bash
# Capture the host's network state before an SDN apply, so net-rollback.sh can undo it offline.
#
#   sudo /root/concord-nest-stage/net-snapshot.sh   take a snapshot (root; run the STAGED copy, docs/TESTBED.md)
#   net-snapshot.sh --dry-run       run the gate checks and say what would be captured (no root needed)
#
# As root it refuses to run unless its directory and net-snapshot.sh, net-rollback.sh, host-guard.sh and
# lib.sh are owned by root and not writable by group or other (it sources lib.sh as root, and installs the
# others as the trusted rollback). --i-accept-user-writable-source overrides that; do not use it.
#
# Also installs root-owned copies of net-rollback.sh, lib.sh and host-guard.sh (plus SHA256SUMS) into
# /var/lib/concord-nest/bin/. The rollback is run from there, never from a worktree: sudo must not
# execute files an unprivileged account can edit, and the worktree may be gone or on an unmounted filesystem.
#
# Writes /var/lib/concord-nest/net-snapshot-<UTC timestamp>/ (mode 0700), a world-readable sidecar
# net-snapshot-<timestamp>.boot_id next to it (what build.sh's gate reads), and a "latest" symlink.
# That is local disk, not /etc/pve, so a symlink is fine here.
#
# Refuses to run if a host network edit is staged (interfaces.new exists) or if
# `ifquery --check -a` reports any failing line: a rollback target must be a healthy state.
# Local commands only: no PVE API, no network. Never changes the host's network configuration.
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# Before lib.sh is sourced (root would execute its top-level code): everything root runs or installs must
# be root-owned and not group/world-writable, i.e. the staged copy, never the worktree.
UNSAFE_SRC=0
for arg in "$@"; do [[ $arg == --i-accept-user-writable-source ]] && UNSAFE_SRC=1; done
if ((EUID == 0 && !UNSAFE_SRC)); then
    bad=""
    for p in "$HERE" "$HERE/net-snapshot.sh" "$HERE/net-rollback.sh" "$HERE/host-guard.sh" "$HERE/lib.sh"; do
        if [[ ! -e $p || $(stat -L -c %u "$p") != 0 || -n $(find -L "$p" -maxdepth 0 -perm /022) ]]; then bad+=" $p"; fi
    done
    if [[ -n $bad ]]; then
        printf 'ABORT: running as root from files an unprivileged account could have edited. Not root-owned, missing, or group/world-writable:%s\n' "$bad" >&2
        printf 'Stage the files first (sudo install into /root/concord-nest-stage, then sha256sum -c): docs/TESTBED.md, "Stage and verify".\n' >&2
        printf 'The flag --i-accept-user-writable-source skips this check. Do not use it: root would execute whatever those files contain now, and install it as the trusted rollback.\n' >&2
        exit 1
    fi
fi
# shellcheck source=lib.sh
. "$HERE/lib.sh"

DRY=0
for arg in "$@"; do
    case $arg in
        --dry-run) DRY=1 ;;
        --i-accept-user-writable-source) ;;   # handled above, before lib.sh is sourced
        -h | --help) sed -n 2,22p "$0"; exit 0 ;;
        *) die "unknown argument: $arg (try --help)" ;;
    esac
done
if ((EUID != 0 && !DRY)); then die "net-snapshot.sh must run as root (sudo $0); --dry-run works without root"; fi

# ---- gate: only snapshot a healthy, unmodified network ----------------------------------------
[[ ! -e /etc/network/interfaces.new ]] || die "/etc/network/interfaces.new exists: a host network edit is staged. Apply or revert it first"
# ifquery exits non-zero when a line fails, so capture its output and status separately and always show the output then.
ifrc=0
ifcheck=$(ifquery --check -a 2>&1) || ifrc=$?
if ((ifrc != 0)) || grep -q '\[fail\]' <<<"$ifcheck"; then
    printf '%s\n' "$ifcheck" >&2
    die "ifquery --check -a failed (exit $ifrc) or reports failing lines (output above); the running network does not match its config"
fi
log "gate ok: no staged edit, ifquery --check -a passes on every line"

if ((DRY)); then
    log "DRY-RUN  would capture into $NEST_STATE/net-snapshot-<UTC>/: interfaces, interfaces.d, ip addr/link/route/rule, bridge link,"
    log "DRY-RUN  forwarding sysctls, iptables/ip6tables/nft rules and counts, /etc/pve/sdn, wireguard, dnsmasq, frr, ifquery check, boot_id"
    log "DRY-RUN  would install root-owned net-rollback.sh, lib.sh, host-guard.sh and SHA256SUMS into $NEST_BIN"
    exit 0
fi

# The rule counts are the baseline the rollback deletes down to, so a failed read must not become 0. Read them
# before anything is written; wait out a held xtables lock (each try already waits 10 s), else refuse.
read_count() {   # fn -> prints the count, or "unknown" when there is no iptables to ask; dies if it cannot be read
    local fn=$1 n try
    command -v iptables >/dev/null 2>&1 || { echo unknown; return 0; }
    for try in 1 2 3; do
        if n=$("$fn"); then echo "$n"; return 0; fi
    done
    return 1
}
snat_n=$(read_count nat_snat_count) || die "cannot read the iptables nat table after 3 tries (xtables lock held?). Nothing was written; retry when it is free"
ct_n=$(read_count raw_ct_count) || die "cannot read the iptables raw table after 3 tries (xtables lock held?). Nothing was written; retry when it is free"

ts=$(date -u +%Y%m%dT%H%M%SZ)
S=$NEST_STATE/net-snapshot-$ts
umask 077
mkdir -p "$NEST_STATE"
chmod 755 "$NEST_STATE"
mkdir "$S"
chmod 700 "$S"
meta() { echo "$1=$2" >>"$S/meta"; }
: >"$S/meta"

boot=$(</proc/sys/kernel/random/boot_id)
echo "$boot" >"$S/boot_id"
meta timestamp "$ts"
meta boot_id "$boot"
meta hostname "$(hostname)"

# 0. root-owned rollback tooling, outside the worktree
install -d -m 0755 -o root -g root "$NEST_BIN"
install -m 0755 -o root -g root "$HERE/net-rollback.sh" "$NEST_BIN/net-rollback.sh"
install -m 0755 -o root -g root "$HERE/host-guard.sh" "$NEST_BIN/host-guard.sh"
install -m 0644 -o root -g root "$HERE/lib.sh" "$NEST_BIN/lib.sh"
(cd "$NEST_BIN" && sha256sum net-rollback.sh lib.sh host-guard.sh >SHA256SUMS.new && chmod 644 SHA256SUMS.new && mv -f SHA256SUMS.new SHA256SUMS)
for f in net-rollback.sh lib.sh host-guard.sh; do
    cmp -s "$HERE/$f" "$NEST_BIN/$f" || die "installed $NEST_BIN/$f differs from $HERE/$f"
    meta "bin_sha256_${f%.sh}" "$(sha256sum "$NEST_BIN/$f" | cut -d' ' -f1)"
done

# 1. /etc/network/interfaces (interfaces.new is known absent from the gate)
cp /etc/network/interfaces "$S/interfaces"
meta interfaces_new_existed 0

# 1b. is the host guard installed? (rollback leaves it alone unless this was 0 and --remove-guard is given)
if [[ -e $GUARD_HOOK ]] && grep -qF 'concord-nest-guard (CON-48)' "$GUARD_HOOK"; then meta guard_installed 1; else meta guard_installed 0; fi

# 2. interfaces.d
mkdir "$S/interfaces.d"
cp -a /etc/network/interfaces.d/. "$S/interfaces.d/" 2>/dev/null || true
ls -la /etc/network/interfaces.d >"$S/interfaces.d.ls"
if [[ -e /etc/network/interfaces.d/sdn ]]; then meta sdn_file_existed 1; else meta sdn_file_existed 0; fi

# 3. live link state
ip -j addr >"$S/ip-addr.json"
ip -j link >"$S/ip-link.json"
bridge link >"$S/bridge-link" 2>&1 || true
ip -j route show table all >"$S/ip-route.json"
ip -6 route show table all >"$S/ip6-route" 2>&1 || true
ip rule >"$S/ip-rule"
ip -4 route show default >"$S/default-route"
ip -4 -o addr show dev vmbr0 2>/dev/null | awk '{print $4}' >"$S/vmbr0-addrs" || true
if ip link show cnest >/dev/null 2>&1; then meta cnest_existed 1; else meta cnest_existed 0; fi
# Does this host already carry the estate network? Then rolling back to this snapshot keeps it.
if [[ -e /etc/network/interfaces.d/sdn ]] || ip link show cnest >/dev/null 2>&1 || grep -q "$ZONE" /etc/pve/sdn/zones.cfg 2>/dev/null; then
    meta estate_present 1
else
    meta estate_present 0
fi
# The SNAT out-interface and source address the SDN zone will pick (ip route get 8.8.8.8 at apply time).
route_get=$(ip -4 route get 8.8.8.8 2>/dev/null | head -n1 || true)
meta out_dev "$(sed -n 's/.* dev \([^ ]*\).*/\1/p' <<<"$route_get")"
meta out_ip "$(sed -n 's/.* src \([^ ]*\).*/\1/p' <<<"$route_get")"

# 4. forwarding sysctls (runtime only; they follow the interface)
grep . /proc/sys/net/ipv4/ip_forward /proc/sys/net/ipv4/conf/*/forwarding /proc/sys/net/ipv6/conf/*/forwarding >"$S/fwd" 2>/dev/null || true
meta ip_forward "$(</proc/sys/net/ipv4/ip_forward)"

# 5. firewall rules. The -save files are for reference only; rollback never restores them,
# because that would clobber Tailscale's chains.
iptables-save >"$S/iptables-save" 2>&1 || true
ip6tables-save >"$S/ip6tables-save" 2>&1 || true
nft list ruleset >"$S/nft-ruleset" 2>&1 || true
meta snat_count "$snat_n"
meta ct_count "$ct_n"

# 6. /etc/pve/sdn: every file, by content (pmxcfs has no useful metadata, so no cp -a)
if [[ -d /etc/pve/sdn ]]; then
    meta pve_sdn_dir_existed 1
    mkdir "$S/pve-sdn"
    (cd /etc/pve/sdn && find . -type f -print0) | while IFS= read -r -d '' f; do
        mkdir -p "$S/pve-sdn/$(dirname "$f")"
        cat "/etc/pve/sdn/$f" >"$S/pve-sdn/$f"
    done
    ls -A /etc/pve/sdn >"$S/pve-sdn.ls"
else
    meta pve_sdn_dir_existed 0
fi

# 7. wireguard dirs
ls -la /etc/wireguard /etc/wireguard/proxmox >"$S/wireguard.ls" 2>&1 || true
if [[ -d /etc/wireguard/proxmox ]]; then meta wg_proxmox_existed 1; else meta wg_proxmox_existed 0; fi

# 8. dnsmasq (a DHCP-less zone must leave it alone)
meta dnsmasq_enabled "$(systemctl is-enabled dnsmasq 2>&1 || true)"

# 9. FRR
meta frr_enabled "$(systemctl is-enabled frr 2>&1 || true)"
meta frr_active "$(systemctl is-active frr 2>&1 || true)"
if [[ -e /etc/frr/frr.conf ]]; then
    meta frr_conf_sha256 "$(sha256sum /etc/frr/frr.conf | cut -d' ' -f1)"
    cp /etc/frr/frr.conf "$S/frr.conf"
else
    meta frr_conf_sha256 absent
fi

# 10. ifreload gate evidence, and tailscale state for the post-rollback checks
printf '%s\n' "$ifcheck" >"$S/ifcheck"
meta tailscaled_active "$(systemctl is-active tailscaled 2>&1 || true)"

# The dir is 0700; this sidecar is what unprivileged build.sh/teardown.sh read.
echo "$boot" >"$NEST_STATE/net-snapshot-$ts.boot_id"
chmod 644 "$NEST_STATE/net-snapshot-$ts.boot_id"
ln -sfn "$S" "$NEST_STATE/latest"

log "snapshot written: $S (mode 0700)"
log "  boot_id            $boot"
log "  interfaces         $(wc -l <"$S/interfaces") lines; interfaces.d/sdn existed: $(grep '^sdn_file_existed=' "$S/meta" | cut -d= -f2)"
log "  cnest existed      $(grep '^cnest_existed=' "$S/meta" | cut -d= -f2)"
log "  ip_forward         $(grep '^ip_forward=' "$S/meta" | cut -d= -f2)"
log "  SNAT / CT rules    $(grep '^snat_count=' "$S/meta" | cut -d= -f2) / $(grep '^ct_count=' "$S/meta" | cut -d= -f2)"
log "  /etc/pve/sdn       $( [[ -d $S/pve-sdn ]] && find "$S/pve-sdn" -type f | wc -l || echo 'absent') files"
log "  frr                enabled=$(grep '^frr_enabled=' "$S/meta" | cut -d= -f2) active=$(grep '^frr_active=' "$S/meta" | cut -d= -f2)"
log "  latest -> $S"
log "  rollback tools     $NEST_BIN (root-owned) sha256:"
while read -r sum f; do log "    $sum  $f"; done <"$NEST_BIN/SHA256SUMS"
if [[ $(grep '^estate_present=' "$S/meta" | cut -d= -f2) == 1 ]]; then
    log "!!!! WARNING: this snapshot INCLUDES the estate network (cnest, interfaces.d/sdn or the zone $ZONE exists)."
    log "!!!! Rolling back to it KEEPS cnest; it does not give you the host without the estate."
    log "!!!! For a rollback to 'no estate', use a snapshot taken before the first SDN apply (estate_present=0)."
fi
log "next: the host guard, if wanted: $GUARD_INSTALL_CMD   (it goes after this snapshot, so the snapshot records guard_installed=0; harmless)"
log "rollback if networking breaks: $ROLLBACK_CMD"
