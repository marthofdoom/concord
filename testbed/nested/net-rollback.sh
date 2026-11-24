#!/usr/bin/env bash
# Put the host's network back to a net-snapshot.sh snapshot. Root, local commands only: it works with no
# network and no PVE API.
#
#   sudo /var/lib/concord-nest/bin/net-rollback.sh --execute    do it
#   sudo /var/lib/concord-nest/bin/net-rollback.sh [--dry-run]  default: print what it would do, run the checks, change nothing
#   ... --snapshot DIR          use DIR instead of /var/lib/concord-nest/latest
#   ... --restore-interfaces    also overwrite /etc/network/interfaces when it differs (default: show diff -u only)
#   ... --restore-frr           also overwrite /etc/frr/frr.conf when it differs (default: show diff -u only)
#   ... --remove-guard          also remove the host guard, but only if the snapshot recorded it as absent
#   ... --restore-sdn           also restore /etc/pve/sdn when it holds SDN objects that are neither ours nor in the snapshot
#
# Run it from /var/lib/concord-nest/bin/ (root-owned copies installed by net-snapshot.sh), never from a
# worktree: it verifies its siblings against SHA256SUMS there and warns loudly on a mismatch.
# It tries every step and reports: a failing step is counted, not fatal. The exit status is non-zero
# if any step or check failed. Output is also written to /var/lib/concord-nest/rollback-<UTC>.log.
#
# Restore order (each step is a no-op when the host is already as snapshotted):
#   1 ifdown cnest (while interfaces.d/sdn still exists, so its post-down rules run; else ip link del)
#   2 delete the SNAT and CT rules in a loop down to the snapshot's count
#     (iptables-restore is never used: it would clobber Tailscale's chains). The host guard is left in place
#   3 /etc/pve/sdn back to the snapshot (cat > only: pmxcfs refuses chmod, chown and symlinks); the diff is always
#     printed, and it is skipped (a failure) if it would delete SDN objects we did not create, unless --restore-sdn
#   4 interfaces.d/sdn; /etc/network/interfaces only with --restore-interfaces
#   5 ifreload -a, only if steps 1-4 changed something or ifquery --check -a fails
#   6 net.ipv4.ip_forward, written only if it differs from the snapshot (a write resets every
#     interface's forwarding, vmbr0's included)
#   7 wireguard dir and frr compared; frr.conf copied only with --restore-frr
# Then every post-rollback check prints PASS or FAIL.
# After a rollback, a rebuild needs a fresh snapshot.
set -uo pipefail   # no -e: one failing step must not skip the steps after it

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# Verify the installed copies before sourcing anything from here.
if [[ -f $HERE/SHA256SUMS ]]; then
    if ! (cd "$HERE" && sha256sum -c --quiet SHA256SUMS >&2); then
        printf '!!!! WARNING: files in %s do NOT match SHA256SUMS (see above). They may have been edited since\n!!!! net-snapshot.sh installed them. Continuing anyway; read the output below with that in mind.\n' "$HERE" >&2
    fi
    for f in net-rollback.sh lib.sh host-guard.sh SHA256SUMS; do
        [[ $(stat -c %u "$HERE/$f" 2>/dev/null) == 0 ]] || printf '!!!! WARNING: %s/%s is missing or not owned by root\n' "$HERE" "$f" >&2
    done
else
    printf '!!!! WARNING: no SHA256SUMS in %s: this is not the installed root-owned copy (/var/lib/concord-nest/bin). Its files cannot be verified.\n' "$HERE" >&2
fi
# shellcheck source=lib.sh
. "$HERE/lib.sh"

SNAP=$NEST_STATE/latest
RESTORE_IFACES=0 RESTORE_FRR=0 REMOVE_GUARD=0 RESTORE_SDN=0
for ((i = 1; i <= $#; i++)); do
    case ${!i} in
        --execute) EXECUTE=1 ;;
        --dry-run) EXECUTE=0 ;;
        --snapshot) i=$((i + 1)); SNAP=${!i:-} ;;
        --restore-interfaces) RESTORE_IFACES=1 ;;
        --restore-frr) RESTORE_FRR=1 ;;
        --remove-guard) REMOVE_GUARD=1 ;;
        --restore-sdn) RESTORE_SDN=1 ;;
        -h | --help) sed -n 2,30p "$0"; exit 0 ;;
        *) die "unknown argument: ${!i} (try --help)" ;;
    esac
done
if ((EUID != 0)); then
    die "net-rollback.sh must run as root, even for a dry run (the snapshot is mode 0700): sudo $NEST_BIN/net-rollback.sh $( ((EXECUTE)) && echo --execute || echo --dry-run)"
fi
S=$(readlink -f "$SNAP") || die "no snapshot at $SNAP"
[[ -d $S && -f $S/meta ]] || die "not a snapshot: $S (run net-snapshot.sh first)"

# Everything printed from here on is also kept, because the operator may be reading this blind.
ROLLBACK_LOG=$NEST_STATE/rollback-$(date -u +%Y%m%dT%H%M%SZ).log
# A terminal hang-up or a dead tee must not kill the run half way (the operator may be reading this blind): ignore
# HUP and PIPE from here on; the tee below inherits the ignored HUP and keeps writing the file.
trap '' PIPE HUP
(umask 077; : >"$ROLLBACK_LOG") 2>/dev/null && exec > >(tee -a "$ROLLBACK_LOG") 2>&1

if ((EXECUTE)); then log "MODE: EXECUTE (this changes the host's network state)"; else log "MODE: dry run (nothing is changed)"; fi
log "snapshot: $S"
log "log file: $ROLLBACK_LOG"

m() { grep "^$1=" "$S/meta" | head -n1 | cut -d= -f2-; }
FAILS=0
step_failed() { log "STEP FAILED: $*"; FAILS=$((FAILS + 1)); }
run() {   # print, and run only with --execute; a failure is counted, never fatal
    if ((EXECUTE)); then log "RUN      $*"; "$@" || step_failed "$*"; else log "DRY-RUN  $*"; fi
    return 0
}
try() {   # like run, but a failure is only a note (e.g. rmdir of a directory that is not empty)
    if ((EXECUTE)); then log "RUN      $*"; "$@" || log "note: failed (left as is): $*"; else log "DRY-RUN  $*"; fi
    return 0
}
CHANGED=0   # set when step 1, 3 or 4 changes (or would change) something; gates ifreload

if [[ $(m estate_present) == 1 ]]; then
    log "!!!! WARNING: this snapshot INCLUDES the estate network (cnest / interfaces.d/sdn / zone existed when it was taken)."
    log "!!!! Rolling back to it KEEPS cnest; it does not remove the estate. For 'the host without the estate' use a"
    log "!!!! snapshot with estate_present=0. Snapshots here (use --snapshot DIR):"
else
    log "this snapshot has estate_present=$(m estate_present) (0 = taken without the estate network). Snapshots here (--snapshot DIR):"
fi
for d in "$NEST_STATE"/net-snapshot-*/; do
    [[ -f ${d}meta ]] || continue
    log "    $(basename "$d")  estate_present=$(grep '^estate_present=' "${d}meta" | cut -d= -f2)  $([[ $(readlink -f "$d") == "$S" ]] && echo '<- selected')"
done

if [[ $(m boot_id) != "$(</proc/sys/kernel/random/boot_id)" ]]; then
    log "WARNING: the snapshot is from another boot, so ifdown has no /run/network state. The fallback (ip link del) is used"
fi

SDN_FILE=/etc/network/interfaces.d/sdn

# ---- 1. ifdown cnest ----------------------------------------------------------------------
log "---- 1/7 ifdown cnest"
if [[ $(m cnest_existed) == 1 && $(m sdn_file_existed) == 1 ]] && cmp -s "$S/interfaces.d/sdn" "$SDN_FILE" 2>/dev/null; then
    # The snapshot was taken with the estate network up and its file is unchanged: bouncing cnest would cut the
    # nodes' link for nothing; step 2 trims duplicate rules down to the snapshot's count.
    log "cnest was up in the snapshot and interfaces.d/sdn is unchanged: left up"
elif ip link show cnest >/dev/null 2>&1 || [[ -e $SDN_FILE ]]; then
    CHANGED=1
    if [[ -e $SDN_FILE ]]; then
        if ((EXECUTE)); then ifdown cnest || log "ifdown cnest failed; falling back"; else log "DRY-RUN  ifdown cnest"; fi
    fi
    if ((EXECUTE)); then
        if ip link show cnest >/dev/null 2>&1; then run ip link del cnest; fi
    elif ip link show cnest >/dev/null 2>&1; then
        log "DRY-RUN  ip link del cnest   (only if ifdown left it)"
    fi
else
    log "cnest is not present"
fi

# ---- 2. firewall rules: loop-delete down to the snapshot's count ---------------------------------
log "---- 2/7 iptables rules (loop-delete; never iptables-restore)"
rules=()
if [[ -f $SDN_FILE ]]; then
    # The exact rule texts the zone's post-up lines add, with quotes dropped.
    while IFS= read -r line; do rules+=("$line"); done < <(
        sed -nE "s/^[[:space:]]*post-up[[:space:]]+(iptables[[:space:]].*)$/\1/p" "$SDN_FILE" | tr -d "'")
fi
if ((${#rules[@]} == 0)); then
    # sdn file already gone: rebuild the same two rules from the constants and the snapshot's route.
    rules=("iptables -t nat -A POSTROUTING -s $SUBNET -o $(m out_dev) -j SNAT --to-source $(m out_ip)"
        "iptables -t raw -I PREROUTING -i fwbr+ -j CT --zone 1")
fi
for line in "${rules[@]}"; do
    read -ra a <<<"$line"
    bin=${a[0]}
    chk=() del=()
    for t in "${a[@]:1}"; do
        if [[ $t == -A || $t == -I ]]; then chk+=(-C); del+=(-D); else chk+=("$t"); del+=("$t"); fi
    done
    case $line in
        *SNAT*) cur=nat_snat_count base=$(m snat_count) ;;
        *"CT --zone"*) cur=raw_ct_count base=$(m ct_count) ;;
        *) continue ;;
    esac
    if [[ ! $base =~ ^[0-9]+$ ]]; then
        step_failed "the snapshot has no usable rule count for '$cur' (base='$base'); rules were NOT trimmed"
        continue
    fi
    if ((EXECUTE)); then
        while :; do
            now=$($cur) || { step_failed "cannot read iptables ($cur failed, xtables lock held?); rules were NOT trimmed"; break; }
            ((now > base)) || break
            "$bin" -w 10 "${chk[@]}" 2>/dev/null || break
            log "RUN      $bin -w 10 ${del[*]}"
            "$bin" -w 10 "${del[@]}" || { step_failed "could not delete: $bin ${del[*]}"; break; }
        done
    else
        log "DRY-RUN  delete '$bin -w 10 ${del[*]}' while count > $base (now $($cur || echo 'UNREADABLE'))"
    fi
done
# The host guard stays: its rules all match -i cnest, so they are inert once cnest is gone and the hook
# re-applies them if cnest returns. Removing it would make isolation worse after a teardown rollback.
if ((REMOVE_GUARD)); then
    if [[ $(m guard_installed) == 0 ]]; then
        run "$HERE/host-guard.sh" remove
    else
        log "--remove-guard ignored: the snapshot recorded the guard as installed (guard_installed=$(m guard_installed)); it stays"
    fi
else
    log "host guard left in place (--remove-guard removes it only if the snapshot recorded it absent)"
fi

# ---- 3. /etc/pve/sdn ---------------------------------------------------------------------------
log "---- 3/7 /etc/pve/sdn"
sdn_ids() {   # section headers ("type: id") of every .cfg in the directories given
    local d
    for d in "$@"; do [[ -d $d ]] && cat "$d"/*.cfg 2>/dev/null; done | sed -nE 's/^([a-z]+:[[:space:]]+[^[:space:]]+).*/\1/p' | sort -u
}
if systemctl is-active --quiet pve-cluster && mountpoint -q /etc/pve; then
    # Always show what differs, so a deletion is never silent.
    while IFS= read -r -d '' f; do
        f=${f#./}
        cmp -s "$S/pve-sdn/$f" "/etc/pve/sdn/$f" 2>/dev/null && continue
        log "WARNING: /etc/pve/sdn/$f differs from the snapshot (diff -u snapshot current):"
        a=$S/pve-sdn/$f b=/etc/pve/sdn/$f
        [[ -f $a ]] || a=/dev/null
        [[ -f $b ]] || b=/dev/null
        diff -u "$a" "$b" 2>&1 || true
    done < <({ [[ -d $S/pve-sdn ]] && (cd "$S/pve-sdn" && find . -type f -print0); [[ -d /etc/pve/sdn ]] && (cd /etc/pve/sdn && find . -type f -print0); } | sort -zu)
    # SDN objects that are neither in the snapshot nor ours were created by someone else since: not ours to delete.
    foreign=$(comm -23 <(sdn_ids /etc/pve/sdn) <({ sdn_ids "$S/pve-sdn"; printf '%s\n' "simple: $ZONE" "vnet: $VNET" "subnet: $ZONE-${SUBNET/\//-}"; } | sort -u))
    if [[ -n $foreign ]] && ((!RESTORE_SDN)); then
        step_failed "/etc/pve/sdn holds SDN objects that are not ours and not in the snapshot ($(tr '\n' ',' <<<"$foreign")); /etc/pve/sdn was NOT restored. Read the diff above; --restore-sdn deletes them"
    else
    if [[ -d /etc/pve/sdn ]]; then
        while IFS= read -r -d '' f; do
            f=${f#./}
            if [[ ! -f $S/pve-sdn/$f ]]; then CHANGED=1; run rm -f -- "/etc/pve/sdn/$f"; fi
        done < <(cd /etc/pve/sdn && find . -type f -print0)
    fi
    if [[ -d $S/pve-sdn ]]; then
        while IFS= read -r -d '' f; do
            f=${f#./}
            if ! cmp -s "$S/pve-sdn/$f" "/etc/pve/sdn/$f" 2>/dev/null; then
                CHANGED=1
                if ((EXECUTE)); then
                    log "RUN      cat snapshot/$f > /etc/pve/sdn/$f"
                    { mkdir -p "/etc/pve/sdn/$(dirname "$f")" && cat "$S/pve-sdn/$f" >"/etc/pve/sdn/$f"; } || step_failed "could not write /etc/pve/sdn/$f"
                else
                    log "DRY-RUN  cat snapshot/$f > /etc/pve/sdn/$f"
                fi
            fi
        done < <(cd "$S/pve-sdn" && find . -type f -print0)
    elif [[ $(m pve_sdn_dir_existed) == 0 && -d /etc/pve/sdn ]]; then
        CHANGED=1
        try rmdir /etc/pve/sdn
    fi
    fi
else
    step_failed "pve-cluster is not active or /etc/pve is not mounted; /etc/pve/sdn was NOT restored (fix pve-cluster, then re-run)"
fi

# ---- 4. interfaces files -----------------------------------------------------------------------
log "---- 4/7 /etc/network/interfaces and interfaces.d/sdn"
# /etc/network/interfaces may have been edited by the operator since the snapshot (a VLAN, an MTU on vmbr0).
# The SDN apply cannot change it (it is refused while an edit is staged), so by default only show the difference.
if ! cmp -s "$S/interfaces" /etc/network/interfaces; then
    log "WARNING: /etc/network/interfaces differs from the snapshot (diff -u snapshot current):"
    diff -u "$S/interfaces" /etc/network/interfaces || true
    if ((RESTORE_IFACES)); then
        CHANGED=1
        run cp "$S/interfaces" /etc/network/interfaces
    else
        log "NOT restored. If those edits are not wanted, re-run with --restore-interfaces"
    fi
fi
if [[ $(m sdn_file_existed) == 1 ]]; then
    cmp -s "$S/interfaces.d/sdn" "$SDN_FILE" 2>/dev/null || { CHANGED=1; run cp "$S/interfaces.d/sdn" "$SDN_FILE"; }
elif [[ -e $SDN_FILE ]]; then
    CHANGED=1
    run rm -f "$SDN_FILE"
fi
if [[ -e /etc/network/interfaces.new ]]; then log "note: /etc/network/interfaces.new exists; it is not ours and is left alone"; fi

# ---- 5. ifreload -a ----------------------------------------------------------------------------
log "---- 5/7 ifreload -a"
# Capture first: grep -q closing the pipe early would make a pipefail status unreliable.
ifq() { local o; o=$(ifquery --check -a 2>&1 || true); ! grep -q '\[fail\]' <<<"$o"; }
if ((!CHANGED)) && ifq; then
    log "no network file or link changed and ifquery --check -a passes: ifreload -a skipped"
elif ((EXECUTE)); then
    log "RUN      ifreload -a"
    ifreload -a || step_failed "ifreload -a failed"
else
    log "DRY-RUN  ifreload -a   (would run: changed=$CHANGED, or ifquery --check -a fails)"
fi

# ---- 6. sysctl ---------------------------------------------------------------------------------
log "---- 6/7 net.ipv4.ip_forward (written only if it differs from the snapshot)"
if [[ $(</proc/sys/net/ipv4/ip_forward) != "$(m ip_forward)" ]]; then
    run sysctl -w "net.ipv4.ip_forward=$(m ip_forward)"
else
    log "unchanged ($(m ip_forward)); not written"
fi

# ---- 7. wireguard and frr: compare, change only on difference -------------------------------------
log "---- 7/7 wireguard and frr"
if [[ $(m wg_proxmox_existed) == 0 && -d /etc/wireguard/proxmox ]]; then
    try rmdir /etc/wireguard/proxmox
fi
frr_now=absent
if [[ -e /etc/frr/frr.conf ]]; then frr_now=$(sha256sum /etc/frr/frr.conf | cut -d' ' -f1); fi
if [[ $frr_now != "$(m frr_conf_sha256)" && -f $S/frr.conf ]]; then
    log "WARNING: /etc/frr/frr.conf differs from the snapshot (diff -u snapshot current):"
    diff -u "$S/frr.conf" /etc/frr/frr.conf || true
    if ((RESTORE_FRR)); then run cp "$S/frr.conf" /etc/frr/frr.conf; else log "NOT restored. Re-run with --restore-frr to overwrite it"; fi
fi
if [[ $frr_now != "$(m frr_conf_sha256)" && ! -f $S/frr.conf ]]; then log "note: /etc/frr/frr.conf changed or appeared since the snapshot; no copy to restore"; fi
if [[ $(systemctl is-enabled frr 2>&1 || true) != "$(m frr_enabled)" && $(m frr_enabled) != enabled ]]; then
    run systemctl disable --now frr
fi
log "dnsmasq enabled state: now $(systemctl is-enabled dnsmasq 2>&1 || true), snapshot $(m dnsmasq_enabled) (compared only)"

# ---- post-rollback checks ----------------------------------------------------------------------
log "---- post-rollback checks$( ((EXECUTE)) || echo ' (dry run: state has NOT been rolled back, so FAIL here may be expected)')"
check() {   # description command...; the command's output is printed under the result line
    local d=$1 out l
    shift
    if out=$("$@" 2>&1); then log "PASS  $d"; else log "FAIL  $d"; FAILS=$((FAILS + 1)); fi
    while IFS= read -r l; do [[ -z $l ]] || log "        $l"; done <<<"$out"
}
gw=$(sed -n 's/^default via \([^ ]*\) dev .*/\1/p' "$S/default-route" | head -n1)
check "vmbr0 keeps its snapshot addresses" bash -c 'while IFS= read -r a; do [[ -z $a ]] || ip -4 -o addr show dev vmbr0 | grep -q " $a " || exit 1; done <"$1"' _ "$S/vmbr0-addrs"
check "default route is as snapshotted" bash -c 'while IFS= read -r r; do ip route show default | grep -qxF -- "$r" || exit 1; done <"$1"' _ "$S/default-route"
if [[ -n $gw ]]; then check "gateway $gw answers ping" ping -c1 -W2 "$gw"; else log "SKIP  no default gateway in the snapshot"; fi
if [[ $(m cnest_existed) == 0 ]]; then
    check "cnest is gone" bash -c '! ip link show cnest'
    check "interfaces.d/sdn is gone" test ! -e "$SDN_FILE"
fi
count_is() {   # count function, expected: fails (never passes) when iptables cannot be read or the expectation is unknown
    local n
    n=$("$1") || { echo "cannot read iptables ($1 failed, xtables lock held?)"; return 1; }
    [[ $2 =~ ^[0-9]+$ ]] || { echo "the snapshot has no usable count (got '$2')"; return 1; }
    [[ $n == "$2" ]] || { echo "now $n"; return 1; }
}
check "SNAT rule count is $(m snat_count)" count_is nat_snat_count "$(m snat_count)"
check "CT rule count is $(m ct_count)" count_is raw_ct_count "$(m ct_count)"
# Every forwarding line of the snapshot must still hold (cnest lines excluded; new guest taps may appear).
fwd_diff() {
    local line now ifn rc=0
    now=$(grep . /proc/sys/net/ipv4/ip_forward /proc/sys/net/ipv4/conf/*/forwarding /proc/sys/net/ipv6/conf/*/forwarding 2>/dev/null || true)
    while IFS= read -r line; do
        [[ $line == */cnest/* ]] && continue
        if [[ $line =~ /conf/([^/]+)/forwarding ]]; then
            ifn=${BASH_REMATCH[1]}
            if [[ $ifn != all && $ifn != default && ! -e /sys/class/net/$ifn ]]; then echo "INFO gone since snapshot: $ifn ($line)"; continue; fi
        fi
        grep -qxF -- "$line" <<<"$now" || { echo "changed: $line"; rc=1; }
    done <"$S/fwd"
    return "$rc"
}
check "forwarding sysctls match the snapshot (cnest lines aside)" fwd_diff
check "ifquery --check -a passes on every line" ifq
bridge_ports() {
    local p bl rc=0
    bl=$(bridge link 2>&1 || true)
    for p in $(grep -oE 'fwpr[0-9]+p[0-9]+' "$S/bridge-link" | sort -u); do
        if [[ ! -e /sys/class/net/$p ]]; then echo "INFO gone since snapshot: $p (that guest is stopped)"; continue; fi
        grep -q "$p" <<<"$bl" || { echo "missing $p: the guest is running but not on the bridge; restart it (qm stop/start) to re-plug it"; rc=1; }
    done
    return "$rc"
}
check "guest bridge ports from the snapshot are still on vmbr0" bridge_ports
if [[ $(m tailscaled_active) == active ]]; then
    check "tailscaled is active" systemctl is-active --quiet tailscaled
    check "tailscale has an IPv4 address" bash -c 'tailscale ip -4 | grep -q .'
    if grep -q 'lookup 52' "$S/ip-rule"; then check "ip rule has lookup 52" bash -c "ip rule | grep -q 'lookup 52'"; fi
fi
check "/etc/network/interfaces matches the snapshot" cmp -s "$S/interfaces" /etc/network/interfaces
sdn_files_match() {
    local f
    if [[ -d $S/pve-sdn ]]; then
        while IFS= read -r -d '' f; do cmp -s "$S/pve-sdn/$f" "/etc/pve/sdn/$f" || return 1; done < <(cd "$S/pve-sdn" && find . -type f -print0)
    fi
    if [[ -d /etc/pve/sdn ]]; then
        while IFS= read -r -d '' f; do [[ -f $S/pve-sdn/$f ]] || return 1; done < <(cd /etc/pve/sdn && find . -type f -print0)
    fi
}
check "/etc/pve/sdn matches the snapshot" sdn_files_match

log "full log: $ROLLBACK_LOG"
if ((FAILS)); then
    log "RESULT: $FAILS check(s) or step(s) FAILED"
    exit 1
fi
log "RESULT: all steps and checks passed"
