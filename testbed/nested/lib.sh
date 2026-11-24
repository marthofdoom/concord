# shellcheck shell=bash
# Shared constants and helpers for the nested-estate scripts. Sourced, never run.
#
# No site-specific value belongs here: those come from testbed/site.env through site.sh. This file is
# in the root-run set (net-snapshot.sh and net-rollback.sh source it), so it must stay self-contained.
#
# Everything the scripts may touch is named here, once, so the guards in build.sh,
# teardown.sh and darken.sh all enforce the same list. If a name is not in this
# file, the scripts have no business changing it.

# ---- what the estate is -----------------------------------------------------
# NODE, STORAGE_PATH and STORAGE_MOUNTPOINT are set by site.sh. Everything up to IMAGE_* is made
# readonly below, so nothing loaded later can widen what the guards accept.
STORAGE=concord-nest
# rootdir is for CT 9004 (nestview), whose rootfs lives here. A storage built without nestview in mind
# may lack it; build.sh accepts that one other set and never changes an existing storage.
STORAGE_CONTENT="images,iso,import,rootdir"
ZONE=cnestz                                # SDN ids are 2-8 alphanumerics, so "cnest" is the vnet only
VNET=cnest
SUBNET=10.99.0.0/24
GATEWAY=10.99.0.1
POOL=concord-nest
# The comments and NESTVIEW_DESC below are identity markers: the guards compare them with what is on
# the host, so changing one orphans an estate built before the change.
POOL_COMMENT="Concord CON-48 scratch estate"
PUSER=concord@pve
PUSER_COMMENT="Concord CON-48 harness user (scoped to the nested estate)"
TOKEN_NAME=nest
FULL_TOKENID="${PUSER}!${TOKEN_NAME}"
VMID_MIN=9001
VMID_MAX=9003
VM_TAG=concord-nest
# CT 9004 runs nestview (testbed/nestview/README.md). build.sh does not create it and it is in
# no pool (so the nest token has no rights over the CT that stores it). teardown.sh removes it only
# after matching all three: lxc type, hostname, and the first line of the description.
NESTVIEW_VMID=9004
NESTVIEW_HOSTNAME=nestview
NESTVIEW_DESC="nestview (CON-51): dashboard for the CON-48 nested estate"
NAMESERVERS="1.1.1.1 9.9.9.9"
CI_USER=debian

# Base image, pinned to a dated build so the checksum stays valid. "latest" is
# replaced in place by Debian and would break the pin.
# Checksum source: https://cloud.debian.org/images/cloud/trixie/20261111-2659/SHA512SUMS
IMAGE_FILE=debian-13-genericcloud-amd64-20261111-2659.qcow2
IMAGE_URL=https://cloud.debian.org/images/cloud/trixie/20261111-2659/${IMAGE_FILE}
IMAGE_SHA512=3247873136ba09b060fab45e9c115239f81c1d401fce00b8fa9b872013f7135d6a40b12462ab5ac03b9fa4ed5955dd0e8d1c900109a939ad7a0a4dafe7dea47b

readonly STORAGE STORAGE_CONTENT ZONE VNET SUBNET GATEWAY POOL POOL_COMMENT PUSER PUSER_COMMENT TOKEN_NAME \
    FULL_TOKENID VMID_MIN VMID_MAX VM_TAG NESTVIEW_VMID NESTVIEW_HOSTNAME NESTVIEW_DESC NAMESERVERS CI_USER \
    IMAGE_FILE IMAGE_URL IMAGE_SHA512

# ---- host safety net (net-snapshot.sh / net-rollback.sh / host-guard.sh) ---------
# The SDN apply reloads the host's networking. These are the operator-run, root-side tools around it.
NEST_STATE=/var/lib/concord-nest                       # world-listable; snapshots inside are 0700
GUARD_HOOK=/etc/network/if-up.d/concord-nest-guard
LIB_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# Root-owned copies that net-snapshot.sh installs (root filesystem, not a working tree, and not
# writable by the unprivileged account that sudo would otherwise be running code from).
NEST_BIN=$NEST_STATE/bin
ROLLBACK_CMD="sudo $NEST_BIN/net-rollback.sh --execute"
# Root-owned 0700 staging directory the operator copies the four root-run files into (docs/TESTBED.md,
# "Stage and verify"). Root never runs a file from a working tree: an unprivileged account can edit those.
STAGE_DIR=/root/concord-nest-stage
SNAPSHOT_CMD="sudo $STAGE_DIR/net-snapshot.sh"
GUARD_INSTALL_CMD="sudo $NEST_BIN/host-guard.sh install"

# vmid -> name / address; in_range is the one VMID guard every script uses
vm_name() { echo "nest$(($1 - VMID_MIN + 1))"; }
vm_ip() { echo "10.99.0.$(($1 - VMID_MIN + 11))"; }
in_range() { [[ $1 =~ ^[0-9]+$ ]] && (($1 >= VMID_MIN && $1 <= VMID_MAX)); }

# ---- logging / mode ---------------------------------------------------------
EXECUTE=0
LOG_FILE=""

init_log() {   # $1 = script name; only a real run leaves a log file
    ((EXECUTE)) || return 0
    local dir=${XDG_STATE_HOME:-$HOME/.local/state}/concord-nest
    mkdir -p "$dir"
    LOG_FILE=$dir/$1-$(date +%Y%m%dT%H%M%S).log
    : >"$LOG_FILE"
}

log() {
    local line
    line="$(date +%H:%M:%S) $*"
    echo "$line" >&2
    if [[ -n $LOG_FILE ]]; then echo "$line" >>"$LOG_FILE"; fi
}
die() { log "ABORT: $*"; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing required tool: $1"; }

# ---- API --------------------------------------------------------------------
# pve.sh reads its own token and puts curl args before the URL. We append
# curl's -w to get the HTTP status without ever seeing the token.
_call() {   # method path [curl args...] -> sets API_CODE and API_BODY
    local method=$1 path=$2 out
    shift 2
    out=$("$PVE_SH" -X "$method" -w $'\n%{http_code}' "$@" "$path") || die "pve.sh failed for $method $path"
    API_CODE=${out##*$'\n'}
    API_BODY=${out%$'\n'*}
}

# Read-only. Prints the JSON body; aborts on any non-200.
api_get() {
    _call GET "$1"
    [[ $API_CODE == 200 ]] || die "GET $1 returned HTTP $API_CODE: $(printf %s "$API_BODY" | head -c 300)"
    printf '%s' "$API_BODY"
}

# Read-only, for objects that may legitimately not exist yet. Returns 1 on non-200.
api_get_try() {
    _call GET "$1"
    [[ $API_CODE == 200 ]] || return 1
    printf '%s' "$API_BODY"
}

# The only function that can mutate the host through the API, with one exception: build.sh's token
# POST (step 5) goes straight to pve.sh, because the response holds the one-time secret and must
# never pass through api_write's logging. That call is guarded by build.sh's own EXECUTE check.
# Dry-run prints and returns.
# Prints .data of the response on stdout (a UPID for async calls).
# Args after the path are curl args, normally --data-urlencode k=v pairs.
api_write() {   # method path [--data-urlencode k=v ...]
    local method=$1 path=$2
    shift 2
    case $method in POST | PUT | DELETE) ;; *) die "api_write: refusing method $method" ;; esac
    if ((!EXECUTE)); then
        log "DRY-RUN  $method $path ${*:-}"
        echo "UPID:DRYRUN"
        return 0
    fi
    log "EXECUTE  $method $path ${*:-}"
    # DELETE carries its parameters in the query string, so route them there.
    if [[ $method == DELETE ]]; then
        _call DELETE "$path" "$@" -G
    else
        _call "$method" "$path" "$@"
    fi
    [[ $API_CODE == 200 ]] || die "$method $path returned HTTP $API_CODE: $(printf %s "$API_BODY" | head -c 400)"
    printf '%s' "$API_BODY" | jq -r '.data // empty'
}

wait_task() {   # upid
    local upid=$1 enc st
    ((EXECUTE)) || return 0
    [[ $upid == UPID:* ]] || return 0   # synchronous calls return null/empty
    enc=$(jq -rn --arg u "$upid" '$u|@uri')
    for _ in $(seq 1 720); do   # up to an hour; imports are slow
        st=$(api_get "/nodes/$NODE/tasks/$enc/status")
        if [[ $(jq -r '.data.status' <<<"$st") == stopped ]]; then
            [[ $(jq -r '.data.exitstatus' <<<"$st") == OK ]] || die "task failed ($(jq -r '.data.exitstatus' <<<"$st")): $upid"
            log "task ok: $upid"
            return 0
        fi
        sleep 5
    done
    die "task timed out: $upid"
}

# Runs api_write and waits for the task it started.
api_write_wait() {
    local upid
    upid=$(api_write "$@")
    wait_task "$upid"
}

preflight_common() {
    need jq
    need curl
    need openssl
    [[ -x $PVE_SH ]] || die "PVE_SH not executable: $PVE_SH"
    local v status
    v=$(api_get /version | jq -r '.data.version')
    log "connected: PVE $v"
    status=$(api_get /cluster/status)
    [[ $(jq -r '[.data[]|select(.type=="node")]|length' <<<"$status") == 1 ]] \
        || die "expected a standalone host (exactly one node in /cluster/status)"
    jq -e --arg n "$NODE" '.data[]|select(.type=="node" and .name==$n and .local==1)' <<<"$status" >/dev/null \
        || die "this API endpoint is not node '$NODE'"
}

# Read-only fact; the datacenter firewall must stay as it is.
report_firewall() {
    local fw
    fw=$(api_get /cluster/firewall/options | jq -c '.data')
    log "datacenter firewall options (read only, never changed by these scripts): $fw"
    if jq -e '.enable == 1' <<<"$fw" >/dev/null; then
        log "note: datacenter firewall is ENABLED on this host"
    else
        log "datacenter firewall is not enabled (no 'enable' key); it stays that way"
    fi
}

# Existing guest with this VMID from /cluster/resources, as one JSON object, or nothing.
vm_resource() {
    api_get '/cluster/resources?type=vm' | jq -c --argjson id "$1" '.data[]|select(.vmid==$id)'
}

# True if the existing guest is one of ours: right name, in our pool, tagged, NIC on our vnet.
vm_is_ours() {   # vmid
    local id=$1 res cfg members
    res=$(vm_resource "$id")
    [[ -n $res ]] || return 1
    [[ $(jq -r '.name' <<<"$res") == "$(vm_name "$id")" ]] || return 1
    [[ $(jq -r '.type' <<<"$res") == qemu ]] || return 1
    cfg=$(api_get_try "/nodes/$NODE/qemu/$id/config") || return 1
    # "bridge=cnest" must be followed by "," or the end, so a vnet named cnest2 does not match.
    jq -e --arg t "$VM_TAG" --arg b "bridge=$VNET" \
        '.data | ((.tags // "") | split(";") | index($t)) and ((.net0 // "") | test("(^|,)" + $b + "(,|$)"))' <<<"$cfg" >/dev/null || return 1
    members=$(api_get_try "/pools?poolid=$POOL") || return 1
    jq -e --argjson id "$id" '.data[0].members[]?|select(.vmid==$id)' <<<"$members" >/dev/null
}

# ---- pending-object shape ---------------------------------------------------
# In a ?pending=1 listing, an object that is not applied yet keeps only its identity keys at the
# top level; every other key sits under .pending (API2/Network/SDN.pm, PVE::Network::SDN). Read
# through p() so both applied and not-yet-applied objects work. .state is "new", "changed" or
# "deleted" while a change is pending.
JQ_PENDING='def p(k): (.[k] // .pending[k]);'

# ---- guards shared by build.sh and teardown.sh before any SDN apply ---------------
# PUT /cluster/sdn forks "pvesh set /nodes/<node>/network", which renames a staged
# /etc/network/interfaces.new over /etc/network/interfaces and runs ifreload -a. So an apply also
# applies any host network edit staged in the GUI, vmbr0 included. Refuse if one is staged.
require_no_staged_network() {
    local net
    net=$(api_get "/nodes/$NODE/network")
    jq -e '.changes == null' <<<"$net" >/dev/null \
        || die "host network changes are staged (GET /nodes/$NODE/network has .changes). An SDN apply would apply them too. Revert or apply them yourself first"
    [[ ! -e /etc/network/interfaces.new ]] || die "/etc/network/interfaces.new exists: a staged host network edit would be applied by the SDN apply"
}

# Other SDN changes pending anywhere would be committed by the same apply. Prints one line each.
foreign_sdn_pending() {   # zone vnet (ours)
    local z=$1 v=$2 other
    api_get '/cluster/sdn/zones?pending=1' | jq -r --arg z "$z" "$JQ_PENDING"'.data[]|select(.state != null and .zone != $z)|"zone " + .zone'
    api_get '/cluster/sdn/vnets?pending=1' | jq -r --arg v "$v" "$JQ_PENDING"'.data[]|select(.state != null and .vnet != $v)|"vnet " + .vnet'
    for other in $(api_get '/cluster/sdn/vnets?pending=1' | jq -r --arg v "$v" '.data[]|select(.vnet != $v)|.vnet'); do
        api_get_try "/cluster/sdn/vnets/$other/subnets?pending=1" | jq -r --arg o "$other" '.data[]?|select(.state != null)|"subnet of vnet " + $o' || true
    done
    api_get '/cluster/sdn/controllers?pending=1' | jq -r '.data[]|select(.state != null)|"controller " + (.controller // "?")'
    api_get '/cluster/sdn/fabrics/all?pending=1' | jq -r '[.. | objects | select(.state? != null)] | length | select(. > 0) | "fabric changes (" + tostring + ")"'
}

# A snapshot of the host's network state from THIS boot must exist (net-snapshot.sh, run as root by
# the operator). ifdown relies on /run/network state, which lasts one boot, so an older snapshot is not
# enough to roll back from. The snapshot dir is 0700; the world-readable sidecar
# net-snapshot-<ts>.boot_id next to it is what unprivileged scripts can check.
snapshot_gate() {
    local boot f ts found=""
    boot=$(</proc/sys/kernel/random/boot_id)
    for f in "$NEST_STATE"/net-snapshot-*.boot_id; do
        [[ -r $f ]] || continue
        ts=${f%.boot_id}
        if [[ $(<"$f") == "$boot" && -d $ts ]]; then found=$ts; fi
    done
    [[ -n $found ]] || die "no network snapshot from this boot under $NEST_STATE. As root, run: $SNAPSHOT_CMD (staged and verified first, see docs/TESTBED.md)"
    log "network snapshot for this boot: $found"
}

host_guard_present() { [[ -x $GUARD_HOOK ]]; }

# ---- host rule counting (root only; used by net-snapshot.sh and net-rollback.sh) -------------
# The SDN zone's post-up lines add one SNAT rule and one raw CT rule per ifup, and ifreload can
# stack duplicates. Counting is how snapshot and rollback agree on how many belong to the baseline.
# They return 3 and print nothing when iptables cannot be read (xtables lock held past -w 10, ...): a
# failed read must never look like a count of 0. Callers use `n=$(nat_snat_count) || ...`.
nat_snat_count() { local o; o=$(iptables -w 10 -t nat -S POSTROUTING 2>/dev/null) || return 3; grep -cE -- "-s ${SUBNET//./\\.} .*-j SNAT" <<<"$o" || true; }
raw_ct_count() { local o; o=$(iptables -w 10 -t raw -S PREROUTING 2>/dev/null) || return 3; grep -cE -- '-i fwbr\+ -j CT --zone 1' <<<"$o" || true; }
