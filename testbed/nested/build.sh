#!/usr/bin/env bash
# Build the nested-PVE test estate on a PVE host. Site settings: testbed/site.env.
#
#   build.sh                         dry run: GETs only, prints every write it would make
#   build.sh --execute               do it, except the SDN apply
#   build.sh --execute --yes-apply-sdn
#                                    also apply SDN (reloads host networking). Needs a network
#                                    snapshot from this boot (run the staged copy as root: sudo /root/concord-nest-stage/net-snapshot.sh)
#
# Options: --no-install  stop after the VMs are running (skip the PVE install over SSH)
#          --no-start    create the VMs but start none of them (implies --no-install)
#          --accept-no-host-guard
#                        allow --execute without the host guard (host-guard.sh install)
#
# Idempotent: every object is created only if absent; an object that already
# exists is accepted only if it matches this script's own expected config,
# otherwise the script aborts without writing anything further.
# Undo with teardown.sh. Full description: docs/TESTBED.md.
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$HERE/lib.sh"
# shellcheck source=site.sh
. "$HERE/site.sh"
# ROOT_PW_FILE (from site.env) holds the nodes' root password, for root@pam on each node's own GUI.
NODE_PW_FILE=/tmp/concord-nest-root-password

APPLY_SDN_OK=0 INSTALL=1 START=1 NO_GUARD_OK=0
for arg in "$@"; do
    case $arg in
        --execute) EXECUTE=1 ;;
        --yes-apply-sdn) APPLY_SDN_OK=1 ;;
        --no-install) INSTALL=0 ;;
        --no-start) START=0 INSTALL=0 ;;
        --accept-no-host-guard) NO_GUARD_OK=1 ;;
        -h | --help) sed -n 2,19p "$0"; exit 0 ;;
        *) die "unknown argument: $arg (try --help)" ;;
    esac
done
site_load_estate
init_log build

if ((EXECUTE)); then log "MODE: EXECUTE (writes will happen)"; else log "MODE: dry run (GET only, nothing is written)"; fi

# install-pve.sh proves isolation by failing to reach port 22 on this address from inside a node. That
# proves nothing unless the address is this host's own and the port answers from here.
check_lan_probe() {
    local dev
    dev=$(ip -4 -o addr show | awk -v ip="$HOST_LAN_IP" '{split($4, a, "/"); if (a[1] == ip) {print $2; exit}}')
    [[ -n $dev ]] || die "HOST_LAN_IP $HOST_LAN_IP is not an address of this host, so the nodes' isolation check would prove nothing"
    [[ $dev != lo && $HOST_LAN_IP != 127.* ]] || die "HOST_LAN_IP $HOST_LAN_IP is a loopback address; use the host's LAN address"
    [[ $HOST_LAN_IP != "${SUBNET%.*}".* ]] || die "HOST_LAN_IP $HOST_LAN_IP is in the estate's own subnet $SUBNET; use the host's LAN address"
    # bash's /dev/tcp: no tool to install.
    timeout 5 bash -c 'exec 3<>"/dev/tcp/$1/22"' _ "$HOST_LAN_IP" 2>/dev/null \
        || die "nothing answers on $HOST_LAN_IP:22 from this host, so the nodes' isolation check would prove nothing (start sshd)"
}

# ---------------------------------------------------------------------------
# Guards. Everything in this section is read-only and runs before any write.
# ---------------------------------------------------------------------------
need ssh-keygen
need ssh
need scp
need ip
need timeout
# There is no default password. Checked first, in dry runs too, so a build never stops half way on it.
site_private_file "NODE_ROOT_PASSWORD_FILE" "$ROOT_PW_FILE" 077
[[ -s $ROOT_PW_FILE ]] || die "NODE_ROOT_PASSWORD_FILE is empty: $ROOT_PW_FILE"
check_lan_probe
preflight_common
report_firewall

# The host guard (host-guard.sh install, root) blocks the nodes from the host's own
# services and the LAN at the host. Without it only the in-node nftables stand between a node and
# the LAN, and that does not cover nested guests (they are bridged, see docs/TESTBED.md).
if host_guard_present; then
    log "host guard hook present: $GUARD_HOOK"
else
    log "WARNING: ############################################################################"
    log "WARNING: host guard is NOT installed ($GUARD_HOOK missing)."
    log "WARNING: Nodes, and guests inside them, could reach the LAN and the host's services (SSH, 8006)."
    log "WARNING: As root, run: $GUARD_INSTALL_CMD (after the snapshot; docs/TESTBED.md)"
    log "WARNING: ############################################################################"
    if ((EXECUTE && !NO_GUARD_OK)); then
        die "host guard absent; install it, or re-run with --accept-no-host-guard (nothing has been written yet)"
    fi
fi

# The build token needs real admin rights; fail now rather than half way.
perms=$(api_get '/access/permissions?path=/' | jq -c '.data["/"] // {}')
for p in Sys.Modify Datastore.Allocate SDN.Allocate Permissions.Modify User.Modify VM.Allocate Pool.Allocate; do
    jq -e --arg p "$p" '.[$p] == 1' <<<"$perms" >/dev/null || die "API token lacks $p on / (the build needs an administrator token)"
done

# Expected-state probes: each prints nothing and returns 0 if absent, "ok" if
# present and matching, and aborts if present but different.
sorted_csv() { tr ',' '\n' <<<"$1" | sort | paste -sd,; }

# Prints "ok", or "ok-no-rootdir" for a storage whose content lacks rootdir.
# That one other set is accepted as it is and never PUT here: adding rootdir lets the nest token
# allocate container volumes, which only the nestview deploy needs, so it stays that deploy's own
# step (testbed/nestview/README.md, step 0), not a side effect of re-running a build.
probe_storage() {
    local s have want pre_rootdir
    s=$(api_get /storage | jq -c --arg id "$STORAGE" '.data[]|select(.storage==$id)')
    [[ -n $s ]] || return 0
    [[ $(jq -r .type <<<"$s") == dir ]] || die "storage '$STORAGE' exists but is not type dir"
    [[ $(jq -r .path <<<"$s") == "$STORAGE_PATH" ]] || die "storage '$STORAGE' exists with a different path: $(jq -r .path <<<"$s")"
    [[ $(jq -r '.nodes // ""' <<<"$s") == "$NODE" ]] || die "storage '$STORAGE' exists but is not restricted to node $NODE"
    have=$(sorted_csv "$(jq -r .content <<<"$s")")
    want=$(sorted_csv "$STORAGE_CONTENT")
    pre_rootdir=$(sorted_csv "$(tr ',' '\n' <<<"$STORAGE_CONTENT" | grep -vx rootdir | paste -sd,)")
    if [[ $have == "$want" ]]; then
        echo ok
    elif [[ $have == "$pre_rootdir" ]]; then
        echo ok-no-rootdir
    else
        die "storage '$STORAGE' exists with different content types: $(jq -r .content <<<"$s") (expected $want, or $pre_rootdir without rootdir)"
    fi
}

probe_zone() {
    local z
    z=$(api_get '/cluster/sdn/zones?pending=1' | jq -c --arg id "$ZONE" '.data[]|select(.zone==$id)')
    [[ -n $z ]] || return 0
    [[ $(jq -r .type <<<"$z") == simple ]] || die "SDN zone '$ZONE' exists but is not type simple"
    [[ $(jq -r '.state // ""' <<<"$z") != deleted ]] || die "SDN zone '$ZONE' is pending deletion (an earlier teardown did not apply). Run teardown.sh --execute --yes-apply-sdn"
    jq -e "$JQ_PENDING"'(p("dhcp") // "") == ""' <<<"$z" >/dev/null || die "SDN zone '$ZONE' exists with DHCP enabled; this estate uses static addresses"
    echo ok
}

probe_vnet() {
    local v
    v=$(api_get '/cluster/sdn/vnets?pending=1' | jq -c --arg id "$VNET" '.data[]|select(.vnet==$id)')
    [[ -n $v ]] || return 0
    [[ $(jq -r '.state // ""' <<<"$v") != deleted ]] || die "SDN vnet '$VNET' is pending deletion (an earlier teardown did not apply). Run teardown.sh --execute --yes-apply-sdn"
    [[ $(jq -r "$JQ_PENDING"'p("zone")' <<<"$v") == "$ZONE" ]] || die "SDN vnet '$VNET' exists in a different zone: $(jq -r "$JQ_PENDING"'p("zone")' <<<"$v")"
    echo ok
}

probe_subnet() {
    local s
    s=$(api_get_try "/cluster/sdn/vnets/$VNET/subnets?pending=1") || return 0
    jq -e --arg c "$SUBNET" "$JQ_PENDING"'.data[]|select(((p("cidr") // "") == $c) or ((p("subnet") // "") | endswith($c | gsub("/";"-"))))' <<<"$s" >/dev/null || return 0
    jq -e --arg g "$GATEWAY" "$JQ_PENDING"'.data[]|select(p("gateway") == $g and (p("snat") == 1 or p("snat") == true))' <<<"$s" >/dev/null \
        || die "SDN subnet $SUBNET exists on vnet '$VNET' but gateway/snat differ from expected ($GATEWAY, snat on)"
    echo ok
}

probe_pool() {
    local p
    p=$(api_get /pools | jq -c --arg id "$POOL" '.data[]|select(.poolid==$id)')
    [[ -n $p ]] || return 0
    [[ $(jq -r '.comment // ""' <<<"$p") == "$POOL_COMMENT" ]] || die "pool '$POOL' exists but was not created by this script (comment differs)"
    echo ok
}

probe_user() {
    local u
    u=$(api_get /access/users | jq -c --arg id "$PUSER" '.data[]|select(.userid==$id)')
    [[ -n $u ]] || return 0
    [[ $(jq -r '.comment // ""' <<<"$u") == "$PUSER_COMMENT" ]] || die "user '$PUSER' exists but was not created by this script (comment differs)"
    echo ok
}

probe_token() {
    local t
    # Listing tokens of a user that does not exist yet is a 500, which means "absent".
    t=$(api_get_try "/access/users/$PUSER/token") || return 0
    jq -e --arg id "$TOKEN_NAME" '.data[]|select(.tokenid==$id)' <<<"$t" >/dev/null || return 0
    echo ok
}

st_storage=$(probe_storage)
st_zone=$(probe_zone)
st_vnet=$(probe_vnet)
st_subnet=$(probe_subnet)
st_pool=$(probe_pool)
st_user=$(probe_user)
st_token=$(probe_token)

# Other pending SDN changes would be applied along with ours. Refuse that.
foreign_pending=$(foreign_sdn_pending "$ZONE" "$VNET")
[[ -z $foreign_pending ]] || die "unrelated SDN changes are pending and would be applied too: $foreign_pending"

# Token file and token must agree: PVE shows the secret exactly once.
if [[ $st_token == ok && ! -f $TOKEN_FILE ]]; then
    die "token $FULL_TOKENID exists in PVE but $TOKEN_FILE does not; its secret cannot be recovered. Run teardown.sh, then build again"
fi
if [[ -z $st_token && -e $TOKEN_FILE ]]; then
    die "$TOKEN_FILE exists but token $FULL_TOKENID does not exist in PVE; refusing to overwrite. Move the file away and re-run"
fi

# VMIDs: abort if one is taken by anything that is not our own guest.
for id in $(seq "$VMID_MIN" "$VMID_MAX"); do
    if [[ -n $(vm_resource "$id") ]]; then
        vm_is_ours "$id" || die "VMID $id exists and is not this estate's $(vm_name "$id") (name, pool, tag or NIC differ). Not touching it"
        log "VMID $id: already built ($(vm_name "$id")); will be left alone"
    fi
done

# SDN apply is the one step that reloads host networking.
sdn_apply_needed=0
if [[ -z $st_zone || -z $st_vnet || -z $st_subnet ]]; then sdn_apply_needed=1; fi
# Our objects may already be created but not applied (an interrupted earlier run).
if [[ -n $(api_get '/cluster/sdn/zones?pending=1' | jq -r --arg z "$ZONE" '.data[]|select(.zone==$z and .state != null)|.zone') ||
    -n $(api_get '/cluster/sdn/vnets?pending=1' | jq -r --arg v "$VNET" '.data[]|select(.vnet==$v and .state != null)|.vnet') ||
    -n $(api_get_try "/cluster/sdn/vnets/$VNET/subnets?pending=1" | jq -r '.data[]?|select(.state != null)|.state') ]]; then
    sdn_apply_needed=1
fi
if [[ $sdn_apply_needed == 1 ]]; then
    log "WARNING: the SDN apply (PUT /cluster/sdn) reloads the HOST's network configuration (ifreload)."
    log "WARNING: It should leave vmbr0 untouched, but it runs on a machine that carries your LAN, so do it when a"
    log "WARNING: short blip is acceptable. It creates bridge cnest (10.99.0.1/24) and turns on forwarding for that"
    log "WARNING: interface only (the global net.ipv4.ip_forward stays 0), plus a SNAT rule out vmbr0."
    # Applies to dry runs too: a dry run should fail where the real run would.
    require_no_staged_network
    if ((EXECUTE && !APPLY_SDN_OK)); then
        die "SDN apply needed; re-run with --yes-apply-sdn to allow it (nothing has been written yet)"
    fi
    if ((EXECUTE)); then snapshot_gate; else log "(--execute will also require a network snapshot from this boot: $SNAPSHOT_CMD, staged and verified first)"; fi
fi

if ((EXECUTE && INSTALL)) && [[ $(hostname) != "$NODE" ]]; then
    die "the install step must run on $NODE (it reaches the nodes over $SUBNET); use --no-install elsewhere"
fi

log "guards passed: storage=${st_storage:-absent} zone=${st_zone:-absent} vnet=${st_vnet:-absent} subnet=${st_subnet:-absent} pool=${st_pool:-absent} user=${st_user:-absent} token=${st_token:-absent}"

# ---------------------------------------------------------------------------
# Writes
# ---------------------------------------------------------------------------
step() { log "---- $*"; }

step "1/9 local SSH keypair"
if [[ -f $SSH_KEY ]]; then
    log "exists: $SSH_KEY"
elif ((EXECUTE)); then
    umask 077
    ssh-keygen -q -t ed25519 -N '' -C concord-nest -f "$SSH_KEY"
    log "generated $SSH_KEY"
else
    log "DRY-RUN  ssh-keygen -t ed25519 -N '' -C concord-nest -f $SSH_KEY"
fi
log "exists: $ROOT_PW_FILE"

step "2/9 storage $STORAGE"
if [[ $st_storage == ok ]]; then
    log "exists and matches"
elif [[ $st_storage == ok-no-rootdir ]]; then
    log "exists without rootdir in its content set; left unchanged. CT 9004 (nestview) needs rootdir: its deploy adds it (testbed/nestview/README.md, step 0)"
else
    api_write POST /storage \
        --data-urlencode "storage=$STORAGE" --data-urlencode type=dir \
        --data-urlencode "path=$STORAGE_PATH" --data-urlencode "content=$STORAGE_CONTENT" \
        --data-urlencode "nodes=$NODE" --data-urlencode "is_mountpoint=$STORAGE_MOUNTPOINT" \
        --data-urlencode mkdir=1 >/dev/null
fi

step "3/9 SDN objects (pending until applied)"
if [[ -n $st_zone ]]; then log "zone exists"; else
    api_write POST /cluster/sdn/zones --data-urlencode "zone=$ZONE" --data-urlencode type=simple >/dev/null
fi
if [[ -n $st_vnet ]]; then log "vnet exists"; else
    api_write POST /cluster/sdn/vnets --data-urlencode "vnet=$VNET" --data-urlencode "zone=$ZONE" >/dev/null
fi
if [[ -n $st_subnet ]]; then log "subnet exists"; else
    api_write POST "/cluster/sdn/vnets/$VNET/subnets" \
        --data-urlencode type=subnet --data-urlencode "subnet=$SUBNET" \
        --data-urlencode "gateway=$GATEWAY" --data-urlencode snat=1 >/dev/null
fi

step "4/9 SDN apply"
if ((sdn_apply_needed)); then
    log "ROLLBACK if networking breaks (run on the host, works offline): $ROLLBACK_CMD"
    api_write_wait PUT /cluster/sdn
    if ((EXECUTE)); then
        for _ in $(seq 1 30); do
            [[ $(api_get "/nodes/$NODE/sdn/zones" | jq -r --arg z "$ZONE" '.data[]|select(.zone==$z)|.status') == available ]] && break
            sleep 2
        done
        [[ $(api_get "/nodes/$NODE/sdn/zones" | jq -r --arg z "$ZONE" '.data[]|select(.zone==$z)|.status') == available ]] \
            || die "zone $ZONE did not become available after apply"
        log "zone $ZONE is available"
    fi
else
    log "nothing pending"
fi

step "5/9 pool, user, token, ACLs"
if [[ -n $st_pool ]]; then log "pool exists"; else
    api_write POST /pools --data-urlencode "poolid=$POOL" --data-urlencode "comment=$POOL_COMMENT" >/dev/null
fi
if [[ -n $st_user ]]; then log "user exists"; else
    api_write POST /access/users --data-urlencode "userid=$PUSER" --data-urlencode "comment=$PUSER_COMMENT" \
        --data-urlencode enable=1 >/dev/null
fi
if [[ -n $st_token ]]; then
    log "token exists"
elif ((EXECUTE)); then
    log "EXECUTE  POST /access/users/$PUSER/token/$TOKEN_NAME privsep=1  (secret goes straight to $TOKEN_FILE, never logged)"
    tmp=$(umask 077 && mktemp "$SEC_DIR/.concord-nest-token.XXXXXX")
    trap 'rm -f "$tmp"' EXIT
    # The response body is the only place PVE shows the secret; it only ever passes through this pipe.
    if "$PVE_SH" -X POST --data-urlencode privsep=1 --data-urlencode "comment=Concord test harness" \
        "/access/users/$PUSER/token/$TOKEN_NAME" \
        | jq -re '.data | select(.value != null) | "\(.["full-tokenid"])=\(.value)"' >"$tmp" && [[ -s $tmp ]]; then
        chmod 600 "$tmp"
        mv "$tmp" "$TOKEN_FILE"
        trap - EXIT
        log "token written to $TOKEN_FILE (mode 600)"
    else
        die "token creation failed; no secret was stored. If PVE did create the token, delete it with teardown.sh"
    fi
else
    log "DRY-RUN  POST /access/users/$PUSER/token/$TOKEN_NAME privsep=1  (secret would be written to $TOKEN_FILE, mode 600, never printed)"
fi

# Privilege separation means the token holds the intersection of its own and the user's ACLs,
# so the same grants go on both. Smallest built-in roles that cover create/destroy/snapshot/
# migrate/power/config of guests in the pool; see docs/TESTBED.md for why each is there.
acl_acls=$(api_get /access/acl)
ensure_acl() {   # path roleid kind(user|token) ugid
    local path=$1 role=$2 kind=$3 ugid=$4 field
    if jq -e --arg p "$path" --arg r "$role" --arg u "$ugid" \
        '.data[]|select(.path==$p and .roleid==$r and .ugid==$u)' <<<"$acl_acls" >/dev/null; then
        log "ACL present: $path $role $ugid"
        return 0
    fi
    field=users
    [[ $kind == token ]] && field=tokens
    api_write PUT /access/acl --data-urlencode "path=$path" --data-urlencode "roles=$role" \
        --data-urlencode "$field=$ugid" --data-urlencode propagate=1 >/dev/null
}
for who in "user $PUSER" "token $FULL_TOKENID"; do
    # shellcheck disable=SC2086
    set -- $who
    ensure_acl "/pool/$POOL" PVEVMAdmin "$1" "$2"
    ensure_acl "/pool/$POOL" PVEPoolUser "$1" "$2"
    ensure_acl "/storage/$STORAGE" PVEDatastoreUser "$1" "$2"
    ensure_acl "/sdn/zones/$ZONE/$VNET" PVESDNUser "$1" "$2"
done

step "6/9 base image $IMAGE_FILE"
present=$(api_get_try "/nodes/$NODE/storage/$STORAGE/content?content=import" \
    | jq -r --arg v "$STORAGE:import/$IMAGE_FILE" '.data[]?|select(.volid==$v)|.volid' || true)
if [[ -n $present ]]; then
    log "already downloaded: $present"
else
    api_write_wait POST "/nodes/$NODE/storage/$STORAGE/download-url" \
        --data-urlencode "url=$IMAGE_URL" --data-urlencode content=import \
        --data-urlencode "filename=$IMAGE_FILE" \
        --data-urlencode "checksum=$IMAGE_SHA512" --data-urlencode checksum-algorithm=sha512
fi

step "7/9 VMs ${VMID_MIN}-${VMID_MAX}"
if [[ -f $SSH_KEY.pub ]]; then pubkey=$(<"$SSH_KEY.pub"); else pubkey="ssh-ed25519 DRYRUN-key-not-generated-yet concord-nest"; fi
# The API wants sshkeys percent-encoded; curl then encodes it again for the form body, which is what PVE expects.
sshkeys_enc=$(jq -rn --arg k "$pubkey" '$k|@uri')
# Without it, PVE's cloud-init falls back to the host's own search domain, per
# PVE/QemuServer/Cloudinit.pm get_dns_conf. Same domain install-pve.sh puts in /etc/hosts. Kept out
# of lib.sh, which root runs from a checksummed copy. Only VMs created from now on get it.
SEARCHDOMAIN=concord.test
# Every guest these scripts create carries its addresses and ports in its Proxmox Notes (the
# description key). Informational only: no guard reads anything past the first line.
# An existing VM is skipped below, so its notes, possibly edited by hand, are left as they are.
vm_notes() {   # vmid
    local ip
    ip=$(vm_ip "$1")
    cat <<EOF
Concord nested PVE node (scratch). Built by testbed/nested/build.sh

**Addresses** (vnet \`$VNET\`, $SUBNET, gateway $GATEWAY on the host)
- IP: \`$ip/24\` on vmbr0 (port nic0)
- PVE web GUI / API: https://$ip:8006 (root@pam, password in secret store: ${ROOT_PW_FILE##*/})
- SSH: \`ssh $CI_USER@$ip\` port 22, key only (key/known_hosts per testbed/nested/site.sh)
- Reachable from the host only; the node cannot reach the LAN or the host (host guard + in-node nftables)

Docs: concord docs/TESTBED.md
EOF
}
for id in $(seq "$VMID_MIN" "$VMID_MAX"); do
    name=$(vm_name "$id")
    if [[ -n $(vm_resource "$id") ]]; then log "VM $id ($name) exists; skipping (its notes are left as they are)"; continue; fi
    api_write_wait POST "/nodes/$NODE/qemu" \
        --data-urlencode "vmid=$id" --data-urlencode "name=$name" \
        --data-urlencode "pool=$POOL" --data-urlencode "tags=$VM_TAG" \
        --data-urlencode "description=$(vm_notes "$id")" \
        --data-urlencode cores=2 --data-urlencode sockets=1 --data-urlencode cpu=host \
        --data-urlencode memory=7168 --data-urlencode balloon=0 \
        --data-urlencode ostype=l26 --data-urlencode scsihw=virtio-scsi-single \
        --data-urlencode "scsi0=$STORAGE:0,import-from=$STORAGE:import/$IMAGE_FILE,format=qcow2,discard=on,iothread=1" \
        --data-urlencode "ide2=$STORAGE:cloudinit,format=qcow2" \
        --data-urlencode boot=order=scsi0 \
        --data-urlencode "net0=virtio,bridge=$VNET" \
        --data-urlencode serial0=socket --data-urlencode vga=serial0 --data-urlencode agent=1 \
        --data-urlencode "watchdog=model=i6300esb,action=reset" \
        --data-urlencode onboot=0 \
        --data-urlencode "ciuser=$CI_USER" --data-urlencode "sshkeys=$sshkeys_enc" \
        --data-urlencode "ipconfig0=ip=$(vm_ip "$id")/24,gw=$GATEWAY" \
        --data-urlencode "nameserver=$NAMESERVERS" --data-urlencode "searchdomain=$SEARCHDOMAIN" \
        --data-urlencode ciupgrade=0
    api_write_wait PUT "/nodes/$NODE/qemu/$id/resize" --data-urlencode disk=scsi0 --data-urlencode size=64G
done

step "8/9 start nest1 and nest2 (nest3 stays stopped by default)"
if ((START)); then
    for id in $VMID_MIN $((VMID_MIN + 1)); do
        in_range "$id" || die "internal: $id out of range"
        state=$(vm_resource "$id" | jq -r '.status // "absent"')
        if [[ $state == running ]]; then log "VM $id already running"; continue; fi
        api_write_wait POST "/nodes/$NODE/qemu/$id/status/start"
    done
else
    log "skipped (--no-start)"
fi

step "9/9 install Proxmox VE inside nest1 and nest2"
# The keepalives make the client send at least every 15 s. A session the node's own firewall
# load picked up mid-flow recovers at the next one: the client's packet opens the conntrack entry,
# and the node's replies then count as established. A transport that is really dead ends in
# 2 minutes with exit 255, instead of hanging until the node reboots. A 255 is not retried here:
# install-pve.sh may still be running in the node, and a second copy would race it for dpkg.
SSH_OPTS=(-i "$SSH_KEY" -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new
    -o "UserKnownHostsFile=$KNOWN_HOSTS" -o ConnectTimeout=5 -o BatchMode=yes -o LogLevel=ERROR
    -o ServerAliveInterval=15 -o ServerAliveCountMax=8)

wait_ssh() {   # ip
    for _ in $(seq 1 120); do
        if ssh "${SSH_OPTS[@]}" "$CI_USER@$1" true 2>/dev/null; then return 0; fi
        sleep 5
    done
    die "no SSH to $1 after 10 minutes"
}

if ((INSTALL)); then
    for id in $VMID_MIN $((VMID_MIN + 1)); do
        ip=$(vm_ip "$id")
        name=$(vm_name "$id")
        if ((!EXECUTE)); then
            log "DRY-RUN  wait for ssh $CI_USER@$ip; (scp install-pve.sh and the root password file; ssh sudo bash install-pve.sh --hostname $name --ip $ip --lan-probe $HOST_LAN_IP --root-password-file $NODE_PW_FILE; rm the password file), repeated after each reboot until it exits 0"
            continue
        fi
        wait_ssh "$ip"
        for round in 1 2 3 4; do
            log "$name: install round $round"
            rc=0
            # Copied every round: /tmp is tmpfs on Debian 13 and is empty after each reboot.
            # The password file goes over as a file (scp keeps its 0600 mode) and is removed in the
            # same session, whatever the script's exit, including before a scheduled reboot.
            scp "${SSH_OPTS[@]}" -q "$HERE/install-pve.sh" "$CI_USER@$ip:/tmp/install-pve.sh"
            scp "${SSH_OPTS[@]}" -q "$ROOT_PW_FILE" "$CI_USER@$ip:$NODE_PW_FILE"
            ssh "${SSH_OPTS[@]}" "$CI_USER@$ip" "chmod 600 $NODE_PW_FILE; sudo bash /tmp/install-pve.sh --hostname $name --ip $ip --gateway $GATEWAY --dns '$NAMESERVERS' --lan-probe $HOST_LAN_IP --root-password-file $NODE_PW_FILE; rc=\$?; rm -f $NODE_PW_FILE; exit \$rc" || rc=$?
            if ((rc == 0)); then log "$name: install complete"; break; fi
            if ((rc == 10)); then
                log "$name: rebooting, waiting for it to come back"
                sleep 30
                wait_ssh "$ip"
                continue
            fi
            if ((rc == 255)); then
                die "$name: the SSH session failed (exit 255), so install-pve.sh's own result is unknown. Check that it is no longer running in the node, then re-run build.sh --execute (each stage is safe to repeat)"
            fi
            die "$name: install-pve.sh failed with exit $rc (see output above)"
        done
        [[ $rc == 0 ]] || die "$name: install did not finish in 4 rounds"
    done
else
    log "skipped (--no-install)"
fi

log "done. $( ((EXECUTE)) || echo 'This was a dry run; nothing was written. ')Next: docs/TESTBED.md section 'Verify the estate'."
