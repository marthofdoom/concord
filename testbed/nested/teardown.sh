#!/usr/bin/env bash
# Remove exactly what build.sh created, plus CT 9004 (nestview) when it is verified as
# nestview, and nothing else.
#
#   teardown.sh                          dry run: GETs only, prints every write it would make
#   teardown.sh --execute --yes-apply-sdn
#                                        do it. Removing the SDN zone needs an SDN apply, which
#                                        reloads host networking, hence the explicit flag. Needs a
#                                        network snapshot from this boot (the staged copy, as root: sudo /root/concord-nest-stage/net-snapshot.sh).
#
# Guarded like build.sh: an object is removed only if it matches the config
# build.sh gives it. Anything that is not ours (a VMID in range with another
# name, a storage with other content, a pool with other members) makes the
# script abort before it changes anything. A VMID 9004 that is not nestview aborts it too.
#
# What it does NOT do: it cannot delete the directory $STORAGE_PATH itself (the API
# has no way to remove a directory, and this script needs no root). The
# dir is empty after teardown; remove it by hand if you want it gone.
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$HERE/lib.sh"
# shellcheck source=site.sh
. "$HERE/site.sh"

APPLY_SDN_OK=0
for arg in "$@"; do
    case $arg in
        --execute) EXECUTE=1 ;;
        --yes-apply-sdn) APPLY_SDN_OK=1 ;;
        -h | --help) sed -n 2,19p "$0"; exit 0 ;;
        *) die "unknown argument: $arg (try --help)" ;;
    esac
done
site_load_estate
init_log teardown
if ((EXECUTE)); then log "MODE: EXECUTE (writes will happen)"; else log "MODE: dry run (GET only, nothing is written)"; fi

need ssh-keygen
preflight_common
report_firewall

# ---------------------------------------------------------------------------
# Guards (read-only, before any write)
# ---------------------------------------------------------------------------
vm_ids=()
for id in $(seq "$VMID_MIN" "$VMID_MAX"); do
    in_range "$id" || die "internal: $id out of range"
    if [[ -n $(vm_resource "$id") ]]; then
        vm_is_ours "$id" || die "VMID $id exists and is not this estate's $(vm_name "$id"). Not touching it"
        vm_ids+=("$id")
    fi
done

# CT 9004 (nestview). Its rootfs is on our storage, so the storage cannot go while it exists.
# It is found by VMID alone (it is in no pool) and removed only if it is nestview on every count.
# Its destroy uses destroy-unreferenced-disks: for a CT, PVE frees every volume owned by the VMID
# on every enabled storage with rootdir content (PVE::LXC::destroy_lxc_container ->
# PVE::Storage::vdisk_list, owner = VMID only), and a config volume only if the CT owns it. So both
# its config volumes and every 9004 volume on those storages must be on $STORAGE.
nestview=0
nv=$(vm_resource "$NESTVIEW_VMID")
if [[ -n $nv ]]; then
    nv_is="VMID $NESTVIEW_VMID exists but is not nestview"
    [[ $(jq -r .type <<<"$nv") == lxc ]] || die "$nv_is: type $(jq -r .type <<<"$nv"), not lxc. Not touching it"
    [[ $(jq -r .node <<<"$nv") == "$NODE" ]] || die "$nv_is on node $NODE. Not touching it"
    [[ $(jq -r '.pool // ""' <<<"$nv") == "" ]] || die "$nv_is as deployed: it is in pool $(jq -r .pool <<<"$nv"). Not touching it"
    [[ $(jq -r '.template // 0' <<<"$nv") == 0 ]] || die "$nv_is: it is a template. Not touching it"
    nv_cfg=$(api_get "/nodes/$NODE/lxc/$NESTVIEW_VMID/config")
    [[ $(jq -r '.data.hostname // ""' <<<"$nv_cfg") == "$NESTVIEW_HOSTNAME" ]] \
        || die "$nv_is: hostname '$(jq -r '.data.hostname // ""' <<<"$nv_cfg")'. Not touching it"
    [[ $(jq -r '(.data.description // "") | split("\n")[0]' <<<"$nv_cfg") == "$NESTVIEW_DESC" ]] \
        || die "$nv_is: its description does not start with '$NESTVIEW_DESC'. Not touching it"
    # The destroy frees config volumes from both the current config and its pending section, and
    # GET .../config (without current=1) returns only the pending-merged view. A pending change could
    # hide a current volume from the check below, so refuse while any change is pending, and check
    # the current config as well as the merged one.
    pend=$(api_get "/nodes/$NODE/lxc/$NESTVIEW_VMID/pending" | jq -r '.data[]|select(has("pending") or has("delete"))|.key')
    [[ -z $pend ]] || die "CT $NESTVIEW_VMID (nestview) has pending config changes (${pend//$'\n'/ }); apply or revert them first. Not touching it"
    nv_cur=$(api_get "/nodes/$NODE/lxc/$NESTVIEW_VMID/config?current=1")
    nv_vols=$(jq -rs '[.[].data | to_entries[] | select(.key | test("^(rootfs|mp[0-9]+|unused[0-9]+)$")) | "\(.key)=\(.value | split(",")[0])"] | unique[]' <<<"$nv_cfg$nv_cur")
    for kv in $nv_vols; do
        [[ ${kv#*=} == "$STORAGE":* ]] || die "CT $NESTVIEW_VMID (nestview) has ${kv%%=*} outside storage $STORAGE: ${kv#*=}. Remove it by hand"
    done
    # Only disk volumes count: vdisk_list lists images (content images/rootdir), and the destroy never
    # touches the CT's vzdump backups (content backup), which the unfiltered listing also returns.
    for sid in $(api_get "/nodes/$NODE/storage?content=rootdir&enabled=1" | jq -r '.data[]|select(.active == 1)|.storage'); do
        out=$(api_get "/nodes/$NODE/storage/$sid/content?vmid=$NESTVIEW_VMID" | jq -r --arg s "$STORAGE" --argjson id "$NESTVIEW_VMID" \
            '.data[]|select(.vmid==$id and (.content == "images" or .content == "rootdir"))|.volid|select(startswith($s + ":") | not)')
        [[ -z $out ]] || die "storage $sid holds disk volumes of VMID $NESTVIEW_VMID that destroy-unreferenced-disks would free: $out. Not touching CT $NESTVIEW_VMID"
    done
    inactive=$(api_get "/nodes/$NODE/storage?content=rootdir&enabled=1" | jq -r '.data[]|select(.active != 1)|.storage')
    [[ -z $inactive ]] || die "enabled rootdir storages are not active ($inactive); CT $NESTVIEW_VMID's destroy would fail half way. Not touching it"
    nestview=1
    log "CT $NESTVIEW_VMID is nestview (lxc, hostname $NESTVIEW_HOSTNAME, description marker, no pool); volumes: ${nv_vols//$'\n'/ }"
fi

storage=$(api_get /storage | jq -c --arg id "$STORAGE" '.data[]|select(.storage==$id)')
if [[ -n $storage ]]; then
    [[ $(jq -r .type <<<"$storage") == dir && $(jq -r .path <<<"$storage") == "$STORAGE_PATH" ]] \
        || die "storage '$STORAGE' exists but is not the one build.sh creates (type/path differ)"
    # Every volume must be ours: the base image, a disk of a VMID in range, or, only when CT 9004 was
    # verified as nestview above, that CT's own volumes (its destroy below frees them).
    content=$(api_get_try "/nodes/$NODE/storage/$STORAGE/content" || echo '{"data":[]}')
    foreign=$(jq -r --arg img "$STORAGE:import/$IMAGE_FILE" --argjson lo "$VMID_MIN" --argjson hi "$VMID_MAX" \
        --argjson nv "$((nestview ? NESTVIEW_VMID : -1))" --arg nvpre "$STORAGE:$NESTVIEW_VMID/" \
        '.data[]|select(.volid != $img and ((.vmid // 0) < $lo or (.vmid // 0) > $hi))
         |select((.vmid // 0) == $nv and (.volid | startswith($nvpre)) and (.volid | test("/(vm|subvol)-" + ($nv|tostring) + "-")) | not)
         |.volid' <<<"$content")
    [[ -z $foreign ]] || die "storage '$STORAGE' holds volumes that are not this estate's: $foreign"
fi

pool=$(api_get /pools | jq -c --arg id "$POOL" '.data[]|select(.poolid==$id)')
if [[ -n $pool ]]; then
    [[ $(jq -r '.comment // ""' <<<"$pool") == "$POOL_COMMENT" ]] || die "pool '$POOL' was not created by build.sh (comment differs)"
    members=$(api_get "/pools?poolid=$POOL" | jq -r '.data[0].members[]?|select(.type != null)|"\(.type)/\(.vmid // .storage)"')
    for m in $members; do
        case $m in
            qemu/900[1-3] | storage/"$STORAGE") ;;
            *) die "pool '$POOL' has a member that is not part of this estate: $m" ;;
        esac
    done
fi

user=$(api_get /access/users | jq -c --arg id "$PUSER" '.data[]|select(.userid==$id)')
if [[ -n $user ]]; then
    [[ $(jq -r '.comment // ""' <<<"$user") == "$PUSER_COMMENT" ]] || die "user '$PUSER' was not created by build.sh (comment differs)"
fi

zone_deleted=0 vnet_deleted=0
zone=$(api_get '/cluster/sdn/zones?pending=1' | jq -c --arg id "$ZONE" '.data[]|select(.zone==$id)')
vnet=$(api_get '/cluster/sdn/vnets?pending=1' | jq -c --arg id "$VNET" '.data[]|select(.vnet==$id)')
if [[ -n $zone ]]; then
    [[ $(jq -r .type <<<"$zone") == simple ]] || die "zone '$ZONE' is not the simple zone build.sh creates"
    zone_deleted=$([[ $(jq -r '.state // ""' <<<"$zone") == deleted ]] && echo 1 || echo 0)
fi
if [[ -n $vnet ]]; then
    vz=$(jq -r "$JQ_PENDING"'p("zone")' <<<"$vnet")
    [[ $vz == "$ZONE" ]] || die "vnet '$VNET' is in zone $vz, not $ZONE"
    vnet_deleted=$([[ $(jq -r '.state // ""' <<<"$vnet") == deleted ]] && echo 1 || echo 0)
fi
# Any other vnet in our zone would be deleted with it. Refuse.
if [[ -n $zone ]]; then
    other=$(api_get '/cluster/sdn/vnets?pending=1' | jq -r --arg z "$ZONE" --arg v "$VNET" "$JQ_PENDING"'.data[]|select(p("zone")==$z and .vnet != $v)|.vnet')
    [[ -z $other ]] || die "zone '$ZONE' contains vnets that are not ours: $other"
fi
foreign_pending=$(foreign_sdn_pending "$ZONE" "$VNET")
[[ -z $foreign_pending ]] || die "unrelated SDN changes are pending and would be applied too: $foreign_pending"

sdn_apply_needed=0
if [[ -n $zone || -n $vnet ]]; then sdn_apply_needed=1; fi
if ((sdn_apply_needed)); then
    log "WARNING: removing the SDN zone needs an SDN apply (PUT /cluster/sdn), which reloads the HOST's network configuration."
    # Applies to dry runs too: a dry run should fail where the real run would.
    require_no_staged_network
    if ((EXECUTE && !APPLY_SDN_OK)); then die "SDN apply needed; re-run with --yes-apply-sdn (nothing has been written yet)"; fi
    if ((EXECUTE)); then snapshot_gate; else log "(--execute will also require a network snapshot from this boot: $SNAPSHOT_CMD, staged and verified first)"; fi
fi

log "guards passed: nestview=$( ((nestview)) && echo "CT $NESTVIEW_VMID" || echo absent) vms=${vm_ids[*]:-none} storage=$([[ -n $storage ]] && echo present || echo absent) pool=$([[ -n $pool ]] && echo present || echo absent) user=$([[ -n $user ]] && echo present || echo absent) zone=$([[ -n $zone ]] && echo present || echo absent)"

# ---------------------------------------------------------------------------
# Writes, in reverse build order
# ---------------------------------------------------------------------------
step() { log "---- $*"; }

step "1/7 CT $NESTVIEW_VMID (nestview) and VMs"
if ((nestview)); then
    [[ $NESTVIEW_VMID == 9004 ]] || die "internal: nestview VMID is $NESTVIEW_VMID"
    state=$(vm_resource "$NESTVIEW_VMID" | jq -r '.status')
    if [[ $state != stopped ]]; then
        api_write_wait POST "/nodes/$NODE/lxc/$NESTVIEW_VMID/status/stop"
    fi
    api_write_wait DELETE "/nodes/$NODE/lxc/$NESTVIEW_VMID" --data-urlencode purge=1 --data-urlencode destroy-unreferenced-disks=1
    log "note: nestview's local files in $SEC_DIR (deploy key, passphrase, known_hosts) are left in place"
else
    log "CT $NESTVIEW_VMID absent"
fi
for id in "${vm_ids[@]}"; do
    in_range "$id" || die "internal: $id out of range"
    state=$(vm_resource "$id" | jq -r '.status')
    if [[ $state != stopped ]]; then
        api_write_wait POST "/nodes/$NODE/qemu/$id/status/stop"
    fi
    api_write_wait DELETE "/nodes/$NODE/qemu/$id" --data-urlencode purge=1
done
[[ ${#vm_ids[@]} -gt 0 ]] || log "no VMs to remove"

step "2/7 ACLs, token, user"
if [[ -n $user ]]; then
    acl=$(api_get /access/acl)
    for who in "users $PUSER" "tokens $FULL_TOKENID"; do
        for pr in "/pool/$POOL PVEVMAdmin,PVEPoolUser" "/storage/$STORAGE PVEDatastoreUser" "/sdn/zones/$ZONE/$VNET PVESDNUser"; do
            # shellcheck disable=SC2086
            set -- $who $pr
            kind=$1 ugid=$2 path=$3 roles=$4
            if jq -e --arg p "$path" --arg u "$ugid" '.data[]|select(.path==$p and .ugid==$u)' <<<"$acl" >/dev/null; then
                api_write PUT /access/acl --data-urlencode "path=$path" --data-urlencode "roles=$roles" \
                    --data-urlencode "$kind=$ugid" --data-urlencode delete=1 >/dev/null
            fi
        done
    done
    if api_get_try "/access/users/$PUSER/token" | jq -e --arg id "$TOKEN_NAME" '.data[]|select(.tokenid==$id)' >/dev/null 2>&1; then
        api_write DELETE "/access/users/$PUSER/token/$TOKEN_NAME" >/dev/null
    fi
    api_write DELETE "/access/users/$PUSER" >/dev/null
else
    log "user $PUSER absent"
fi

step "3/7 pool"
if [[ -n $pool ]]; then
    api_write DELETE /pools --data-urlencode "poolid=$POOL" >/dev/null
else
    log "pool absent"
fi

step "4/7 SDN objects and apply"
if [[ -n $vnet ]]; then
    # Subnet id is "<zone>-<network>-<prefix>".
    subnet_id=${ZONE}-${SUBNET/\//-}
    if api_get_try "/cluster/sdn/vnets/$VNET/subnets?pending=1" | jq -e '[.data[]|select(.state != "deleted")]|length > 0' >/dev/null 2>&1; then
        api_write DELETE "/cluster/sdn/vnets/$VNET/subnets/$subnet_id" >/dev/null
    fi
    # An object already pending deletion only needs the apply.
    if ((!vnet_deleted)); then api_write DELETE "/cluster/sdn/vnets/$VNET" >/dev/null; fi
fi
if [[ -n $zone ]] && ((!zone_deleted)); then
    api_write DELETE "/cluster/sdn/zones/$ZONE" >/dev/null
fi
if ((sdn_apply_needed)); then
    log "ROLLBACK if networking breaks (run on the host, works offline): $ROLLBACK_CMD"
    api_write_wait PUT /cluster/sdn
    # ifreload re-runs post-up lines, which can stack duplicate SNAT/CT rules; net-rollback.sh removes them in a loop.
    log "note: if 'iptables -t nat -S POSTROUTING' still shows 10.99.0.0/24 after this, run: $ROLLBACK_CMD"
else
    log "nothing to apply"
fi

step "5/7 base image and storage"
if [[ -n $storage ]]; then
    if jq -e --arg img "$STORAGE:import/$IMAGE_FILE" '.data[]|select(.volid==$img)' <<<"$content" >/dev/null; then
        api_write_wait DELETE "/nodes/$NODE/storage/$STORAGE/content/$STORAGE:import/$IMAGE_FILE"
    fi
    api_write DELETE "/storage/$STORAGE" >/dev/null
    log "note: the directory $STORAGE_PATH is left in place (empty); remove it as root if you want it gone"
else
    log "storage absent"
fi

step "6/7 local credentials"
rm_local() {   # file
    [[ -e $1 ]] || return 0
    if ((EXECUTE)); then rm -f -- "$1"; log "removed $1"; else log "DRY-RUN  rm $1"; fi
}
if [[ -f $TOKEN_FILE ]]; then
    if grep -q "^${FULL_TOKENID}=" "$TOKEN_FILE"; then rm_local "$TOKEN_FILE"; else log "leaving $TOKEN_FILE: it is not this estate's token"; fi
fi
if [[ -f $SSH_KEY.pub ]]; then
    if grep -q ' concord-nest$' "$SSH_KEY.pub"; then rm_local "$SSH_KEY"; rm_local "$SSH_KEY.pub"; else log "leaving $SSH_KEY: not this estate's key"; fi
fi
rm_local "$KNOWN_HOSTS"

step "7/7 done"
log "teardown $( ((EXECUTE)) && echo complete || echo 'dry run complete; nothing was written')"
