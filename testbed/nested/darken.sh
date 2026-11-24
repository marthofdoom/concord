#!/usr/bin/env bash
# Make a nested node "go dark" on demand, and bring it back.
#
#   darken.sh kill    <vmid|name>   stop the VM hard (power pulled; the guest gets no shutdown)
#   darken.sh pause   <vmid|name>   suspend the VM in memory (CPU frozen, guest clock stops)
#   darken.sh sever   <vmid|name>   unplug the NIC (link_down=1); the guest keeps running
#   darken.sh restore <vmid|name>   undo whichever of the above is in effect
#   darken.sh status  <vmid|name>   show state and link state; changes nothing
#
# Add --dry-run to print the call without making it. Unlike build.sh this acts
# immediately by default: going dark on demand is the point of the tool.
#
# Acts only on VMIDs 9001-9003 (nest1-nest3). It refuses any other VMID, and
# refuses a VMID in range that is not this estate's guest (name, tag, pool, NIC).
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$HERE/lib.sh"
# shellcheck source=site.sh
. "$HERE/site.sh"

EXECUTE=1
args=()
for a in "$@"; do
    case $a in
        --dry-run) EXECUTE=0 ;;
        -h | --help) sed -n 2,14p "$0"; exit 0 ;;
        *) args+=("$a") ;;
    esac
done
[[ ${#args[@]} -eq 2 ]] || die "usage: darken.sh kill|pause|sever|restore|status <vmid|nest1..nest3> [--dry-run]"
mode=${args[0]} target=${args[1]}
site_load_estate
init_log darken

case $target in
    nest[1-3]) vmid=$((VMID_MIN + ${target#nest} - 1)) ;;
    *) vmid=$target ;;
esac
in_range "$vmid" || die "refusing '$target': only VMIDs $VMID_MIN-$VMID_MAX (nest1-nest3) are allowed"

preflight_common
vm_is_ours "$vmid" || die "VMID $vmid is not this estate's $(vm_name "$vmid"); refusing"

cfg=$(api_get "/nodes/$NODE/qemu/$vmid/config" | jq -c .data)
net0=$(jq -r .net0 <<<"$cfg")
# Power state comes from status/current, not /cluster/resources: there .status is "paused" for a
# suspended VM (PVE 9.2), so a test for "running" would treat a paused VM as off. status/current's
# .status is running/stopped by whether the QEMU process exists (QemuServer::vmstatus), and
# .qmpstatus says whether that process is running or paused/suspended.
cur=$(api_get "/nodes/$NODE/qemu/$vmid/status/current" | jq -c .data)
state=$(jq -r .status <<<"$cur")
qmp=$(jq -r '.qmpstatus // .status' <<<"$cur")
linkdown=no
[[ $net0 == *link_down=1* ]] && linkdown=yes
log "VM $vmid ($(vm_name "$vmid")): status=$state qmp=$qmp cluster-status=$(vm_resource "$vmid" | jq -r .status) link_down=$linkdown"

# QMP states darken can act on. Every other state of a live process (io-error, internal-error,
# guest-panicked, shutdown, or one QEMU adds later) is a fault darken did not cause: a blind
# stop, cont or config change would hide it, so every mode except status refuses and names it.
# prelaunch counts as paused, as in PVE's vm_is_paused: a VM started with --paused (a vzdump of a
# stopped VM, a live-restore) is left there by an interrupted job, and vm_resume's cont undoes it.
case $state:$qmp in
    stopped:* | running:running | running:paused | running:suspended | running:prelaunch) ;;
    *)
        msg="VM $vmid is in an unexpected state (status=$state qmp=$qmp)"
        [[ $mode == status ]] || die "$msg; refusing '$mode', look at the VM first"
        log "$msg; every mode but status refuses it" ;;
esac

base=/nodes/$NODE/qemu/$vmid
case $mode in
    status) ;;
    kill)
        [[ $state == running ]] || die "VM $vmid is not running (no QEMU process)"
        api_write_wait POST "$base/status/stop" ;;
    pause)
        [[ $qmp == running ]] || die "VM $vmid is not in the running state (qmp=$qmp)"
        api_write_wait POST "$base/status/suspend" ;;
    sever)
        [[ $state == running ]] || log "VM is not running; the setting is saved and applies at next start"
        [[ $linkdown == no ]] || die "NIC already severed"
        api_write PUT "$base/config" --data-urlencode "net0=${net0},link_down=1" >/dev/null ;;
    restore)
        # A paused VM still has its process (state=running), so it gets resume only, never start.
        # The guard above leaves only stopped or a running process in one of four qmp states.
        if [[ $state == stopped ]]; then api_write_wait POST "$base/status/start"
        elif [[ $qmp != running ]]; then api_write_wait POST "$base/status/resume"; fi
        if [[ $linkdown == yes ]]; then
            fixed=${net0//,link_down=1/}
            api_write PUT "$base/config" --data-urlencode "net0=$fixed" >/dev/null
        fi
        if [[ $qmp == running && $linkdown == no ]]; then log "nothing to restore: VM is running, resumed, and linked"; fi ;;
    *) die "unknown mode '$mode' (kill|pause|sever|restore|status)" ;;
esac
log "done: $mode $(vm_name "$vmid")"
