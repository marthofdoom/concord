#!/usr/bin/env bash
# Create or upgrade a Concord container on THIS Proxmox host. Run as root.
#
#   deploy.sh --vmid N --storage S --bridge vmbr0 --ip 192.0.2.50/24|dhcp \
#             [--gateway 192.0.2.1] --config FILE --secrets FILE \
#             --template concord-X-amd64.tar.xz [--hostname NAME] [--dry-run]
#   deploy.sh --upgrade N --template concord-X-amd64.tar.xz [--dry-run]
#
# Only a container this run created is ever destroyed, and an upgrade only
# touches a container carrying the Concord marker (tag and /etc/concord-ct).
set -euo pipefail

CONCORD_GID=900   # keep in step with build-template.sh
MARKER_FILE=/etc/concord-ct
TAG=concord
HEALTH_DEADLINE=${CONCORD_HEALTH_DEADLINE:-90}

vmid= storage= bridge= ip= gateway= config= secrets= template= hostname= upgrade=
rootfs_gb=1 dry=0
created=0 workdir=

die() { echo "error: $*" >&2; exit 1; }
say() { echo "== $*"; }
# Mutating commands go through run so --dry-run shows them and does nothing.
run() {
	if ((dry)); then printf 'DRY-RUN:'; printf ' %q' "$@"; echo; else "$@"; fi
}

usage() { sed -n '2,10p' "${BASH_SOURCE[0]}"; }

while (($#)); do
	case $1 in
	--vmid) vmid=$2; shift 2 ;;
	--storage) storage=$2; shift 2 ;;
	--bridge) bridge=$2; shift 2 ;;
	--ip) ip=$2; shift 2 ;;
	--gateway) gateway=$2; shift 2 ;;
	--config) config=$2; shift 2 ;;
	--secrets) secrets=$2; shift 2 ;;
	--template) template=$2; shift 2 ;;
	--hostname) hostname=$2; shift 2 ;;
	--rootfs-gb) rootfs_gb=$2; shift 2 ;;
	--upgrade) upgrade=$2; shift 2 ;;
	--dry-run) dry=1; shift ;;
	-h | --help) usage; exit 0 ;;
	*) usage >&2; die "unknown argument: $1" ;;
	esac
done

((dry)) || [[ $(id -u) -eq 0 ]] || die "run as root on a Proxmox host"
for t in pct pvesm pvesh tar curl awk; do command -v "$t" >/dev/null || die "missing command: $t"; done
[[ -n $template && -f $template ]] || die "--template FILE (built by build-template.sh) is required"

workdir=$(mktemp -d)
cleanup() {
	local rc=$?
	if ((rc != 0 && created)); then
		say "failed; destroying container $vmid that this run created"
		# created is only set once pct create succeeded in this run.
		if pct config "$vmid" 2>/dev/null | grep -Eq "^tags:.*(^|[;, ])$TAG([;, ]|$)"; then
			pct stop "$vmid" >/dev/null 2>&1 || true
			pct destroy "$vmid" --purge 1 >/dev/null 2>&1 || echo "could not destroy $vmid; remove it by hand" >&2
		else
			echo "container $vmid lost its $TAG tag; not destroying it" >&2
		fi
	fi
	rm -rf "$workdir"
	exit "$rc"
}
trap cleanup EXIT

listen_port() { # config file -> port
	local p
	p=$(sed -n 's/^[[:space:]]*listen[[:space:]]*=[[:space:]]*"[^"]*:\([0-9][0-9]*\)".*/\1/p' "$1" | head -n1)
	echo "${p:-8010}"
}

ct_ip() { # vmid -> address of eth0
	local cfg addr
	cfg=$(pct config "$1" | sed -n 's/^net0:.*[,:]ip=\([^,]*\).*/\1/p')
	if [[ $cfg == */* ]]; then echo "${cfg%/*}"; return; fi
	addr=$(pct exec "$1" -- ip -4 -o addr show dev eth0 2>/dev/null | awk '{sub("/.*","",$4); print $4; exit}')
	[[ -n $addr ]] || return 1
	echo "$addr"
}

# Healthy = the port is listening inside the container (read from /proc, so no
# tools are needed there) AND /healthz answers from the host. busybox wget in
# the template has no TLS, and the service is HTTPS when not on loopback.
healthy() { # vmid port ip
	local vm=$1 port=$2 addr=$3 hex
	hex=$(printf '%04X' "$port")
	pct exec "$vm" -- sh -c "awk -v h=:$hex '\$2 ~ h\"\$\" && \$4==\"0A\" {f=1} END{exit !f}' /proc/net/tcp /proc/net/tcp6" >/dev/null 2>&1 || return 1
	curl -ksf --max-time 3 "https://$addr:$port/healthz" >/dev/null 2>&1 ||
		curl -sf --max-time 3 "http://$addr:$port/healthz" >/dev/null 2>&1
}

wait_healthy() { # vmid port
	local vm=$1 port=$2 addr end
	end=$((SECONDS + HEALTH_DEADLINE))
	while ((SECONDS < end)); do
		if addr=$(ct_ip "$vm") && healthy "$vm" "$port" "$addr"; then
			echo "$addr"
			return 0
		fi
		sleep 2
	done
	return 1
}

verify_concord_ct() { # vmid
	pct config "$1" >"$workdir/ct.conf" 2>/dev/null || die "container $1 does not exist"
	grep -Eq "^tags:.*(^|[;, ])$TAG([;, ]|$)" "$workdir/ct.conf" || die "container $1 is not tagged '$TAG'; refusing to touch it"
	pct status "$1" | grep -q running || die "container $1 is not running; start it first"
	pct pull "$1" "$MARKER_FILE" "$workdir/marker" >/dev/null 2>&1 || die "container $1 has no $MARKER_FILE; not a Concord container"
	head -n1 "$workdir/marker" | grep -qx 'concord-ct 1' || die "container $1 marker is not recognised"
}

# ---------------------------------------------------------------- upgrade
if [[ -n $upgrade ]]; then
	vmid=$upgrade
	[[ $vmid =~ ^[0-9]+$ ]] || die "bad VMID: $vmid"
	verify_concord_ct "$vmid"
	mkdir -p "$workdir/new" "$workdir/old"
	tar -xJf "$template" -C "$workdir/new" ./usr/local/bin/concord ./usr/local/bin/concordctl ||
		die "template does not hold the binaries"
	new=$workdir/new/usr/local/bin
	say "saving current binaries"
	pct pull "$vmid" /usr/local/bin/concord "$workdir/old/concord"
	pct pull "$vmid" /usr/local/bin/concordctl "$workdir/old/concordctl"
	pct pull "$vmid" /etc/concord/concord.toml "$workdir/concord.toml" 2>/dev/null || : >"$workdir/concord.toml"
	port=$(listen_port "$workdir/concord.toml")

	# `pct push` only works on a running container, so the swap happens inside
	# it: push beside the old binary, then rename over it with the service down.
	swap_bins() { # dir
		run pct push "$vmid" "$1/concord" /usr/local/bin/concord.new --perms 0755 --user 0 --group 0 &&
			run pct push "$vmid" "$1/concordctl" /usr/local/bin/concordctl.new --perms 0755 --user 0 --group 0 &&
			run pct exec "$vmid" -- rc-service concord stop &&
			run pct exec "$vmid" -- mv /usr/local/bin/concord.new /usr/local/bin/concord &&
			run pct exec "$vmid" -- mv /usr/local/bin/concordctl.new /usr/local/bin/concordctl &&
			run pct exec "$vmid" -- rc-service concord start
	}

	snap=pre-upgrade-$(date -u +%Y%m%d%H%M%S)
	say "snapshot $snap (skipped with a warning if the storage cannot)"
	run pct snapshot "$vmid" "$snap" || { snap=; echo "warning: no snapshot; the old binaries are kept for rollback" >&2; }
	say "replacing binaries"
	# Not under set -e: a swap that fails half way must reach the rollback.
	swapped=1
	swap_bins "$new" || swapped=0
	if ((dry)); then echo "DRY-RUN: wait up to ${HEALTH_DEADLINE}s for /healthz on port $port; roll back on failure"; exit 0; fi
	if ((swapped)) && addr=$(wait_healthy "$vmid" "$port"); then
		say "upgraded; healthy at $addr:$port"
		[[ -z $snap ]] || echo "snapshot $snap can be removed with: pct delsnapshot $vmid $snap"
		exit 0
	fi
	say "upgrade failed; restoring the previous binaries"
	# The service may already be stopped, or crash-looping.
	pct exec "$vmid" -- rc-service concord stop >/dev/null 2>&1 || true
	if pct push "$vmid" "$workdir/old/concord" /usr/local/bin/concord.new --perms 0755 --user 0 --group 0 &&
		pct push "$vmid" "$workdir/old/concordctl" /usr/local/bin/concordctl.new --perms 0755 --user 0 --group 0 &&
		pct exec "$vmid" -- mv /usr/local/bin/concord.new /usr/local/bin/concord &&
		pct exec "$vmid" -- mv /usr/local/bin/concordctl.new /usr/local/bin/concordctl &&
		pct exec "$vmid" -- rc-service concord start && wait_healthy "$vmid" "$port" >/dev/null; then
		die "upgrade failed; the previous version is running again"
	fi
	die "upgrade failed and the previous version is NOT healthy either; snapshot ${snap:-(none)} may help"
fi

# ----------------------------------------------------------------- create
[[ $vmid =~ ^[0-9]+$ && $vmid -ge 100 ]] || die "--vmid N (>= 100) is required"
[[ -n $storage && -n $bridge && -n $ip ]] || die "--storage, --bridge and --ip are required"
[[ -f $config && -f $secrets ]] || die "--config and --secrets must be existing files"
if [[ $ip != dhcp ]]; then
	[[ $ip =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$ ]] || die "--ip must be a.b.c.d/nn or dhcp"
	[[ -n $gateway ]] || die "--gateway is required with a static --ip"
	[[ $gateway =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || die "bad --gateway"
fi
[[ $bridge =~ ^[A-Za-z0-9_.-]+$ && $storage =~ ^[A-Za-z0-9_.-]+$ ]] || die "bad --bridge or --storage"
hostname=${hostname:-concord-$vmid}
[[ $hostname =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]] || die "bad --hostname"
# The secrets must not be readable by others even before they are pushed.
perm=$(stat -c %a "$secrets")
[[ $perm =~ ^[0-7]00$ ]] || die "secrets file is mode $perm; chmod 600 it first"

say "checks"
if pvesh get /cluster/nextid --vmid "$vmid" >/dev/null 2>&1; then :; else die "VMID $vmid is already in use; refusing"; fi
pct status "$vmid" >/dev/null 2>&1 && die "VMID $vmid already exists; refusing"
pvesm status --content rootdir --storage "$storage" 2>/dev/null | awk 'NR>1{f=1} END{exit !f}' ||
	die "storage '$storage' does not exist or cannot hold container volumes"

port=$(listen_port "$config")
net="name=eth0,bridge=$bridge,firewall=1,ip=$ip"
[[ $ip == dhcp ]] || net+=",gw=$gateway"

say "creating container $vmid"
run pct create "$vmid" "$template" \
	--hostname "$hostname" --ostype alpine --unprivileged 1 \
	--memory 128 --swap 0 --cores 1 --rootfs "$storage:$rootfs_gb" \
	--net0 "$net" --onboot 1 --tags "$TAG" --start 0
((dry)) || created=1

notes() { printf 'Concord\nIP: %s\nPort: %s\nURL: https://%s:%s/\nManaged by deploy/ct/deploy.sh; upgrade with --upgrade %s.\n' "$1" "$port" "$1" "$port" "$vmid"; }
if [[ $ip != dhcp ]]; then run pct set "$vmid" --description "$(notes "${ip%/*}")"; fi

# `pct push` needs a running container, so the service comes up without a
# config first and is restarted once it has one.
say "starting"
run pct start "$vmid"
say "pushing config and secrets"
run pct push "$vmid" "$config" /etc/concord/concord.toml --perms 0640 --user 0 --group "$CONCORD_GID"
run pct push "$vmid" "$secrets" /etc/concord/secrets.toml --perms 0600 --user "$CONCORD_GID" --group "$CONCORD_GID"
run pct exec "$vmid" -- rc-service concord restart
if ((dry)); then
	echo "DRY-RUN: wait up to ${HEALTH_DEADLINE}s for /healthz on port $port"
	exit 0
fi
addr=$(wait_healthy "$vmid" "$port") || die "no healthy /healthz within ${HEALTH_DEADLINE}s (inside logs: pct exec $vmid -- logread)"
[[ $ip != dhcp ]] || pct set "$vmid" --description "$(notes "$addr")"
created=0

cat <<NEXT

Concord is up: https://$addr:$port/  (self-signed certificate)

Next, create the first admin (the password is read from stdin):
  pct exec $vmid -- su -s /bin/sh concord -c '/usr/local/bin/concord user add NAME --role admin'
Logs:  pct exec $vmid -- logread
NEXT
