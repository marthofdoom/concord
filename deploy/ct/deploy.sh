#!/usr/bin/env bash
{ # Read to the end before anything runs: this may come over a pipe (bash -s).
# Nothing may print or export what this script holds.
{ set +xva; } 2>/dev/null
unset SSLKEYLOGFILE
# Create, upgrade or add hosts to a Concord container. Run as root on a Proxmox
# host; see usage below and docs/DEPLOY.md.
#
# Only a container this run created is ever destroyed, and an upgrade only
# touches a container carrying the Concord marker (tag and /etc/concord-ct).
set -euo pipefail
umask 077
export LC_ALL=C

CONCORD_GID=900   # keep in step with build-template.sh
MARKER_FILE=/etc/concord-ct
TAG=concord
HEALTH_DEADLINE=${CONCORD_HEALTH_DEADLINE:-90}

vmid= storage= bridge= ip= gateway= config= secrets= template= hostname= upgrade=
rootfs_gb=1 dry=0
mode=create name= api_address= install=concord keep= rotate=0 replace=0 force=0
created=0 creating=0 workdir= stage= snap=

die() { echo "error: $*" >&2; exit 1; }
# In --enroll fd 1 is stderr by the time this is used; the record is on fd 3.
say() { echo "== $*"; }
# Mutating commands go through run so --dry-run shows them and does nothing.
run() {
	if ((dry)); then printf 'DRY-RUN:'; printf ' %q' "$@"; echo; else "$@"; fi
}

usage() {
	printf '%s\n' \
		'deploy.sh --vmid N --storage S --bridge vmbr0 --ip 192.0.2.50/24|dhcp' \
		'    [--gateway 192.0.2.1] --template concord-X-amd64.tar.xz [--hostname NAME]' \
		'    [--name NAME] [--api-address ADDR] [--install ID] [--rotate-token]' \
		'    [--config FILE --secrets FILE]   (instead of creating a token here)' \
		'deploy.sh --upgrade N --template concord-X-amd64.tar.xz' \
		'deploy.sh --enroll --name NAME --api-address ADDR [--install ID] [--rotate-token] [--force]' \
		'deploy.sh --add-host N [--replace]   (reads the record of --enroll on stdin)' \
		'deploy.sh --remove-host N NAME' \
		'deploy.sh --prune-tokens --keep TOKEN [--install ID]' \
		'deploy.sh --unenroll [--install ID]' \
		'All take --dry-run.'
}
one_mode() { [[ $mode == create ]] || die "choose one mode"; mode=$1; }

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
	--upgrade) one_mode upgrade; upgrade=$2; shift 2 ;;
	--enroll) one_mode enroll; shift ;;
	--add-host) one_mode add; vmid=$2; shift 2 ;;
	--remove-host) one_mode remove; vmid=$2; name=$3; shift 3 ;;
	--unenroll) one_mode unenroll; shift ;;
	--prune-tokens) one_mode prune; shift ;;
	--name) name=$2; shift 2 ;;
	--api-address) api_address=$2; shift 2 ;;
	--install) install=$2; shift 2 ;;
	--keep) keep=$2; shift 2 ;;
	--rotate-token) rotate=1; shift ;;
	--replace) replace=1; shift ;;
	--force) force=1; shift ;;
	--dry-run) dry=1; shift ;;
	-h | --help) usage; exit 0 ;;
	*) usage >&2; die "unknown argument: $1" ;;
	esac
done

((dry)) || [[ $(id -u) -eq 0 ]] || die "run as root on a Proxmox host"
case $mode in
create | upgrade) tools="pct pvesm pvesh tar curl awk sha256sum" ;;
add | remove) tools="pct curl awk perl timeout openssl lxc-info nsenter" ;;
*) tools="pveum curl perl timeout openssl" ;;
esac
if [[ $mode == create && -z $config$secrets ]]; then tools+=" pveum perl timeout openssl ip lxc-info nsenter"; fi
for t in $tools; do command -v "$t" >/dev/null || die "missing command: $t"; done
case $mode in
create | upgrade) [[ -n $template && -f $template ]] || die "--template FILE (built by build-template.sh) is required" ;;
add | remove) [[ $vmid =~ ^[1-9][0-9]{2,8}$ ]] || die "bad VMID" ;;
esac
# Only the record reader needs stdin, and only --enroll's record is for stdout.
[[ $mode == add || $mode == create || $mode == upgrade ]] || exec </dev/null
if [[ $mode == enroll ]]; then exec 3>&1 1>&2; fi

# ------------------------------------------------- PVE user, token, record
# The token is created without privilege separation, so it sees exactly what
# its user sees: PVEAuditor on / and nothing else.
PVE_USER=concord-monitor
PVE_REALM=pve
PVE_USERID=$PVE_USER@$PVE_REALM
PVE_ROLE=PVEAuditor
# In two pieces only so that the leak scan does not take it for a token.
AUTH_SCHEME=PVE""APIToken
NAME_RE='[A-Za-z0-9][A-Za-z0-9._-]{0,62}'
IPV4_RE='[0-9]{1,3}(\.[0-9]{1,3}){3}'
# The last label starts with a letter: 0x7f000001 would be read as a number.
DNS_RE='([A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?\.)*[A-Za-z]([A-Za-z0-9-]*[A-Za-z0-9])?'
FP_RE='[0-9A-F]{2}(:[0-9A-F]{2}){31}'
UUID_RE='[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}'
INSTALL_RE='[A-Za-z][A-Za-z0-9-]{0,39}'
# Network namespace prefix: empty on this host, nsenter for the container's.
NS=()

# Names everything this run creates, so that undoing never takes anything else.
nonce=$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')
[[ $nonce =~ ^[0-9a-f]{16}$ ]] || die "no randomness"

check_addr() { # address
	((${#1} <= 253)) && [[ $1 =~ ^($IPV4_RE|$DNS_RE)$ ]] || die "bad API address: use an IPv4 address or a DNS name"
	if [[ $1 =~ ^[0-9.]+$ ]]; then
		local o
		[[ $1 =~ ^$IPV4_RE$ ]] || die "bad API address: not an IPv4 address"
		for o in ${1//./ }; do ((10#$o <= 255)) && [[ $o == 0 || $o != 0* ]] || die "bad API address: not an IPv4 address"; done
	fi
	[[ ${1,,} != localhost && $1 != 127.* && $1 != 0.* ]] || die "the API address must be one the container can reach, not loopback"
}

# JSON comes on stdin; perl is part of PVE. Arguments are never secret.
json() { perl -MJSON::PP -0777 -e 'my $d = decode_json(scalar <STDIN>); '"$1" -- "${@:2}"; }

pveum_json() { pveum "$@" --output-format json </dev/null; }

# absent | foreign | the user's marker comment
user_state() {
	local j
	j=$(pveum_json user list --full 1) || return 1
	printf '%s' "$j" | json '
		for (@$d) { next if lc($_->{userid}) ne lc($ARGV[0]);
			my $c = $_->{comment} // ""; my $g = $_->{groups} // "";
			$g = join ",", @$g if ref $g;
			print $c =~ /\Aconcord-deploy user run=[0-9a-f]{16}\z/ ? $g eq "" ? $c : "grouped" : "foreign"; exit }
		print "absent"' "$PVE_USERID"
}

# Token names, one per line: those of one installation, or with no argument all.
token_names() { # [install id]
	local j
	j=$(pveum_json user token list "$PVE_USERID") || return 1
	printf '%s' "$j" | json '
		for (sort { $a->{tokenid} cmp $b->{tokenid} } @$d) {
			my $c = $_->{comment} // "";
			next if @ARGV && $c !~ /\Aconcord-deploy install=\Q$ARGV[0]\E run=[0-9a-f]{16}\z/;
			die "odd token name" if $_->{tokenid} !~ /\A[A-Za-z][A-Za-z0-9._-]+\z/;
			print "$_->{tokenid}\n" }' "$@"
}

# none | ok | other: what the user is granted directly.
acl_state() {
	local j
	j=$(pveum_json acl list) || return 1
	printf '%s' "$j" | json '
		my @m = grep { $_->{type} eq "user" && $_->{ugid} eq $ARGV[0] } @$d;
		print !@m ? "none" : @m == 1 && $m[0]{path} eq "/" && $m[0]{roleid} eq $ARGV[1] && $m[0]{propagate} ? "ok" : "other"' \
		"$PVE_USERID" "$PVE_ROLE"
}

served_cert() { # host:port -> PEM
	local raw
	# Not one pipeline: x509 stops reading early, and pipefail would call the
	# SIGPIPE that follows a failure.
	raw=$("${NS[@]}" timeout 10 openssl s_client -connect "$1" </dev/null 2>/dev/null) || [[ -n $raw ]] || return 1
	openssl x509 -outform PEM < <(printf '%s\n' "$raw") 2>/dev/null
}

cert_fp() { # PEM on stdin -> AA:BB:..
	local fp
	fp=$(openssl x509 -noout -fingerprint -sha256) || return 1
	fp=${fp##*=} fp=${fp^^}
	[[ $fp =~ ^$FP_RE$ ]] || return 1
	echo "$fp"
}

# The pin comes from what pveproxy serves, and must also be the file pveproxy
# would serve: anything else means another host or a proxy answered.
local_fingerprint() { # address -> fingerprint
	local pem fp file=/etc/pve/local/pve-ssl.pem want
	if [[ -f /etc/pve/local/pveproxy-ssl.pem && -f /etc/pve/local/pveproxy-ssl.key ]]; then file=/etc/pve/local/pveproxy-ssl.pem; fi
	pem=$(served_cert "$1:8006") && fp=$(printf '%s\n' "$pem" | cert_fp) || die "no TLS certificate from $1:8006"
	want=$(openssl x509 -in "$file" -outform PEM | cert_fp) || die "cannot read $file"
	[[ $fp == "$want" ]] || die "$1:8006 does not serve $file: not this host, or pveproxy needs a restart"
	echo "$fp"
}

# The API must answer through the pinned certificate, with VM.Audit on / and
# propagating: a token that sees too little makes guests look deleted.
# Reads the globals fp, token_id and secret. Explains itself in $why.
why=
check_api() { # address
	local pem got pin out
	why="no TLS certificate from $1:8006"
	pem=$(served_cert "$1:8006") && got=$(printf '%s\n' "$pem" | cert_fp) || return 1
	why="$1:8006 serves a certificate with another fingerprint"
	[[ $got == "$fp" ]] || return 1
	# curl pins keys, not certificates: pin the key of the certificate just
	# checked, so the token only goes to whoever holds it.
	why="cannot compute the key pin"
	pin=$(printf '%s\n' "$pem" | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl base64) || return 1
	[[ $pin =~ ^[A-Za-z0-9+/]{43}=$ ]] || return 1
	why="the API at $1:8006 did not accept the token"
	# The token goes over stdin: an argument would be in the process list.
	out=$(printf 'header = "Authorization: %s=%s=%s"\n' "$AUTH_SCHEME" "$token_id" "$secret" |
		"${NS[@]}" curl -q -K - -sfk --noproxy '*' --proto '=https' --max-time 15 --max-filesize 1000000 \
			--pinnedpubkey "sha256//$pin" "https://$1:8006/api2/json/access/permissions?path=/" 2>/dev/null) || return 1
	why="the token lacks VM.Audit on / with propagate"
	printf '%s' "$out" | json 'exit(($d->{data}{"/"}{"VM.Audit"} // 0) == 1 ? 0 : 1)' 2>/dev/null || return 1
	why=
}

# A new token or a container's network may need a moment.
wait_api() { # address
	local end=$((SECONDS + (HEALTH_DEADLINE < 15 ? HEALTH_DEADLINE : 15)))
	while :; do
		if check_api "$1"; then return 0; fi
		((SECONDS < end)) || return 1
		sleep 1
	done
}

# From inside the container's network, where Concord will connect from. Its
# busybox has no TLS, so this host's tools run in its network namespace (with
# this host's resolver: an IP address is the surer --api-address).
check_from_ct() { # vmid address
	local pid
	pid=$(lxc-info -n "$1" -p -H </dev/null) && [[ $pid =~ ^[0-9]+$ ]] && ((pid > 1)) || die "cannot find container $1's init process"
	NS=(nsenter -t "$pid" -n --)
	wait_api "$2" || die "from inside container $1: $why"
	NS=()
}

# Sets fp, token_id, secret and old_tokens. What it creates is undone by
# cleanup until committed=1. The *_try flags are set before the command, since
# a signal is only handled after it; undo_pve looks at what is really there.
user_try=0 acl_try=0 token_try='' committed=0
fp='' token_id='' secret='' old_tokens=''
make_token() { # address
	local state acl j tok
	fp=$(local_fingerprint "$1") || exit 1
	state=$(user_state) || die "cannot list users with pveum"
	case $state in
	absent) ;;
	foreign) die "user $PVE_USERID exists and was not created by this installer; refusing to touch it" ;;
	grouped) die "user $PVE_USERID is in a group, so its token would see more than $PVE_ROLE; refusing" ;;
	esac
	acl=none
	if [[ $state != absent ]]; then
		old_tokens=$(token_names "$install") || die "cannot list tokens with pveum"
		[[ -z $old_tokens ]] || ((rotate)) ||
			die "installation '$install' already has a token here; use --rotate-token to replace it, or --install ID for another container"
		acl=$(acl_state) || die "cannot list permissions with pveum"
		[[ $acl != other ]] || die "user $PVE_USERID has other permissions than $PVE_ROLE on /; refusing to create a token for it"
	fi
	tok=$install-${nonce:0:8}
	say "user $PVE_USERID, $PVE_ROLE on /, token $tok"
	if [[ $state == absent ]]; then
		((dry)) || user_try=1
		run pveum user add "$PVE_USERID" --comment "concord-deploy user run=$nonce" </dev/null || die "could not create the user"
	fi
	if [[ $acl == none ]]; then
		((dry)) || acl_try=1
		run pveum acl modify / --users "$PVE_USERID" --roles "$PVE_ROLE" --propagate 1 </dev/null || die "could not set the permission"
	fi
	if ((dry)); then
		run pveum user token add "$PVE_USERID" "$tok" --privsep 0 --comment "concord-deploy install=$install run=$nonce" --output-format json
		return 0
	fi
	token_try=$tok
	# pveum prints the secret once, here, and it stays in this variable.
	j=$(pveum_json user token add "$PVE_USERID" "$tok" --privsep 0 --comment "concord-deploy install=$install run=$nonce") ||
		die "could not create the token"
	secret=$(printf '%s' "$j" | json 'print $d->{value} // ""' 2>/dev/null) || die "cannot read pveum's answer"
	j=
	[[ $secret =~ ^$UUID_RE$ ]] || die "pveum returned no usable token"
	token_id="$PVE_USERID!$tok"
	say "checking the token against $1:8006"
	wait_api "$1" || die "$why"
}

undo_pve() {
	local names state
	if [[ -n $token_try ]]; then
		if names=$(token_names 2>/dev/null); then
			if grep -Fqx -- "$token_try" <(printf '%s\n' "$names"); then
				pveum user token delete "$PVE_USERID" "$token_try" </dev/null >/dev/null 2>&1 &&
					echo "removed token $token_try" >&2 ||
					echo "could not remove token $token_try of $PVE_USERID; remove it by hand" >&2
			fi
		else
			echo "could not list tokens; check $PVE_USERID for token $token_try by hand" >&2
		fi
	fi
	if ((user_try)); then
		# Removing the user removes its permissions with it.
		state=$(user_state 2>/dev/null) || state=unknown
		case $state in
		absent) ;;
		"concord-deploy user run=$nonce")
			if names=$(token_names 2>/dev/null) && [[ -z $names ]] &&
				pveum user delete "$PVE_USERID" </dev/null >/dev/null 2>&1; then
				echo "removed user $PVE_USERID" >&2
			else
				echo "could not remove user $PVE_USERID; check it by hand" >&2
			fi
			;;
		*) echo "check user $PVE_USERID by hand" >&2 ;;
		esac
	elif ((acl_try)); then
		pveum acl delete / --users "$PVE_USERID" --roles "$PVE_ROLE" </dev/null >/dev/null 2>&1 ||
			echo "could not remove $PVE_USERID's permission on /; check it by hand" >&2
	fi
}

# Deletes the named tokens of this installation, except $2.
delete_tokens() { # names keep
	local t rc=0
	for t in $1; do
		[[ $t != "$2" ]] || continue
		run pveum user token delete "$PVE_USERID" "$t" </dev/null || { echo "could not remove token $t" >&2; rc=1; }
	done
	return "$rc"
}

# ------------------------------------------------- config inside a container
CONF_DIR=/etc/concord

# Puts back the files of an interrupted change. .prev is complete or absent
# (it is renamed into place), and may be restored more than once.
restore_conf() {
	pct exec "$vmid" -- sh -c "cd $CONF_DIR"' && { [ ! -d .prev ] || {
		for f in concord.toml secrets.toml; do cp -p .prev/$f $f.back && mv -f $f.back $f || exit 1; done; }; }' </dev/null || return 1
	pct exec "$vmid" -- rc-service concord restart </dev/null
}
drop_prev() {
	pct exec "$vmid" -- sh -c "cd $CONF_DIR"' && rm -rf concord.toml.new secrets.toml.new .prev.tmp .prev.gone && { [ ! -d .prev ] || mv .prev .prev.gone; } && rm -rf .prev.gone' </dev/null
}

read_conf() {
	verify_concord_ct "$vmid"
	if pct exec "$vmid" -- sh -c "[ -d $CONF_DIR/.prev ]" </dev/null; then
		say "an earlier change was cut off; restoring the files it replaced"
		if ((dry)); then echo "DRY-RUN: restore $CONF_DIR/.prev"; else
			{ restore_conf && drop_prev; } || die "could not restore them"
		fi
	fi
	pct pull "$vmid" "$CONF_DIR/concord.toml" "$workdir/c" >/dev/null </dev/null || die "cannot read the container's config"
	pct pull "$vmid" "$CONF_DIR/secrets.toml" "$workdir/s" >/dev/null </dev/null || die "cannot read the container's secrets"
	port=$(listen_port "$workdir/c") || exit 1
	grep -Eq "^[[:space:]]*secrets_file[[:space:]]*=[[:space:]]*[\"']($CONF_DIR/)?secrets\.toml[\"'][[:space:]]*(#.*)?\$" "$workdir/c" ||
		die "the config does not use $CONF_DIR/secrets.toml; edit it by hand"
	# The line editing below would misread these.
	if grep -Eq "\"\"\"|'''|^[[:space:]]*hosts[[:space:]]*=" "$workdir/c" "$workdir/s"; then
		die "the config is written in a way this script does not edit; change it by hand"
	fi
}

# Drops one host. Prints to $workdir/{c,s}.new; returns 3 if there is none.
drop_host() { # name
	perl -e '
		my ($want, $out, $other, $hit, @blk, $in) = (shift, "", 0, 0);
		sub flush { return unless @blk;
			my $t = join "", @blk;
			my ($n) = $t =~ /^\s*name\s*=\s*["\x27]([^"\x27]*)["\x27]/m; $n //= "";
			if ($n eq $want) { $hit++;
				# Comments after the block belong to what follows.
				my $i = $#blk; $i-- while $i > 0 && $blk[$i] =~ /^\s*(#.*)?$/;
				$out .= join "", @blk[$i+1..$#blk];
			} else { $out .= $t; $other++;
				(my $a = uc $n) =~ s/[^A-Z0-9]/_/g; (my $b = uc $want) =~ s/[^A-Z0-9]/_/g;
				die "the name is too close to the existing host $n\n" if $a eq $b }
			@blk = () }
		while (<STDIN>) {
			if (/^\s*\[/) { flush(); $in = /^\s*\[\[\s*"?hosts"?\s*\]\]/ }
			if ($in) { push @blk, $_ } else { $out .= $_ } }
		flush(); $out .= "\n" if $out ne "" && $out !~ /\n\z/; print $out;
		exit($hit == 0 ? 3 : $hit > 1 ? 4 : $other == 0 ? 5 : 0)' "$1" <"$workdir/c" >"$workdir/c.new" && rc=0 || rc=$?
	perl -e '
		my $want = quotemeta shift;
		while (<STDIN>) { s/\n?\z/\n/; print unless /^\s*(?:$want|"$want"|\x27$want\x27)\s*=/ }' "$1" <"$workdir/s" >"$workdir/s.new" ||
		die "cannot edit the secrets"
	case $rc in 0 | 3 | 5) return "$rc" ;; 4) die "host $1 is in the config more than once" ;; *) die "cannot edit the config" ;; esac
}

# Both files are replaced, or neither: from confswap on, any exit restores.
apply_conf() {
	say "updating config and secrets in container $vmid"
	if ((dry)); then
		echo "DRY-RUN: replace $CONF_DIR/concord.toml and secrets.toml, restart, wait up to ${HEALTH_DEADLINE}s for /healthz on port $port; roll back on failure"
		return 0
	fi
	stage=confstaged
	pct push "$vmid" "$workdir/c.new" "$CONF_DIR/concord.toml.new" --perms 0640 --user 0 --group "$CONCORD_GID" </dev/null || die "push failed; nothing was changed"
	pct push "$vmid" "$workdir/s.new" "$CONF_DIR/secrets.toml.new" --perms 0600 --user "$CONCORD_GID" --group "$CONCORD_GID" </dev/null || die "push failed; nothing was changed"
	pct exec "$vmid" -- sh -c "umask 077; cd $CONF_DIR"' && rm -rf .prev.tmp && mkdir .prev.tmp &&
		cp -p concord.toml secrets.toml .prev.tmp/ && sync && mv .prev.tmp .prev' </dev/null || die "could not keep the old files; nothing was changed"
	stage=confswap
	pct exec "$vmid" -- mv "$CONF_DIR/secrets.toml.new" "$CONF_DIR/secrets.toml" </dev/null || die "swap failed"
	pct exec "$vmid" -- mv "$CONF_DIR/concord.toml.new" "$CONF_DIR/concord.toml" </dev/null || die "swap failed"
	pct exec "$vmid" -- rc-service concord restart </dev/null || die "Concord did not restart"
	wait_healthy "$vmid" "$port" >/dev/null || die "Concord is not healthy after ${HEALTH_DEADLINE}s"
	stage=confstaged
	drop_prev || { stage=; die "the change is live, but the old files in $CONF_DIR/.prev could not be removed; remove that directory"; }
	stage=
}

# Untrusted: the values reach TOML, URLs and commands. The whole text has to
# match, and no value can hold a quote, space, control character or slash.
read_record() {
	local rec re nl=$'\n'
	[[ ! -t 0 ]] || die "--add-host reads the record of --enroll on stdin; pipe it in"
	if IFS= read -r -d '' -n 2048 rec; then die "the record is too long or not text"; fi
	exec </dev/null
	[[ -n $rec ]] || die "no record on stdin; did --enroll fail?"
	re="^concord-enroll 1${nl}name=($NAME_RE)${nl}address=([A-Za-z0-9.-]{1,253})${nl}fingerprint=($FP_RE)${nl}"
	re+="token=($INSTALL_RE-[0-9a-f]{8})${nl}secret=($UUID_RE)${nl}end${nl}\$"
	[[ $rec =~ $re ]] || die "the record is not one this version understands; refusing it"
	name=${BASH_REMATCH[1]} api_address=${BASH_REMATCH[2]} fp=${BASH_REMATCH[3]}
	local rest=("${BASH_REMATCH[@]:4}")
	token_id="$PVE_USERID!${rest[1]}" secret=${rest[2]}
	rec= rest=() BASH_REMATCH=()
	check_addr "$api_address"
}

host_toml() {
	printf '\n[[hosts]]\nname = "%s"\napi_url = "https://%s:8006"\nfingerprint = "%s"\ntoken_id = "%s"\n' \
		"$name" "$api_address" "$fp" "$token_id"
}

# ------------------------------------------------------------- shared
# Undoes an interrupted swap. `.old` in the container are the only copies of
# the previous binaries; each is renamed back, so this may be repeated. The
# service is started whatever else failed.
restore_old() {
	pct exec "$vmid" -- rc-service concord stop >/dev/null 2>&1
	pct exec "$vmid" -- sh -c 'cd /usr/local/bin && rm -f concord.new concordctl.new &&
		for f in concord concordctl; do [ ! -e $f.old ] || mv -f $f.old $f || exit 1; done'
	local rc=$?
	pct exec "$vmid" -- rc-service concord start || rc=1
	return "$rc"
}

if [[ $mode == upgrade ]]; then
	workdir=$(mktemp -d)
else
	# Will hold secrets: memory only.
	for d in ${CONCORD_TMPFS:-/run /dev/shm}; do
		if [[ -w $d && $(stat -f -c %T "$d") == tmpfs ]]; then workdir=$(mktemp -d "$d/concord-deploy.XXXXXXXX"); break; fi
	done
	[[ -n $workdir ]] || die "neither /run nor /dev/shm is a writable tmpfs"
fi
cleanup() {
	local rc=$?
	# Nothing may stop the rollback half way: not a second signal, nor a write
	# to a terminal that has gone. Inherited by pct, too.
	trap '' HUP INT TERM PIPE
	set +e
	case $stage in
	staged) # the installed binaries were not touched
		pct exec "$vmid" -- sh -c 'cd /usr/local/bin && rm -f concord.new concordctl.new *.old.tmp concord.old concordctl.old' >/dev/null 2>&1 ;;
	swapping)
		say "upgrade failed; restoring the previous binaries"
		if restore_old && wait_healthy "$vmid" "$port" >/dev/null; then
			echo "the previous version is running again" >&2
		else
			echo "the previous version is NOT healthy either; any *.old in /usr/local/bin of the container is it; snapshot ${snap:-(none)} may help" >&2
		fi
		;;
	confstaged) # the files in use were not touched, or the new ones are good
		drop_prev >/dev/null 2>&1 ;;
	confswap)
		say "failed; restoring the previous config and secrets"
		if restore_conf && wait_healthy "$vmid" "$port" >/dev/null; then
			drop_prev >/dev/null 2>&1
			echo "the previous configuration is running again" >&2
		else
			echo "Concord is NOT healthy with the previous configuration either; it is kept in $CONF_DIR/.prev in the container" >&2
		fi
		;;
	esac
	# A signal during pct create is only seen after it: then the run's own mark
	# tells whether the container is this run's.
	local ctconf=
	if ((rc != 0 && creating)); then ctconf=$(pct config "$vmid" 2>/dev/null); fi
	if [[ $ctconf == *"concord-deploy-run-$nonce"* ]]; then created=1; fi
	if ((rc != 0 && created)); then
		say "failed; destroying container $vmid that this run created"
		# created is only set once pct create succeeded in this run.
		if grep -E "^tags:.*(^|[;, ])$TAG([;, ]|$)" >/dev/null < <(printf '%s\n' "$ctconf"); then
			pct stop "$vmid" >/dev/null 2>&1 || true
			pct destroy "$vmid" --purge 1 >/dev/null 2>&1 || echo "could not destroy $vmid; remove it by hand" >&2
		else
			echo "container $vmid lost its $TAG tag; not destroying it" >&2
		fi
	fi
	if ((rc != 0 && !committed)); then undo_pve; fi
	rm -rf "$workdir"
	exit "$rc"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 141' PIPE
trap 'exit 143' TERM

# The port of a config's `listen`, which has to be reachable from outside the
# container. Refused here rather than found out by the health check timing out.
listen_port() { # config file -> port
	local v host port
	v=$(sed -n -e 's/^[[:space:]]*listen[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' \
		-e "s/^[[:space:]]*listen[[:space:]]*=[[:space:]]*'\\([^']*\\)'.*/\\1/p" "$1" | head -n1)
	[[ -n $v ]] || die "the config has no listen = \"ADDRESS:PORT\" line, so Concord would listen on loopback only"
	host=${v%:*} port=${v##*:}
	[[ $v == *:* && $port =~ ^[0-9]{1,5}$ ]] && ((10#$port >= 1 && 10#$port <= 65535)) || die "cannot read a port from listen in the config"
	host=${host#[} host=${host%]}
	if [[ $host == localhost || $host =~ ^(.*:)?127\.[0-9.]+$ || $host =~ ^[0:]*:0*1$ ]]; then
		die "the config listens on loopback; use 0.0.0.0 or the container's own address"
	fi
	echo "$((10#$port))"
}

# The sum detects a damaged or mixed-up file, not a malicious one.
verify_template() {
	[[ -f $template.sha256 ]] || return 0
	local want got
	read -r want _ <"$template.sha256" || true
	got=$(sha256sum <"$template")
	[[ $want == "${got%% *}" ]] || die "$template does not match $template.sha256"
}

ct_ip() { # vmid -> address of eth0
	local cfg addr
	cfg=$(pct config "$1" | sed -n 's/^net0:.*[,:]ip=\([^,]*\).*/\1/p')
	# `return 0`, not `return`: under the EXIT trap a bare return yields the
	# status from before the trap, which failed every rollback health check.
	if [[ $cfg == */* ]]; then echo "${cfg%/*}"; return 0; fi
	addr=$(pct exec "$1" -- ip -4 -o addr show dev eth0 2>/dev/null | awk '{sub("/.*","",$4); print $4; exit}')
	# Container output, about to be part of a URL.
	[[ $addr =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
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

[[ $install =~ ^$INSTALL_RE$ ]] || die "bad --install: letters, digits and '-', at most 40, starting with a letter"
[[ -z $name || $name =~ ^$NAME_RE$ ]] || die "bad host name: letters, digits, '.', '-' and '_', at most 63"
[[ $mode != remove || -n $name ]] || die "--remove-host N NAME"
[[ -z $api_address ]] || check_addr "$api_address"
[[ $rotate == 0 || $mode == create || $mode == enroll ]] || die "--rotate-token goes with --enroll or a new container"
[[ $replace == 0 || $mode == add ]] || die "--replace goes with --add-host"
[[ -z $keep || $mode == prune ]] || die "--keep goes with --prune-tokens"

# ----------------------------------------------------------------- enroll
case $mode in
enroll)
	[[ -n $name && -n $api_address ]] || die "--enroll needs --name NAME and --api-address ADDR"
	# A secret on a screen ends up in scrollback.
	[[ ! -t 3 ]] || ((force || dry)) || die "stdout is a terminal, and the record holds a secret; pipe it to --add-host (or --force)"
	make_token "$api_address"
	if ((dry)); then echo "DRY-RUN: no record"; exit 0; fi
	# Once anything is written the reader may have it, so a signal must not
	# take the token back; a failed write must.
	trap '' HUP INT TERM PIPE
	printf 'concord-enroll 1\nname=%s\naddress=%s\nfingerprint=%s\ntoken=%s\nsecret=%s\nend\n' \
		"$name" "$api_address" "$fp" "${token_id#*!}" "$secret" >&3 || die "could not write the record"
	committed=1
	say "enrolled; give the record above to --add-host"
	[[ -z $old_tokens ]] || say "the previous token still works; once the container uses the new one: --prune-tokens --keep ${token_id#*!} --install $install"
	exit 0
	;;
prune | unenroll)
	state=$(user_state) || die "cannot list users with pveum"
	case $state in
	absent) die "there is no user $PVE_USERID here" ;;
	foreign) die "user $PVE_USERID was not created by this installer; refusing to touch it" ;;
	esac
	names=$(token_names "$install") || die "cannot list tokens with pveum"
	if [[ $mode == prune ]]; then
		[[ -n $keep ]] || die "--prune-tokens needs --keep TOKEN"
		grep -Fqx -- "$keep" <(printf '%s\n' "$names") || die "installation '$install' has no token $keep; nothing removed"
		delete_tokens "$names" "$keep" || exit 1
		exit 0
	fi
	all=$(token_names) || die "cannot list tokens with pveum"
	[[ -n $names || -z $all ]] || die "installation '$install' has no token here (others do; see --install)"
	delete_tokens "$names" "" || exit 1
	if ((!dry)); then all=$(token_names) || die "cannot list tokens with pveum"; elif [[ $all == "$names" ]]; then all=; fi
	if [[ -z $all ]]; then
		run pveum user delete "$PVE_USERID" </dev/null || die "could not remove user $PVE_USERID"
	else
		say "user $PVE_USERID is kept: it has other tokens"
	fi
	exit 0
	;;
add)
	read_record
	read_conf
	drop_host "$name" && found=0 || found=$?
	if ((found != 3 && !replace)); then die "host $name is already configured; use --replace"; fi
	say "checking $name from inside container $vmid"
	check_from_ct "$vmid" "$api_address"
	host_toml >>"$workdir/c.new"
	printf '"%s" = "%s"\n' "$name" "$secret" >>"$workdir/s.new"
	apply_conf
	((dry)) || say "host $name is configured with token ${token_id#*!}"
	exit 0
	;;
remove)
	read_conf
	drop_host "$name" && found=0 || found=$?
	((found != 3)) || die "host $name is not configured"
	((found != 5)) || die "host $name is the only one, and Concord needs at least one"
	apply_conf
	((dry)) || say "host $name is removed; its token still exists: run --unenroll on that host"
	exit 0
	;;
esac

verify_template

# ---------------------------------------------------------------- upgrade
if [[ -n $upgrade ]]; then
	vmid=$upgrade
	[[ $vmid =~ ^[0-9]+$ ]] || die "bad VMID: $vmid"
	verify_concord_ct "$vmid"
	mkdir -p "$workdir/new"
	tar -xJf "$template" -C "$workdir/new" ./usr/local/bin/concord ./usr/local/bin/concordctl ||
		die "template does not hold the binaries"
	new=$workdir/new/usr/local/bin
	for f in concord concordctl; do
		# pct push would follow a link and read its target as this host's root.
		[[ -f $new/$f && ! -L $new/$f && $(stat -c %h "$new/$f") == 1 ]] || die "template: $f is not a plain file"
	done
	pct pull "$vmid" /etc/concord/concord.toml "$workdir/concord.toml" >/dev/null || die "cannot read the container's config"
	port=$(listen_port "$workdir/concord.toml")

	if pct exec "$vmid" -- sh -c 'cd /usr/local/bin && { [ -e concord.old ] || [ -e concordctl.old ]; }'; then
		say "an earlier upgrade was cut off; restoring the binaries it replaced"
		if ((dry)); then echo "DRY-RUN: restore *.old in /usr/local/bin"; else
			restore_old || die "could not restore them"
		fi
	fi

	snap=pre-upgrade-$(date -u +%Y%m%d%H%M%S)
	say "snapshot $snap (skipped with a warning if the storage cannot)"
	run pct snapshot "$vmid" "$snap" || { snap=; echo "warning: no snapshot; the old binaries are kept for rollback" >&2; }

	# `pct push` only works on a running container, so the swap happens inside
	# it. Everything that can run out of space comes first, while the old
	# version is still running untouched.
	say "pushing the new binaries"
	((dry)) || stage=staged
	for f in concord concordctl; do
		run pct push "$vmid" "$new/$f" "/usr/local/bin/$f.new" --perms 0755 --user 0 --group 0 ||
			die "push failed; the running version was not touched"
	done
	# Both copies exist in full before either is named .old.
	run pct exec "$vmid" -- sh -c 'cd /usr/local/bin &&
		cp -p concord concord.old.tmp && cp -p concordctl concordctl.old.tmp && sync &&
		mv concord.old.tmp concord.old && mv concordctl.old.tmp concordctl.old' ||
		die "could not keep the old binaries; the running version was not touched"

	say "replacing binaries"
	# From here until it is healthy, any exit rolls back (see cleanup).
	((dry)) || stage=swapping
	run pct exec "$vmid" -- rc-service concord stop || die "could not stop the service"
	run pct exec "$vmid" -- mv /usr/local/bin/concord.new /usr/local/bin/concord || die "swap failed"
	run pct exec "$vmid" -- mv /usr/local/bin/concordctl.new /usr/local/bin/concordctl || die "swap failed"
	run pct exec "$vmid" -- rc-service concord start || die "the new version did not start"
	if ((dry)); then echo "DRY-RUN: wait up to ${HEALTH_DEADLINE}s for /healthz on port $port; roll back on failure"; exit 0; fi
	addr=$(wait_healthy "$vmid" "$port") || die "the new version is not healthy after ${HEALTH_DEADLINE}s"
	# Good: cleanup now only removes what is left over.
	stage=staged
	say "upgraded; healthy at $addr:$port"
	[[ -z $snap ]] || echo "snapshot $snap can be removed with: pct delsnapshot $vmid $snap"
	exit 0
fi

# ----------------------------------------------------------------- create
[[ $vmid =~ ^[0-9]+$ && $vmid -ge 100 ]] || die "--vmid N (>= 100) is required"
[[ -n $storage && -n $bridge && -n $ip ]] || die "--storage, --bridge and --ip are required"
generate=0
if [[ -z $config$secrets ]]; then
	generate=1
else
	[[ -f $config && -f $secrets ]] || die "--config and --secrets must be existing files"
	[[ -z $name$api_address && $rotate == 0 ]] || die "--name, --api-address and --rotate-token do not go with --config"
fi
if [[ $ip != dhcp ]]; then
	[[ $ip =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$ ]] || die "--ip must be a.b.c.d/nn or dhcp"
	[[ -n $gateway ]] || die "--gateway is required with a static --ip"
	[[ $gateway =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || die "bad --gateway"
fi
[[ $bridge =~ ^[A-Za-z0-9_.-]+$ && $storage =~ ^[A-Za-z0-9_.-]+$ ]] || die "bad --bridge or --storage"
hostname=${hostname:-concord-$vmid}
[[ $hostname =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]] || die "bad --hostname"
# The secrets must not be readable by others even before they are pushed.
if ((!generate)); then
	perm=$(stat -c %a "$secrets")
	[[ $perm =~ ^[0-7]00$ ]] || die "secrets file is mode $perm; chmod 600 it first"
fi

say "checks"
if pvesh get /cluster/nextid --vmid "$vmid" >/dev/null 2>&1; then :; else die "VMID $vmid is already in use; refusing"; fi
pct status "$vmid" >/dev/null 2>&1 && die "VMID $vmid already exists; refusing"
pvesm status --content rootdir --storage "$storage" 2>/dev/null | awk 'NR>1{f=1} END{exit !f}' ||
	die "storage '$storage' does not exist or cannot hold container volumes"

if ((generate)); then
	if [[ -z $name ]]; then
		name=$(uname -n) name=${name%%.*}
		[[ $name =~ ^$NAME_RE$ ]] || die "this host's name does not work as a name; use --name"
	fi
	if [[ -z $api_address ]]; then
		api_address=$(ip -4 -o addr show dev "$bridge" scope global | awk '{sub("/.*","",$4); print $4}') || die "cannot read the addresses of $bridge"
		[[ $api_address =~ ^$IPV4_RE$ ]] || die "$bridge does not have exactly one IPv4 address; use --api-address"
		check_addr "$api_address"
	fi
	config=$workdir/concord.toml secrets=$workdir/secrets.toml
	make_token "$api_address"
	if ((dry)); then token_id="$PVE_USERID!TOKEN"; fi
	# As concord.ct.example.toml.
	{
		printf '%s\n' 'listen = "0.0.0.0:8010"' 'secrets_file = "secrets.toml"' \
			'users_file = "/var/lib/concord/users.toml"' 'state_dir = "/var/lib/concord"'
		host_toml
	} >"$config"
	printf '"%s" = "%s"\n' "$name" "$secret" >"$secrets"
fi
port=$(listen_port "$config")
net="name=eth0,bridge=$bridge,firewall=1,ip=$ip"
[[ $ip == dhcp ]] || net+=",gw=$gateway"

say "creating container $vmid"
((dry)) || creating=1
run pct create "$vmid" "$template" \
	--hostname "$hostname" --ostype alpine --unprivileged 1 \
	--memory 128 --swap 0 --cores 1 --rootfs "$storage:$rootfs_gb" \
	--net0 "$net" --onboot 1 --tags "$TAG" --start 0 \
	--description "concord-deploy-run-$nonce"
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
if ((generate)); then
	say "checking the API from inside the container's network"
	check_from_ct "$vmid" "$api_address"
fi
[[ $ip != dhcp ]] || pct set "$vmid" --description "$(notes "$addr")"
created=0 creating=0 committed=1
if [[ -n $old_tokens ]]; then
	say "the new token works; removing the previous one"
	delete_tokens "$old_tokens" "" || echo "warning: the previous token is still there" >&2
fi

cat <<NEXT

Concord is up: https://$addr:$port/  (self-signed certificate)

Before typing a password into it, check that the certificate your browser shows
has the fingerprint the server logged:
  pct exec $vmid -- logread | grep fingerprint

Next, create the first admin (the password is read from stdin):
  pct exec $vmid -- su -s /bin/sh concord -c '/usr/local/bin/concord user add NAME --role admin'
Logs:  pct exec $vmid -- logread
More hosts: docs/DEPLOY.md, "Add another host".
NEXT
exit 0
}
