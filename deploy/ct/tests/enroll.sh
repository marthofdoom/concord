#!/usr/bin/env bash
# deploy.sh's token and host modes against stub PVE commands: the "host" and the
# "container" are directories. Needs no Proxmox host and no root.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
T=$(mktemp -d)
trap 'rm -rf -- "$T" "${CONCORD_TMPFS:-$T}"' EXIT
mkdir -p "$T/bin"
export T
U=concord-monitor R=pve
export A=PVEAPIToken
CONCORD_TMPFS=$(mktemp -d /dev/shm/concord-test.XXXXXX)
export CONCORD_TMPFS
export CONCORD_LOCK_DIR=$T/lock
PERL=$(command -v perl)
export PERL
export UID_="$U@$R"
FP=$(printf 'AB:%.0s' {1..31})AB
export FP
SECRET_RE='[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}'

# Every stub logs its arguments and honours FAIL ("pattern" to fail) and SIGNAL
# ("SIG pattern", sent once the command has taken effect).
cat >"$T/bin/stub" <<'S'
#!/usr/bin/env bash
cmd=${0##*/}; line="$cmd $*"
printf '%s\n' "$line" >>"$T/log"
env >>"$T/env"
[[ $cmd == @(pct|pveum|pvesm|pvesh) ]] && readlink /proc/self/fd/* | grep -qF "$T/lock" && echo LOCKFD >>"$T/log"
[[ -n ${OTHER:-} && $line == *$OTHER* ]] && { echo x >"$T/db/tok/other"; echo 0 >"$T/db/tok/other.s"; }
[[ -n ${FAILLATE:-} && $line == *$FAILLATE* ]] && grep -q 'user token add' "$T/log" && exit 1
[[ -n ${FAIL:-} && $line == *$FAIL* ]] && exit 1
D=$T/db C=$T/ct
sig() { if [[ -n ${SIGNAL:-} && $line == *${SIGNAL#* }* && ! -e $T/signalled ]]; then
	touch "$T/signalled"; kill -"${SIGNAL%% *}" "$(cat "$T/pid")"; fi; }
trap sig EXIT
case $cmd in
id) echo 0 ;;
uname) echo pve1.example ;;
lxc-info) echo 4242 ;;
pvesm) printf 'h\nx\n' ;;
pvesh) ;;
ip) printf '%b' "${IP_OUT-2: vmbr0 inet 192.0.2.11/24 x\n}" ;;
nsenter) shift 4; "$@" ;;
timeout) shift; "$@" ;;
openssl) case "$*" in
	s_client*) echo "PEM ${SERVED:-$FP}" ;;
	*-fingerprint*) read -r _ f; echo "sha256 Fingerprint=$f" ;;
	*'-in /etc/pve'*) echo "PEM ${FILE_FP:-$FP}" ;;
	base64) cat >/dev/null; printf 'A%.0s' {1..43}; echo = ;;
	*) cat ;;
	esac ;;
curl)
	case "$*" in
	*/healthz) [[ -s $C/concord.toml && $(cat "$T/svc") == up ]] || exit 1 ;;
	*/access/permissions*)
		[[ "$*" == *--pinnedpubkey* ]] || exit 9
		read -r hdr
		for f in "$D"/tok/*; do
			[[ -e $f.s ]] || continue
			[[ $hdr == "header = \"Authorization: $A=$UID_!${f##*/}=$(cat "$f.s")\"" ]] || continue
			grep -q . "$D/acl" && { printf '{"data":{"/":{"VM.Audit":%s}}}' "${AUDIT:-1}"; exit 0; }
		done
		exit 22 ;;
	esac ;;
pveum)
	case "$*" in
	'user list'*) [[ ! -e $D/user ]] || printf '[{"userid":"%s","comment":"%s","groups":"%s"}]' "$UID_" "$(cat "$D/user")" "${GROUPS_:-}"
		[[ -e $D/user ]] || echo '[]' ;;
	'user add'*) [[ ! -e $D/user ]] || exit 1; echo "$5" >"$D/user" ;;
	'user delete'*) rm -f "$D/user" "$D/tok/"*; : >"$D/acl" ;;
	'acl list'*) [[ -s $D/acl ]] && printf '[{"path":"/","type":"user","ugid":"%s","roleid":"%s","propagate":1}]' "$UID_" "$(cat "$D/acl")" || echo '[]' ;;
	'acl modify'*) echo "$7" >"$D/acl" ;;
	'acl delete'*) : >"$D/acl" ;;
	'user token list'*) o=
		for f in "$D"/tok/*; do [[ -e $f.s ]] && o+=",{\"tokenid\":\"${f##*/}\",\"comment\":\"$(cat "$f")\"}"; done
		echo "[${o#,}]" ;;
	'user token add'*) echo "$9" >"$D/tok/$5"; h=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
		s=${h:0:8}-${h:8:4}-${h:12:4}-${h:16:4}-${h:20}
		echo "$s" >"$D/tok/$5.s"; echo "$s" >>"$T/secrets"; printf '{"value":"%s"}' "$s" ;;
	'user token delete'*) rm "$D/tok/$5" "$D/tok/$5.s" ;;
	*) exit 1 ;;
	esac ;;
pct)
	map() { sed "s#/etc/concord#$C#g" <<<"$1"; }
	case $1 in
	config) [[ -d $C ]] || exit 1; printf 'tags: concord\nnet0: name=eth0,ip=192.0.2.50/24\n'; cat "$T/desc" ;;
	status) [[ -d $C ]] && echo 'status: running' ;;
	create)
		# Under 077 a real container's root cannot enter its own root directory.
		[ "$(umask)" = 0022 ] || { echo "pct create under umask $(umask)" >&2; exit 1; }
		[[ -z ${FOREIGN:-} ]] || { mkdir "$C"; echo 'description: other' >"$T/desc"; exit 1; }
		mkdir "$C"; printf 'description: %s\n' "${*: -1}" >"$T/desc" ;;
	start) [[ -z ${REPLACED:-} ]] || { echo 'description: other' >"$T/desc"; exit 1; } ;;
	destroy) rm -rf "$C" ;;
	set) printf 'description: %s\n' "$4" >"$T/desc" ;;
	pull) case $3 in *concord-ct) echo 'concord-ct 1' >"$4" ;; *) cp "$(map "$3")" "$4" ;; esac ;;
	push)
		[[ $(stat -f -c %T "$3") == tmpfs && $(stat -c %a "${3%/*}") == 700 && $(stat -c %a "$3") == 600 ]] || { echo INSECURE >>"$T/log"; exit 1; }
		cp "$3" "$(map "$4")" ;;
	exec) shift 3
		case $* in
		'rc-service concord restart')
			[[ ! -e $T/badnext ]] || { grep -q pve9 "$C/concord.toml" && { echo down >"$T/svc"; exit 0; }; }
			echo up >"$T/svc" ;;
		*proc/net/tcp*) ;;
		*'[ -d '*'/.prev ]; then'*) if [[ -n ${NOPREV:-} || ! -d $C/.prev ]]; then echo no; else echo yes; fi ;;
		'sh -c'*) sh -c "$(map "$3")" ;;
		mv*) mv "$(map "$2")" "$(map "$3")" ;;
		*) exit 1 ;;
		esac ;;
	esac ;;
esac
S
cat >"$T/bin/perl" <<'S'
#!/usr/bin/env bash
env >>"$T/env"
if [[ -n ${FULL:-} && $* == *"$FULL"* ]]; then exec "$PERL" "$@" >/dev/full; fi
exec "$PERL" "$@"
S
chmod +x "$T/bin/stub" "$T/bin/perl"
for c in id uname lxc-info pvesm pvesh ip nsenter timeout openssl curl pveum pct; do ln -s stub "$T/bin/$c"; done
echo template >"$T/t.tar.xz"

host() { rm -rf "$T/db" "$T/ct" "$T/desc" "$T/badnext"; mkdir -p "$T/db/tok"; : >"$T/db/acl"; : >"$T/secrets"; : >"$T/desc"; echo up >"$T/svc"; }
snapshot() { (cd "$T" && { find db ct -type f 2>/dev/null || true; } | sort | xargs -r sha256sum); }
IN=/dev/null
go() { # arguments of deploy.sh
	rc=0; : >"$T/log"; : >"$T/env"; rm -f "$T/signalled"
	PATH="$T/bin:$PATH" CONCORD_HEALTH_DEADLINE=1 \
		bash -c 'echo $$ >"$T/pid"; exec bash '"${BASHOPT:-}"' "$@"' - "${SCRIPT:-$here/../deploy.sh}" "$@" <"$IN" >"$T/out" 2>"$T/err" 7>&- || rc=$?
	# The one place a secret may appear is the record on enroll's stdout.
	local s
	while read -r s; do
		! grep -qF -- "$s" "$T/log" "$T/env" "$T/err" || fail "secret leaked"
		[[ " $* " == *" --enroll "* ]] || ! grep -qF -- "$s" "$T/out" || fail "secret on stdout"
	done <"$T/secrets"
	! grep -q LOCKFD "$T/log" || fail "a lock was inherited"
	! grep -q INSECURE "$T/log" || fail "insecure file"
	# SIGKILL leaves it; nothing can be done there.
	((rc != 137)) || rm -rf "$CONCORD_TMPFS"/concord-deploy.*
	! compgen -G "$CONCORD_TMPFS/*" >/dev/null || fail "leftover work directory"
}
fail() { echo "FAIL: $1 (rc=$rc)"; cat "$T/out" "$T/err" "$T/log"; find "$T/db" "$T/ct" -type f 2>/dev/null; exit 1; }
ok() { echo "ok: $1"; }
refused() { [[ $rc != 0 ]] || fail "$1: accepted"; [[ $(snapshot) == "$before" ]] || fail "$1: changed something"; ok "$1"; }
toks() { find "$T/db/tok" -name '*.s' | wc -l; }
create() { go --vmid 100 --storage s --bridge vmbr0 --ip 192.0.2.50/24 --gateway 192.0.2.1 --template "$T/t.tar.xz" "$@"; }
enroll() { go --enroll --name pve2 --api-address 192.0.2.12 "$@"; }

# ---------------------------------------------------------------- create
host; create; [[ $rc == 0 ]] || fail create
grep -q 'name = "pve1"' "$T/ct/concord.toml" && grep -q '"https://192.0.2.11:8006"' "$T/ct/concord.toml" &&
	grep -Eqx "\"pve1\" = \"$SECRET_RE\"" "$T/ct/secrets.toml" && [[ $(toks) == 1 ]] || fail "create: content"
grep -q -- '--privsep 0' "$T/log" || fail privsep
grep -q '^nsenter -t 4242 -n' "$T/log" || fail "not checked from the container"
cp -r "$T/ct" "$T/ct.good"; cp -r "$T/db" "$T/db.good"; cp "$T/secrets" "$T/secrets.good"
ok create

host; before=$(snapshot); create --dry-run; [[ $rc == 0 && $(snapshot) == "$before" ]] || fail dry-run; ok "create --dry-run"
for ipout in '' '2: vmbr0 inet 192.0.2.11/24 x\n2: vmbr0 inet 192.0.2.12/24 x\n'; do
	IP_OUT=$ipout create; refused "ambiguous bridge address"
done
SERVED=${FP/AB/CD} create; refused "another certificate is served"
grep -q pveum "$T/log" && fail "user created despite the certificate"
AUDIT=0 create; refused "a token that sees too little is undone"
AUDIT='""' create; refused "an odd answer is undone"
for f in 'user add' 'acl modify' 'token add' 'api2/json' 'pct create' 'pct start' 'concord.toml' 'secrets.toml' 'concord restart' healthz lxc-info 'nsenter -t'; do
	FAIL=$f create; refused "create: '$f' fails"
done
for s in HUP:129 INT:130 TERM:143 PIPE:141; do
	for at in 'user add' 'acl modify' 'token add' 'api2/json' 'pct create' 'pct start' 'secrets.toml' 'concord restart' 'nsenter -t'; do
		SIGNAL="${s%:*} $at" create; [[ $rc == "${s#*:}" ]] || fail "signal rc"
		refused "create: ${s%:*} at '$at'"
	done
done

for v in FOREIGN REPLACED; do
	host; export "$v=1"; create; unset "$v"
	[[ $rc != 0 && -d $T/ct && $(toks) == 0 ]] && grep -q 'not destroying it. Check it: pct config 100' "$T/err" || fail "$v"
	ok "a container not proven ours is left, and named ($v)"
done
host; SIGNAL='TERM pct set' create; [[ $rc == 143 && -d $T/ct && $(toks) == 1 ]] || fail "signal while writing the Notes"
ok "a finished container keeps its token"
host; before=$(snapshot); FAIL='pct create' create; grep -q 'pvesm list s --vmid 100' "$T/err" || fail "create: no hint"
refused "a cut-off pct create says what to check"

# ---------------------------------------------------------------- enroll
host; enroll; [[ $rc == 0 && $(wc -l <"$T/out") == 7 ]] || fail enroll
grep -Eqx "secret=$SECRET_RE" "$T/out" && [[ $(head -n1 "$T/out") == 'concord-enroll 1' ]] || fail record
cp "$T/out" "$T/rec"; cp -r "$T/db" "$T/db2"; ok enroll
before=$(snapshot); enroll; refused "existing token without --rotate-token"
FAIL='token add' enroll --rotate-token; refused "a failing rotation keeps the old token and user"
FAIL='api2/json' enroll --rotate-token; refused "a new token that does not work keeps the old one"
old=$(sed -n 's/^token=//p' "$T/rec")
enroll --rotate-token; [[ $rc == 0 && $(toks) == 2 ]] || fail rotate
new=$(sed -n 's/^token=//p' "$T/out")
before=$(snapshot); go --prune-tokens --keep nothere-00000000; refused "prune with a wrong --keep"
go --prune-tokens --keep "$new"; [[ $rc == 0 && $(toks) == 1 && ! -e $T/db/tok/$old ]] || fail prune; ok "rotate and prune"
enroll --install second; [[ $rc == 0 && $(toks) == 2 ]] || fail second; ok "two installations coexist"
echo user-made >"$T/db/tok/other"; echo 0 >"$T/db/tok/other.s"
go --unenroll --install second; [[ $rc == 0 && $(toks) == 2 && -e $T/db/user ]] || fail "unenroll second"
go --unenroll; [[ $rc == 0 && $(toks) == 1 && -e $T/db/user && -e $T/db/tok/other ]] || fail "unenroll keeps a foreign token"
rm "$T/db/tok/other"*; go --unenroll; [[ $rc == 0 && ! -e $T/db/user ]] || fail "unenroll user"; ok unenroll

# Variables the caller exported do not carry the secret to any command.
VARS=(secret rec rest j out token_id tok old_tokens fp name api_address re pem)
for v in "${VARS[@]}"; do export "$v=x"; done
host; create; [[ $rc == 0 ]] || fail "create, exported variables"
host; enroll; [[ $rc == 0 ]] || fail "enroll, exported variables"
record=$(sed '/^secret=/!d;s/.*/secret/' "$T/out"); [[ $record == secret ]] || fail record
cp "$T/out" "$T/rec1"; cp -r "$T/ct.good" "$T/ct"
IN=$T/rec1 go --add-host 100; [[ $rc == 0 ]] || fail "add, exported variables"
IN=$T/rec1 go --add-host 100 --replace; [[ $rc == 0 ]] || fail "replace, exported variables"
grep -q 'prune-tokens --keep concord-[0-9a-f]* --install concord$' "$T/out" || fail "no prune hint"
for v in "${VARS[@]}"; do export -n "$v"; done; ok "exported variables"

# Another run's token relies on the permission or user this run set.
marked() { host; echo 'concord-deploy user run=0123456789abcdef' >"$T/db/user"; }
marked; OTHER='token add' FAIL='api2/json' enroll
[[ $rc != 0 && -s $T/db/acl && $(toks) == 1 ]] && grep -q 'kept .*permission' "$T/err" || fail "permission of another token"
marked; FAIL='api2/json' FAILLATE='token list' enroll
[[ $rc != 0 && -s $T/db/acl ]] && grep -q "kept .*permission" "$T/err" || fail "tokens not listed: permission"
host; OTHER='token add' FAIL='api2/json' enroll
[[ $rc != 0 && -s $T/db/acl && -e $T/db/user && $(toks) == 1 ]] && grep -q 'kept user' "$T/err" || fail "user of another token"
host; FAIL='api2/json' FAILLATE='token list' enroll
[[ $rc != 0 && -s $T/db/acl && -e $T/db/user ]] && grep -q 'kept user' "$T/err" || fail "tokens not listed: user"
ok "undo keeps what another token needs, or may need"

# Runs that overlap are refused, and --dry-run takes no lock.
hold() { exec 7>>"$T/lock/$1"; flock -n 7 || fail "lock $1 is still held"; }
release() { exec 7>&-; }
host; enroll; before=$(snapshot); hold pve
enroll --rotate-token; refused "enroll during another"; enroll --install x --dry-run; [[ $rc == 0 ]] || fail "dry-run locked"
go --unenroll; refused "unenroll during another"; go --prune-tokens --keep "$(ls "$T/db/tok" | head -n1)"; refused "prune during another"
create --install x; refused "create during an enroll"; release; hold ct-100
create --install x; refused "create during another"
enroll --install x; [[ $rc == 0 ]] || fail "enroll is not held up by a container"; release; ok "two locks"

# A preexisting marked user without the permission: only the permission is undone.
host; echo 'concord-deploy user run=0123456789abcdef' >"$T/db/user"; before=$(snapshot)
FAIL='token add' enroll; refused "only this run's permission is undone"
GROUPS_=g enroll; refused "user in a group"
echo Administrator >"$T/db/acl"; before=$(snapshot); enroll; refused "over-privileged user"
host; echo 'someone else' >"$T/db/user"; before=$(snapshot)
for a in --enroll --unenroll; do go $a --name pve2 --api-address 192.0.2.12; refused "unmarked user, $a"; done
enroll --rotate-token; refused "unmarked user, rotate"
host; before=$(snapshot); enroll --dry-run; [[ ! -s $T/out && $rc == 0 && $(snapshot) == "$before" ]] || fail "enroll dry-run"
for s in HUP INT TERM; do for at in 'user add' 'acl modify' 'token add' 'api2/json'; do SIGNAL="$s $at" enroll; refused "enroll: $s at '$at'"; done; done
for a in 127.0.0.1 localhost 0.0.0.0 192.0.2.999 0x7f000001 '192.0.2.1"' 'a b' -x; do go --enroll --name pve2 --api-address "$a"; refused "address $a"; done
for n in 'a"b' 'a b' '../x' $'a\nb' ''; do go --enroll --name "$n" --api-address 192.0.2.12; refused "name $n"; done

# The record cannot be written: the token is taken back.
rc=0; : >"$T/log"
PATH="$T/bin:$PATH" CONCORD_HEALTH_DEADLINE=1 bash "$here/../deploy.sh" --enroll --name pve2 --api-address 192.0.2.12 >/dev/full 2>"$T/err" || rc=$?
refused "record cannot be written"
IN=$here/../deploy.sh SCRIPT=-s go -- --enroll --name pve2 --api-address 192.0.2.12
[[ $rc == 0 ]] && grep -q '^secret=' "$T/out" || fail "script on stdin"; ok "script on stdin"
head -c 20000 "$here/../deploy.sh" >"$T/cut"; host; before=$(snapshot)
IN=$T/cut SCRIPT=-s go -- --enroll --name pve2 --api-address 192.0.2.12; refused "a truncated script does nothing"
host; BASHOPT=-xv enroll; [[ $rc == 0 ]] || fail xtrace; ok "bash -xv leaks nothing"

# ------------------------------------------------------------- add, remove
ct() { # a container with pve1, and pve2's token valid
	host; cp -r "$T/db2/." "$T/db/"; cp -r "$T/ct.good" "$T/ct"; cat "$T/secrets.good" >"$T/secrets"; sed -n 's/^secret=//p' "$T/rec" >>"$T/secrets"
	printf '\n# about the budget\n[budget]\nlink_mbit = 1000\n' >>"$T/ct/concord.toml"
	before=$(snapshot)
}
add() { IN=$T/rec go --add-host 100 "$@"; }
ct; add; [[ $rc == 0 ]] || fail add
grep -c '^\[\[hosts\]\]' "$T/ct/concord.toml" | grep -qx 2 && grep -q '^"pve2" = ' "$T/ct/secrets.toml" || fail "add: content"
[[ $(ls -A "$T/ct" | wc -l) == 2 ]] || fail "add: leftovers"; ok add
hold pve; add --replace; [[ $rc == 0 ]] || fail "add is not held up by an enroll"; release; hold ct-100
before=$(snapshot); add --replace; refused "add during another"; go --remove-host 100 pve1; refused "remove during another"; release
before=$(snapshot); add; refused "existing host without --replace"
add --replace; [[ $rc == 0 && $(grep -c pve2 "$T/ct/secrets.toml") == 1 && $(grep -c '"pve2"' "$T/ct/concord.toml") == 1 ]] || fail replace; ok replace
go --remove-host 100 pve1; [[ $rc == 0 ]] || fail remove
! grep -q pve1 "$T/ct/secrets.toml" && ! grep -q pve1 "$T/ct/concord.toml" && grep -q '^# about the budget' "$T/ct/concord.toml" &&
	grep -q '^link_mbit' "$T/ct/concord.toml" && grep -q '"pve2"' "$T/ct/concord.toml" || fail "remove: content"; ok remove
before=$(snapshot); go --remove-host 100 pve2; refused "removing the last host"
go --remove-host 100 pve7; refused "removing an unknown host"
ct; add --dry-run; [[ $rc == 0 && $(snapshot) == "$before" ]] || fail "add dry-run"; ok "add --dry-run"
SERVED=${FP/AB/CD} add; refused "another certificate"
# Larger than perl's buffer: then perl itself does not report the failure.
head -c 20000 /dev/zero | tr '\0' '#' >"$T/pad"; cat "$T/pad" >>"$T/ct/concord.toml"; cat "$T/pad" >>"$T/ct/secrets.toml"; before=$(snapshot)
for f in 'sub flush' 'print unless'; do FULL=$f add; refused "no space ($f)"; done; ct
AUDIT=0 add; refused "token sees too little"
for f in lxc-info 'nsenter -t' 'concord.toml.new --perms' 'secrets.toml.new --perms' 'mkdir .prev' \
	'mv /etc/concord/secrets' 'mv /etc/concord/concord'; do FAIL=$f add; refused "add: '$f' fails"; done
for s in HUP:129 INT:130 TERM:143; do for at in 'concord.toml.new --perms' 'mkdir .prev' 'mv /etc/concord/secrets' 'mv /etc/concord/concord' 'concord restart' healthz; do
	SIGNAL="${s%:*} $at" add; [[ $rc == "${s#*:}" ]] || fail "rc"; refused "add: ${s%:*} at '$at'"
	[[ $(cat "$T/svc") == up ]] || fail "service down"
done; done
sed 's/name=pve2/name=pve9/' "$T/rec" >"$T/rec9"; touch "$T/badnext"
IN=$T/rec9 go --add-host 100; refused "unhealthy: both files restored"; grep -q 'may still be on its host' "$T/err" || fail "no token hint"; grep -q 'running again' "$T/err" || fail misreported
FAIL='mv /etc/concord/concord' SIGNAL='KILL mv /etc/concord/secrets' add # cut off outright
[[ $rc == 137 && -d $T/ct/.prev ]] || fail kill
rm "$T/badnext"; cp -r "$T/ct" "$T/ct.cut"; cut=$(snapshot)
FAIL='/.prev ]; then' add; [[ $rc != 0 && $(snapshot) == "$cut" ]] || fail "pct fails: the old files"
NOPREV=1 add --replace; [[ $rc != 0 ]] && cmp "$T/ct/.prev/concord.toml" "$T/ct.cut/.prev/concord.toml" && [[ ! -d $T/ct/.prev/.prev.tmp ]] || fail "old files overwritten"
rm -rf "$T/ct"; mv "$T/ct.cut" "$T/ct"; ok "the old files of a cut-off change are kept"
go --remove-host 100 pve7; refused "recovery after a kill"
for l in 'hosts = []' '[hosts.x]' '[ "hosts" . x]' "[[ 'hosts' ]]" '"name" = "x"'; do
	ct; printf '%s\n' "$l" >>"$T/ct/concord.toml"; before=$(snapshot); add; refused "a config it cannot edit: $l"
done

# ------------------------------------------------------- hostile records
ct
bad() { IN=$T/bad go --add-host 100; refused "record: $1"; ! grep -q 'pct push' "$T/log" || fail pushed; }
m() { sed "$2" "$T/rec" >"$T/bad"; bad "$1"; }
: >"$T/bad"; bad empty
m version 's/enroll 1/enroll 2/'; m quote 's/pve2/pve2"/'; m 'shell' 's/pve2/$(touch x)/'; m option 's/pve2/-rf/'
m path 's#192.0.2.12#192.0.2.12/x#'; m userinfo 's/192.0.2.12/a@192.0.2.12/'; m loopback 's/192.0.2.12/127.0.0.1/'; m port 's/192.0.2.12/192.0.2.12:1/'
m fingerprint 's/AB:AB/AB:ab/'; m token 's/^token=/token=x!/'; m secret 's/^secret=/secret=x/'; m 'CRLF' 's/$/\r/'; m 'extra line' '$a x=y'; m reordered '2{h;d};3{G}'; m 'no end' '$d'
m close 's/pve2/PVE1/'; m duplicate '2p'
{ cat "$T/rec"; head -c 3000 /dev/zero | tr '\0' a; } >"$T/bad"; bad long
{ cat "$T/rec"; printf '\0x'; } >"$T/bad"; bad NUL
echo "all passed"
