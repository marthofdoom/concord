#!/usr/bin/env bash
# deploy.sh --upgrade against a stub pct whose container is a directory.
# Needs no Proxmox host and no root; touches nothing outside its temp directory.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
T=$(mktemp -d)
trap 'rm -rf -- "$T"' EXIT
mkdir -p "$T/bin"
export T

cat >"$T/bin/id" <<'S'
#!/bin/sh
echo 0
S
cat >"$T/bin/curl" <<'S'
#!/bin/sh
[ "$(cat "$T/svc")" = up ] && [ "$(cat "$T/ct/concord")" != bad ]
S
for c in pvesm pvesh; do printf '#!/bin/sh\nexit 0\n' >"$T/bin/$c"; done
# FAIL is a pattern of "command" to fail; SIGNAL is "SIG pattern" to send to
# deploy.sh just before that command takes effect.
cat >"$T/bin/pct" <<'S'
#!/usr/bin/env bash
line="$*"
echo "$line" >>"$T/log"
if [[ -n ${SIGNAL:-} && $line == *${SIGNAL#* }* && ! -e $T/signalled ]]; then
	touch "$T/signalled"; kill -"${SIGNAL%% *}" "$(cat "$T/pid")"
fi
[[ -n ${FAIL:-} && $line == *$FAIL* ]] && exit 1
here() { sed "s#/usr/local/bin#$T/ct#g" <<<"$1"; }
case $1 in
config) printf 'tags: concord\nnet0: name=eth0,ip=192.0.2.50/24\n' ;;
status) echo 'status: running' ;;
pull) case $3 in
	*concord-ct) echo 'concord-ct 1' >"$4" ;;
	*) printf '%s\n' "${LISTEN-listen = '0.0.0.0:8010'}" >"$4" ;;
	esac ;;
push) cp "$3" "$(here "$4")" ;;
snapshot) exit 1 ;;
exec) shift 3
	case $* in
	'rc-service concord stop') echo down >"$T/svc" ;;
	'rc-service concord start') [[ $(cat "$T/ct/concord") != nostart ]] && echo up >"$T/svc" ;;
	*proc/net/tcp*) exit 0 ;;
	'sh -c'*) sh -c "$(here "$3")" ;;
	mv*) mv "$(here "$2")" "$(here "$3")" ;;
	*) exit 1 ;;
	esac ;;
esac
S
chmod +x "$T/bin/"*

template() { # content of both binaries
	rm -rf "$T/t"; mkdir -p "$T/t/usr/local/bin"
	echo "$1" >"$T/t/usr/local/bin/concord"; echo "$1" >"$T/t/usr/local/bin/concordctl"
	pack
}
pack() {
	tar -C "$T/t" -cJf "$T/t.tar.xz" ./usr
	sha256sum "$T/t.tar.xz" >"$T/t.tar.xz.sha256"
}
fresh() {
	rm -rf "$T/ct" "$T/signalled"; mkdir "$T/ct"; : >"$T/log"; echo up >"$T/svc"
	echo old >"$T/ct/concord"; echo old >"$T/ct/concordctl"
}
deploy() {
	rc=0
	PATH="$T/bin:$PATH" CONCORD_LOCK_DIR=$T/lock CONCORD_HEALTH_DEADLINE=1 TMPDIR=$T \
		bash -c 'echo $$ >"$T/pid"; exec bash "$@"' - "$here/../deploy.sh" \
		--upgrade 100 --template "$T/t.tar.xz" >"$T/out" 2>&1 || rc=$?
}
fail() { echo "FAIL: $1 (rc=$rc)"; cat "$T/out" "$T/log"; ls "$T/ct"; exit 1; }
# name, expected rc, expected content; always: service up, nothing left over.
expect() {
	[[ $rc == "$2" ]] || fail "$1: rc, expected $2"
	[[ $(cat "$T/ct/concord") == "$3" && $(cat "$T/ct/concordctl") == "$3" ]] || fail "$1: binaries"
	[[ $(cat "$T/svc") == up ]] || fail "$1: service down"
	[[ $(ls "$T/ct" | wc -l) == 2 ]] || fail "$1: leftovers"
	# The rollback must also know it worked: its health check runs in the EXIT
	# trap, where bash treats some things differently.
	! grep -q 'restoring the previous' "$T/out" || grep -q 'running again' "$T/out" || fail "$1: rollback misreported"
	echo "ok: $1"
}

template new; fresh; deploy; expect "upgrade" 0 new

for f in concord.new concordctl.new; do
	fresh; FAIL="/usr/local/bin/$f --perms" deploy; expect "push of $f fails" 1 old
	! grep -q 'rc-service concord stop' "$T/log" || fail "a push failure stopped the service"
done
fresh; FAIL='cp -p' deploy; expect "keeping the old fails" 1 old
fresh; FAIL='service concord stop' deploy; expect "stop fails" 1 old
fresh; FAIL='mv /usr/local/bin/concord.new' deploy; expect "first rename fails" 1 old
fresh; FAIL='mv /usr/local/bin/concordctl.new' deploy; expect "second rename fails" 1 old

for sig in HUP:129 INT:130 TERM:143; do
	for at in 'concord.new --perms' 'cp -p' 'service concord stop' 'mv /usr/local/bin/concord.new' \
		'mv /usr/local/bin/concordctl.new' 'service concord start' 'proc/net/tcp'; do
		fresh; SIGNAL="${sig%:*} $at" deploy
		expect "${sig%:*} at '$at'" "${sig#*:}" old
	done
done

mkdir -p "$T/lock"; exec 7>>"$T/lock/ct-100"; flock -n 7
fresh; deploy; expect "another run holds the container" 1 old
grep -q push "$T/log" && fail "pushed despite the lock"
exec 7>&-

template nostart; fresh; deploy; expect "the new does not start" 1 old
template bad; fresh; deploy; expect "the new is not healthy" 1 old

# Killed outright between the renames: the next run puts the old ones back.
template new; fresh
FAIL='mv /usr/local/bin/concordctl.new' SIGNAL='KILL mv /usr/local/bin/concordctl.new' deploy
[[ $rc == 137 && -e $T/ct/concord.old ]] || fail "kill"
rm -rf "$T"/tmp.* # SIGKILL leaves the work directory; nothing can be done there
template bad; deploy; expect "recovery after a kill" 1 old

# If restoring fails, the service is still started and the copies are kept.
template bad; fresh; FAIL='[ ! -e' deploy
[[ $rc == 1 && -e $T/ct/concord.old ]] || fail "restore failure"
tail -n1 "$T/log" | grep -q . && grep -c 'service concord start' "$T/log" | grep -qx 2 || fail "start not attempted"
echo "ok: restore failure still starts the service"

template new
for l in "listen = '127.0.0.1:8010'" 'listen = "127.0.0.1:8010"' '# listen = "0.0.0.0:8010"' \
	'listen = "0.0.0.0:http"'; do
	fresh; LISTEN=$l deploy; expect "refused: $l" 1 old
	! grep -Eq 'push|stop|snapshot' "$T/log" || fail "touched the container"
done
fresh; echo "0  t" >"$T/t.tar.xz.sha256"; deploy; expect "checksum mismatch" 1 old
rm "$T/t/usr/local/bin/concord"; ln -s /etc/hostname "$T/t/usr/local/bin/concord"; pack
fresh; deploy; expect "symlink in the template" 1 old
if compgen -G "$T/tmp.*" >/dev/null; then fail "work directory left behind"; fi
