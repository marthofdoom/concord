#!/usr/bin/env bash
# Build concord-<version>-amd64.tar.xz, an unprivileged-container template for
# Proxmox VE, without root.
#
# Why this recipe: Alpine's minirootfs has no init system, and its own LXC
# images are not published for 3.24. So the pinned minirootfs is extended with
# the few pinned apks OpenRC needs. Every input is verified against the SHA-256
# in alpine.lock before use (a hash pin is stricter than the apk signature
# check, and needs no apk tooling on the build host). Ownership comes from
# fakeroot, so the tarball holds root-owned entries without privilege.
#
# Usage: build-template.sh [--out DIR] [--bin-dir DIR]
#   --bin-dir  directory holding static musl `concord` and `concordctl`
#              (default: build them with cargo for x86_64-unknown-linux-musl)
# Env: CC_x86_64_unknown_linux_musl overrides the C compiler used for ring
#      (default musl-gcc if present, else gcc, which works for ring's C and asm).
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$here/../.." && pwd)
mirror=${ALPINE_MIRROR:-https://dl-cdn.alpinelinux.org/alpine}
cache=${CONCORD_BUILD_CACHE:-$root/target/ct-cache}
out=$root/target/ct
bindir=
CONCORD_UID=900   # keep in step with deploy.sh

stage() {
	# Runs under fakeroot: $1 = rootfs dir, $2 = output file, $3 = epoch.
	local rfs=$1 outfile=$2 epoch=$3
	mkdir -p "$rfs"
	tar -C "$rfs" -xzpf "$cache/alpine-minirootfs.tar.gz" --numeric-owner
	local apk
	for apk in "$cache"/*.apk; do
		# .apk = signature, control and data gzip streams back to back; GNU tar
		# reads the first stream only, so skip entries to the data segment.
		# Dot-files are the signature and control metadata, not payload.
		tar -C "$rfs" -xzpf "$apk" --numeric-owner --exclude='.[A-Z]*' --warning=no-unknown-keyword
	done
	# A half-populated rootfs must never ship; nothing downstream boots it.
	local f
	for f in sbin/openrc sbin/supervise-daemon sbin/ifup etc/init.d/networking etc/init.d/syslog usr/lib/libcap.so.2 usr/lib/libeinfo.so.1; do
		[[ -e $rfs/$f || -L $rfs/$f ]] || { echo "missing from rootfs: $f" >&2; exit 1; }
	done

	install -d -m 0755 "$rfs/usr/local/bin"
	install -m 0755 "$bindir/concord" "$bindir/concordctl" "$rfs/usr/local/bin/"
	cp -a "$here/rootfs/etc/." "$rfs/etc/"
	chmod 0755 "$rfs/etc/init.d/concord"
	chmod 0644 "$rfs/etc/conf.d/concord" "$rfs/etc/conf.d/syslog"

	# Dedicated user: no login shell, no password, no home but its state dir.
	echo "concord:x:$CONCORD_UID:$CONCORD_UID:Concord:/var/lib/concord:/sbin/nologin" >>"$rfs/etc/passwd"
	echo "concord:x:$CONCORD_UID:" >>"$rfs/etc/group"
	echo "concord:!:0:0:99999:7:::" >>"$rfs/etc/shadow"
	install -d -m 0750 -o 0 -g "$CONCORD_UID" "$rfs/etc/concord"
	install -d -m 0700 -o "$CONCORD_UID" -g "$CONCORD_UID" "$rfs/var/lib/concord"
	# The root account stays locked ('*' in minirootfs). Fail loudly if not.
	grep -q '^root:[*!]' "$rfs/etc/shadow"

	# Marker deploy.sh checks before it touches a container.
	printf 'concord-ct 1\nversion=%s\n' "$version" >"$rfs/etc/concord-ct"
	chmod 0644 "$rfs/etc/concord-ct"

	# Runlevels. PVE's Alpine setup also links networking/bootmisc/hostname on
	# create; doing it here keeps the template bootable on its own.
	local lv
	for lv in boot default shutdown sysinit; do install -d -m 0755 "$rfs/etc/runlevels/$lv"; done
	ln -sf /etc/init.d/hostname "$rfs/etc/runlevels/boot/hostname"
	ln -sf /etc/init.d/bootmisc "$rfs/etc/runlevels/boot/bootmisc"
	ln -sf /etc/init.d/networking "$rfs/etc/runlevels/boot/networking"
	ln -sf /etc/init.d/syslog "$rfs/etc/runlevels/boot/syslog"
	ln -sf /etc/init.d/killprocs "$rfs/etc/runlevels/shutdown/killprocs"
	ln -sf /etc/init.d/savecache "$rfs/etc/runlevels/shutdown/savecache"
	ln -sf /etc/init.d/concord "$rfs/etc/runlevels/default/concord"

	# No SSH server is installed; no setuid/setgid binary may ship.
	# Capture first: `find | grep -q` under pipefail passes when grep exits early.
	local hits
	hits=$(find "$rfs" -xdev \( -perm -4000 -o -perm -2000 \))
	if [[ -n $hits ]]; then
		echo "setuid/setgid files in rootfs:" >&2
		echo "$hits" >&2
		exit 1
	fi

	tar -C "$rfs" --sort=name --numeric-owner --mtime="@$epoch" \
		--pax-option=delete=atime,delete=ctime --format=posix -cf - . |
		xz -T1 -9e >"$outfile"
}

if [[ ${1:-} == --stage ]]; then
	shift
	bindir=$1 version=$2 cache=$3 here=$4
	stage "$5" "$6" "$7"
	exit 0
fi

while (($#)); do
	case $1 in
	--out) out=$2; shift 2 ;;
	--bin-dir) bindir=$2; shift 2 ;;
	-h | --help) sed -n '2,19p' "${BASH_SOURCE[0]}"; exit 0 ;;
	*) echo "unknown argument: $1" >&2; exit 2 ;;
	esac
done

for t in fakeroot xz curl sha256sum tar; do
	command -v "$t" >/dev/null || { echo "missing tool: $t" >&2; exit 1; }
done

version=$(sed -n '/^\[workspace.package\]/,/^\[/{s/^version = "\(.*\)"/\1/p}' "$root/Cargo.toml")
[[ -n $version ]] || { echo "cannot read workspace version" >&2; exit 1; }

if [[ -z $bindir ]]; then
	if [[ -z ${CC_x86_64_unknown_linux_musl:-} ]]; then
		if command -v musl-gcc >/dev/null; then CC_x86_64_unknown_linux_musl=musl-gcc; else CC_x86_64_unknown_linux_musl=gcc; fi
		export CC_x86_64_unknown_linux_musl
	fi
	(cd "$root" && cargo build --release --locked --target x86_64-unknown-linux-musl -p concord-server -p concordctl)
	bindir=$root/target/x86_64-unknown-linux-musl/release
fi
for b in concord concordctl; do [[ -x $bindir/$b ]] || { echo "missing $bindir/$b" >&2; exit 1; }; done

# Fetch and verify every pinned input.
mkdir -p "$cache" "$out"
rm -f "$cache"/*.apk "$cache/alpine-minirootfs.tar.gz"
while read -r sum path; do
	[[ -z $sum || $sum == '#'* ]] && continue
	case $path in
	*minirootfs*) dest=$cache/alpine-minirootfs.tar.gz ;;
	*) dest=$cache/$(basename "$path") ;;
	esac
	curl -fsSL --retry 3 "$mirror/$path" -o "$dest"
	echo "$sum  $dest" | sha256sum -c --quiet - || { echo "checksum mismatch: $path" >&2; exit 1; }
done <"$here/alpine.lock"

# Reproducible mtime: the commit time when in git, else the pinned minirootfs date.
epoch=${SOURCE_DATE_EPOCH:-$(git -C "$root" log -1 --format=%ct 2>/dev/null || echo 1762333144)}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
file=$out/concord-$version-amd64.tar.xz
fakeroot -- "${BASH_SOURCE[0]}" --stage "$bindir" "$version" "$cache" "$here" "$tmp/rootfs" "$file" "$epoch"
sha256sum "$file" >"$file.sha256"
echo "built $file"
