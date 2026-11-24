#!/usr/bin/env bash
# scripts/release.sh against a local bare "origin" and a stub gh. Touches
# nothing outside its temp directory and never talks to GitHub.
set -uo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
T=$(mktemp -d)
trap 'rm -rf -- "$T"' EXIT
export T
fails=0
ok() { echo "ok: $1"; }
bad() { echo "FAIL: $1" >&2; fails=$((fails + 1)); }
# expect NAME WANT CMD...: WANT is 0 or fail; output kept in $T/out.
expect() {
	local name=$1 want=$2 rc
	shift 2
	"$@" >"$T/out" 2>&1
	rc=$?
	if [[ $want == 0 && $rc == 0 ]] || [[ $want == fail && $rc != 0 ]]; then ok "$name"; else bad "$name (rc $rc)"; sed 's/^/    /' "$T/out" >&2; fi
}

# A throwaway repo: just what release.sh reads.
R=$T/repo
mkdir -p "$R/scripts" "$R/deploy/ct" "$T/bin"
cp "$here/scripts/release.sh" "$R/scripts/"
printf '[workspace.package]\nversion = "0.1.0"\n' >"$R/Cargo.toml"
printf '# Changelog\n\n## 0.1.0\n\nnotes\n' >"$R/CHANGELOG.md"
echo '#!/bin/sh' >"$R/deploy/ct/deploy.sh"
echo 'listen = "x"' >"$R/deploy/ct/concord.ct.example.toml"
git init -q -b main "$R"
git init -q --bare -b main "$T/origin.git"
g() { git -C "$R" -c user.name=t -c user.email=t@example.invalid "$@"; }
g add -A && g commit -qm one
g remote add origin "$T/origin.git"
g push -q origin main
g tag -a v0.1.0 -m r && g push -q origin v0.1.0
S=$R/scripts/release.sh
cd "$R" || exit 1

# A release directory built by hand.
mkdir "$T/ct"
head -c 4096 /dev/urandom >"$T/ct/concord-0.1.0-amd64.tar.xz"
echo "$(sha256sum <"$T/ct/concord-0.1.0-amd64.tar.xz" | cut -d' ' -f1)  x" >"$T/ct/concord-0.1.0-amd64.tar.xz.sha256"
echo ctl >"$T/ctl"
"$S" assemble --version 0.1.0 --template-dir "$T/ct" --concordctl "$T/ctl" --out "$T/rel" >/dev/null || { echo "assemble failed" >&2; exit 1; }

# Stub gh: state is files under $T/gh. FAIL_UPLOAD_AT=N dies at the Nth file,
# CORRUPT=1 stores a damaged copy of the first file.
cat >"$T/bin/gh" <<'S'
#!/usr/bin/env bash
st=$T/gh; mkdir -p "$st/assets"
echo "$*" >>"$st/log"
# Like gh without GH_REPO: useless outside the repository.
git rev-parse --git-dir >/dev/null 2>&1 || { echo "not a git repository" >&2; exit 1; }
case "$1 $2" in
api*) cat "$st/tags" 2>/dev/null; exit 0 ;;
"release create") echo "$3" >>"$st/tags"; echo draft >"$st/state"; exit 0 ;;
"release upload")
	shift 3; [[ $1 == -- ]] && shift; n=0
	for f; do
		n=$((n + 1))
		[[ ${FAIL_UPLOAD_AT:-} == "$n" ]] && exit 1
		cp "$f" "$st/assets/${f##*/}"
		[[ ${CORRUPT:-} == 1 && $n == 1 ]] && echo x >>"$st/assets/${f##*/}"
	done; exit 0 ;;
"release download") cp "$st/assets/"* "$5/" ;;
"release edit") [[ " $* " == *" --verify-tag "* ]] || exit 1; echo published >"$st/state" ;;
*) exit 1 ;;
esac
S
chmod +x "$T/bin/gh"
export PATH=$T/bin:$PATH
reset() { rm -rf "$T/gh"; mkdir -p "$T/gh"; }
state() { cat "$T/gh/state" 2>/dev/null; }

expect "check-tag ok" 0 "$S" check-tag v0.1.0
expect "check-tag bad --main-ref word" fail "$S" check-tag v0.1.0 nonsense
expect "check-tag unknown main ref" fail "$S" check-tag v0.1.0 --main-ref nope
echo "# dirty" >>CHANGELOG.md
expect "check-tag dirty tree" fail "$S" check-tag v0.1.0
g checkout -q -- CHANGELOG.md
echo more >>CHANGELOG.md; g commit -qam two
expect "check-tag HEAD is not the tag's commit" fail "$S" check-tag v0.1.0
g reset -q --hard HEAD~1

reset
expect "publish success" 0 "$S" publish v0.1.0 "$T/rel"
[[ $(state) == published ]] && ok "state published" || bad "state published"

reset
echo v0.1.0 >"$T/gh/tags"
expect "existing release or draft refused" fail "$S" publish v0.1.0 "$T/rel"
grep -q "release create" "$T/gh/log" && bad "created despite existing" || ok "nothing created"

# The tag moved on the remote after this commit was built.
reset
echo more >>CHANGELOG.md; g commit -qam three
g tag -fa v0.1.0 -m moved; g push -qf origin v0.1.0
g reset -q --hard HEAD~1; g tag -fa v0.1.0 -m back
expect "remote tag moved" fail "$S" publish v0.1.0 "$T/rel"
grep -q "release create" "$T/gh/log" && bad "created with moved tag" || ok "nothing created (moved tag)"
g push -qf origin v0.1.0

reset
g push -q origin :refs/tags/v0.1.0
expect "remote tag deleted" fail "$S" publish v0.1.0 "$T/rel"
g push -q origin v0.1.0

reset
FAIL_UPLOAD_AT=3 expect "upload dies" fail "$S" publish v0.1.0 "$T/rel"
grep -q "gh release delete v0.1.0" "$T/out" && ok "says how to remove the draft" || bad "no removal hint"
[[ $(state) == draft ]] && ok "stays a draft" || bad "stays a draft"

reset
CORRUPT=1 expect "upload corrupts a file" fail "$S" publish v0.1.0 "$T/rel"
[[ $(state) == draft ]] && ok "corruption stays a draft" || bad "corruption stays a draft"

((fails == 0)) || { echo "$fails failure(s)" >&2; exit 1; }
echo "all release tests passed"
