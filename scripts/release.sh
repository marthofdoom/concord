#!/usr/bin/env bash
# Release steps shared by CI (.github/workflows/release.yml) and by-hand use
# (docs/RELEASING.md), so both run the same code.
#
#   release.sh version                          print the workspace version
#   release.sh check-tag TAG [--main-ref REF]   tag == workspace version, annotated, on main
#   release.sh notes VERSION                    print that CHANGELOG.md section; refuse if absent
#   release.sh assemble --version V --template-dir D --concordctl FILE --out DIR
#   release.sh verify DIR VERSION               refuse a missing, empty, extra or altered file
#   release.sh publish TAG DIR                  draft, upload, re-download, compare, then publish
#
# Why a draft first: a failure at any step must leave an unpublished draft,
# never a release people can already download half-built.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
die() { echo "error: $*" >&2; exit 1; }

version() {
	local v
	v=$(sed -n '/^\[workspace.package\]/,/^\[/{s/^version = "\(.*\)"/\1/p}' "$root/Cargo.toml")
	[[ -n $v ]] || die "cannot read workspace version"
	echo "$v"
}

# The exact set of files a release holds, for a given version.
expected_files() {
	printf '%s\n' "concord-$1-amd64.tar.xz" "concord-$1-amd64.tar.xz.sha256" deploy.sh \
		concord.ct.example.toml concordctl SHA256SUMS
}

# The tag must name the very commit being built: a moved tag, a stale checkout
# or a dirty tree would otherwise ship binaries under the wrong tag.
check_tag() {
	local tag=$1 mainref=${2:-origin/main}
	[[ $tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || die "tag $tag is not vMAJOR.MINOR.PATCH[-suffix]"
	[[ ${tag#v} == "$(version)" ]] || die "tag $tag does not match workspace version $(version)"
	# An annotated tag is its own object; a lightweight one points at the commit.
	[[ $(git -C "$root" cat-file -t "refs/tags/$tag") == tag ]] || die "tag $tag is not annotated"
	[[ $(git -C "$root" rev-parse "refs/tags/$tag^{commit}") == "$(git -C "$root" rev-parse HEAD)" ]] ||
		die "tag $tag does not point at the checked-out commit"
	[[ -z $(git -C "$root" status --porcelain) ]] || die "working tree is not clean"
	git -C "$root" rev-parse --verify -q "$mainref^{commit}" >/dev/null || die "no such ref: $mainref"
	git -C "$root" merge-base --is-ancestor "refs/tags/$tag^{commit}" "$mainref" ||
		die "tag $tag is not on $mainref"
}

# The tag as the remote has it now, compared with the commit that was built.
check_remote_tag() {
	local tag=$1 got
	got=$(git -C "$root" ls-remote origin "refs/tags/$tag^{}" | cut -f1)
	[[ -n $got && $got == "$(git -C "$root" rev-parse HEAD)" ]] ||
		die "remote tag $tag is gone or no longer points at the built commit"
}

notes() {
	local v=$1 out
	[[ -f $root/CHANGELOG.md ]] || die "CHANGELOG.md is missing"
	out=$(awk -v v="$v" '
		/^## / { if (on) exit; on = ($0 ~ "^## \\[?" v "\\]?([ ]|$)"); next }
		on { print }' "$root/CHANGELOG.md")
	[[ -n ${out//[$' \t\n']/} ]] || die "CHANGELOG.md has no section for $v"
	printf '%s\n' "$out"
}

assemble() {
	local v= tdir= ctl= out=
	while (($#)); do
		case $1 in
		--version) v=$2; shift 2 ;;
		--template-dir) tdir=$2; shift 2 ;;
		--concordctl) ctl=$2; shift 2 ;;
		--out) out=$2; shift 2 ;;
		*) die "unknown argument: $1" ;;
		esac
	done
	[[ -n $v && -n $tdir && -n $ctl && -n $out ]] || die "assemble needs --version --template-dir --concordctl --out"
	local t=concord-$v-amd64.tar.xz
	[[ -s $tdir/$t && -s $tdir/$t.sha256 ]] || die "template or its .sha256 missing or empty in $tdir"
	[[ -s $ctl ]] || die "concordctl missing or empty: $ctl"
	[[ ! -e $out ]] || [[ -d $out && -z $(ls -A "$out") ]] || die "$out must not exist or must be empty"
	mkdir -p "$out"
	cp "$tdir/$t" "$out/$t"
	# build-template.sh records the build path; a release names the file only.
	printf '%s  %s\n' "$(sha256sum <"$out/$t" | cut -d' ' -f1)" "$t" >"$out/$t.sha256"
	install -m 0755 "$root/deploy/ct/deploy.sh" "$out/deploy.sh"
	install -m 0644 "$root/deploy/ct/concord.ct.example.toml" "$out/concord.ct.example.toml"
	install -m 0755 "$ctl" "$out/concordctl"
	(cd "$out" && sha256sum -- "$t" "$t.sha256" deploy.sh concord.ct.example.toml concordctl >SHA256SUMS)
	verify "$out" "$v"
}

verify() {
	local d=$1 v=$2 f want
	[[ -d $d ]] || die "$d is not a directory"
	want=$(expected_files "$v" | sort)
	[[ $(cd "$d" && find . -mindepth 1 -printf '%P\n' | sort) == "$want" ]] ||
		die "files in $d differ from the expected set: $(echo $want)"
	while read -r f; do
		[[ -f $d/$f && ! -L $d/$f && -s $d/$f ]] || die "$f is not a regular, non-empty file"
	done <<<"$want"
	# SHA256SUMS must cover every file but itself, exactly once.
	[[ $(awk '{print $2}' "$d/SHA256SUMS" | sort) == "$(grep -vx SHA256SUMS <<<"$want")" ]] ||
		die "SHA256SUMS does not list exactly the other files"
	(cd "$d" && sha256sum -c --quiet SHA256SUMS) || die "SHA256SUMS check failed"
	# deploy.sh reads only the first field of the .sha256; it must equal the template's hash.
	[[ $(cut -d' ' -f1 "$d/concord-$v-amd64.tar.xz.sha256") == "$(sha256sum <"$d/concord-$v-amd64.tar.xz" | cut -d' ' -f1)" ]] ||
		die "template .sha256 does not match the template"
	echo "verified $d for $v"
}

tmp= created=
publish_exit() {
	local rc=$?
	rm -rf -- "${tmp:-}"
	if [[ $rc -ne 0 && -n $created ]]; then
		echo "the release $created is left as an unpublished DRAFT; remove it with: gh release delete $created --yes" >&2
		echo "(the tag stays; if the code changed, release a new version instead of re-tagging)" >&2
	fi
}

publish() {
	local tag=$1 d=$2 v pre=() f
	v=${tag#v}
	verify "$d" "$v"
	[[ $v == *-* ]] && pre=(--prerelease)
	tmp=$(mktemp -d)
	trap publish_exit EXIT
	notes "$v" >"$tmp/notes.md"
	mkdir "$tmp/dl"
	# Upload resolves a release by tag, published or draft; refuse if any exists.
	gh api --paginate "repos/{owner}/{repo}/releases" --jq '.[].tag_name' >"$tmp/existing"
	! grep -qxF -- "$tag" "$tmp/existing" || die "a release for $tag already exists (draft or published); delete it first"
	check_remote_tag "$tag"
	# --verify-tag: never let gh create the tag; it must already exist.
	gh release create "$tag" --draft --verify-tag --title "Concord $v" \
		--notes-file "$tmp/notes.md" ${pre[@]+"${pre[@]}"}
	created=$tag
	(cd "$d" && gh release upload "$tag" -- *)
	gh release download "$tag" --dir "$tmp/dl"
	verify "$tmp/dl" "$v"
	while read -r f; do
		cmp -s -- "$d/$f" "$tmp/dl/$f" || die "$f differs after the round trip"
	done < <(expected_files "$v")
	check_remote_tag "$tag"
	gh release edit "$tag" --draft=false --verify-tag
	created=
	echo "published $tag"
}

cmd=${1:-}
[[ -n $cmd ]] && shift
case $cmd in
version) version ;;
check-tag)
	[[ $# -ge 1 ]] || die "usage: check-tag TAG [--main-ref REF]"
	if [[ $# -eq 1 ]]; then check_tag "$1"
	elif [[ $# -eq 3 && $2 == --main-ref ]]; then check_tag "$1" "$3"
	else die "usage: check-tag TAG [--main-ref REF]"; fi ;;
notes) [[ $# -eq 1 ]] || die "usage: notes VERSION"; notes "$1" ;;
assemble) assemble "$@" ;;
verify) [[ $# -eq 2 ]] || die "usage: verify DIR VERSION"; verify "$1" "$2" ;;
publish) [[ $# -eq 2 ]] || die "usage: publish TAG DIR"; publish "$1" "$2" ;;
*) sed -n '2,11p' "${BASH_SOURCE[0]}"; exit 2 ;;
esac
