# Releasing

CI and a person at a terminal run the same code, `scripts/release.sh`.

## What a release holds

Exactly these files, none empty, nothing else:

- `concord-X-amd64.tar.xz`, the container template
- `concord-X-amd64.tar.xz.sha256`, in the form `deploy.sh` reads
- `deploy.sh`, `concord.ct.example.toml`
- `concordctl`, a static musl binary
- `SHA256SUMS` over all of the above

The host agent (CON-44) is deliberately not shipped yet.

## Steps

1. Bump `version` in the workspace `Cargo.toml`, refresh `Cargo.lock`
   (`cargo build --locked` must pass), add a `## X.Y.Z` section to
   `CHANGELOG.md`. Merge to `main` by pull request.
2. Tag the merge commit, annotated: `git tag -a vX.Y.Z -m "Concord X.Y.Z"`,
   then push the tag. `.github/workflows/release.yml` does the rest. A suffix
   such as `v0.2.0-rc.1` makes a pre-release; 0.x versions are normal releases.
3. The workflow refuses unless the tag equals the workspace version, is
   annotated and is on `main`; runs fmt, clippy, tests, the leak scan and
   `upgrade.sh`; builds; verifies the file set; creates a **draft** release,
   uploads, downloads it again and compares hashes, and only then publishes.
   A failure before the draft is created leaves nothing. A failure after it
   leaves an unpublished draft (the log says so); remove it with
   `gh release delete vX.Y.Z --yes`. If the code had to change, release a new
   version rather than moving the tag. The workflow also refuses if the tag
   no longer points at the built commit, or if a release for it already exists.

Run the workflow by hand (Actions, Release, Run workflow) on `main` for a dry
run that publishes nothing.

## Without CI

    # keep output outside the repo: check-tag refuses a dirty tree
    git fetch origin main
    scripts/release.sh check-tag vX.Y.Z           # version, annotated, on origin/main
    cargo fmt --all -- --check && cargo clippy --workspace --all-targets --all-features --locked
    cargo test --workspace --locked
    cargo run -q -p concord-pve --locked --features capture --example leakscan
    deploy/ct/build-template.sh --out ../concord-out/ct
    deploy/ct/tests/upgrade.sh
    scripts/release.sh assemble --version X.Y.Z --template-dir ../concord-out/ct \
        --concordctl target/x86_64-unknown-linux-musl/release/concordctl --out ../concord-out/release
    scripts/release.sh publish vX.Y.Z ../concord-out/release   # needs an authenticated gh

`verify DIR X.Y.Z` re-checks a directory at any time, and `notes X.Y.Z` prints
the release notes that will be used. The template build is deterministic given the same inputs (pinned Alpine
files, commit time as mtime), but the Rust toolchain tracks `stable` and the
C compiler and xz differ between machines, so equal hashes across machines or
days are not guaranteed; compare two builds on one machine.
