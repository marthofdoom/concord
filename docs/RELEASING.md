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
   Any failure leaves a draft. Delete the draft, fix, and re-tag.

Run the workflow by hand (Actions, Release, Run workflow) on `main` for a dry
run that publishes nothing.

## Without CI

    git fetch origin main
    scripts/release.sh check-tag vX.Y.Z           # version, annotated, on origin/main
    cargo fmt --all -- --check && cargo clippy --workspace --all-targets --all-features --locked
    cargo test --workspace --locked
    cargo run -q -p concord-pve --locked --features capture --example leakscan
    deploy/ct/build-template.sh --out out/ct
    deploy/ct/tests/upgrade.sh
    scripts/release.sh assemble --version X.Y.Z --template-dir out/ct \
        --concordctl target/x86_64-unknown-linux-musl/release/concordctl --out out/release
    scripts/release.sh publish vX.Y.Z out/release   # needs an authenticated gh

`verify DIR X.Y.Z` re-checks a directory at any time, and `notes X.Y.Z` prints
the release notes that will be used. The template build is reproducible: the
same commit gives the same `tar.xz`, so building twice and comparing the
hashes is a cheap check.
