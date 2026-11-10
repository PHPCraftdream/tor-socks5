# Release source companions

Each target's release includes the unchanged executable archive and a matching
`tor-socks5-<tag>-<target>-source.tar.gz` plus SHA-256 file. The source archive
contains:

- `project.tar`: the Git archive of the exact release commit, including the
  repository's tracked source, modified local `vendor/` crates, license texts,
  and notices;
- `cargo-vendor/`: full Cargo-vendored source for the locked external packages;
- `SOURCE-MATERIALS.json`: the commit, target, lockfile and project-archive
  digests, corresponding executable-archive name and digest, and native-material
  provenance digest;
- `native-material/`: selected Rust distribution documentation, the target
  standard-library component manifest, and a provenance inventory of native
  target inputs.

The package command uses the supplied vendor directory and does not fetch source.
Publisher `verify` independently invokes locked `cargo vendor --versioned-dirs`
from the release checkout with a fresh `CARGO_HOME`, then compares every path
and byte in `cargo-vendor/` to Cargo's regenerated output. Verify may fetch
registry data; network or registry failures fail verification closed. The bundle
also binds the named source archive to commit, target, and binary archive digests;
these bindings are not build receipts and do not prove the binary was built from
that source. Bundled checksum maps are structural self-consistency checks only,
not authenticity proofs. This boundary relies on the publisher's Cargo
executable and checkout/configuration trust. Use a clean checkout: the helper
checks that the working `Cargo.lock` exactly matches the requested Git commit,
but relies on other tracked manifests being clean as in CI. It supports only
the exact crates.io source in the current lockfile and rejects Git,
alternate-registry, and other external sources. Local path crates are retained
in `project.tar`.

## CI real-Cargo smoke hook

Run this in a clean CI checkout with Rust/Cargo installed. It packages GNU and
musl targets from the installed Rust distribution using non-executable marker
archives; no build or publication occurs. Rust standard-library targets are
added if absent, and `verify --installed-native` compares each bundle with its
selected installation. The explicit vendor step and companion `verify` both
use Cargo's real locked vendor generation; the latter regenerates independently
in the helper's fresh Cargo home. Network failures are expected to fail closed.
`v1.2.3` is an example valid stable tag.

```bash
set -eu
repo="$PWD"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
export CARGO_HOME="$tmp/cargo-home"
mkdir -p "$CARGO_HOME" "$tmp/artifacts"
rustup target add x86_64-unknown-linux-gnu x86_64-unknown-linux-musl
cargo vendor --locked --versioned-dirs "$tmp/package-vendor"
commit="$(git -C "$repo" rev-parse HEAD)"
for target in x86_64-unknown-linux-gnu x86_64-unknown-linux-musl; do
  printf 'non-executable verification marker\n' > \
    "$tmp/artifacts/tor-socks5-v1.2.3-$target.tar.gz"
  python3 -I "$repo/.github/release/source_companion.py" package \
    --repo-root "$repo" --artifacts-dir "$tmp/artifacts" \
    --tag v1.2.3 --commit "$commit" --target "$target" \
    --vendor-root "$tmp/package-vendor"
  python3 -I "$repo/.github/release/source_companion.py" verify \
    --repo-root "$repo" --artifacts-dir "$tmp/artifacts" \
    --tag v1.2.3 --commit "$commit" --target "$target" --installed-native
done
```

The hook verifies vendor and selected native-material references; it does not build
or authenticate a release binary, certify licensing or legal compliance, or
establish host build tools or dynamically linked host libraries. CCADB/external-
term review also remains outside this check. Preserving source and notices is
not blanket clearance or legal advice.

## Inspecting and using the source

Unpack the companion, then unpack `project.tar` into a project directory. Place
its `cargo-vendor/` directory in that project (for example, as
`project/cargo-vendor/`). To build without registry access, add this source
replacement to `project/.cargo/config.toml`:

```toml
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "cargo-vendor"
```

Run Cargo from the project root with `--locked --offline`. This vendor tree is
for the locked external packages; the project archive also retains local path
crates and their complete included source and notices. The `resocks5-net`
dependency is a crates.io package, not a sibling SDK source tree.

## License and scope notes

The source companion preserves full vendored packages, including their license
and notice files and locally modified source. In particular, the complete
MPL-2.0 and CDLA-Permissive-2.0 package material is retained; a metadata allow
list is not a blanket permission. Follow each applicable license's terms,
including source and notice obligations. The ordinary `Apache-2.0` alternative
is selected only for the four packages offering
`Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT`, and the eight locally
patched vendor packages for which the canonical `Apache-2.0` text is delivered.
No LLVM-exception waiver is claimed. Other packages retain their authentic
offered license terms.

Recipients can find this README in the shipped `project.tar`, at
`.github/release/README.md` after unpacking that archive. For an executable,
use its matching source companion: exact source for included packages, including
MPL-2.0-covered package source, and the corresponding package license and notice
files are retained under `cargo-vendor/` alongside the package source.

The helper preserves `share/doc/rust/licenses/Apache-2.0.txt`,
`share/doc/rust/licenses/MIT.txt`, `share/doc/rust/COPYRIGHT.html`,
`share/doc/rust/COPYRIGHT-library.html`, and all other installed files under
`share/doc/rust/licenses/` from the selected sysroot. For the selected target it preserves the installed Rust
standard-library component manifest and hashes manifest-listed regular `.rlib`,
archive, shared-library, and object inputs under that target's `lib` directory;
`libstd` and `libcompiler_builtins` rlibs are required. These are upstream
Rust-distribution materials collected as distributed, not a finding that any
particular Rust license grants use of musl or another input.

This inventory excludes host build tools, dynamically linked host libraries,
and files outside those documented and selected-target scopes. The finite gap
for musl is that the exact applicable source and terms linkage for Rust-distributed
self-contained musl `libc.a` and startup objects is not established; host
`musl-tools`/apt copyright material is not attributed to those Rust inputs.
Publisher verification checks native structure and self-reported integrity,
not independent authenticity; the CI installed-reference comparison is still
not a build receipt. No build receipt, legal certification, or complete-input
clearance is claimed. Preserving upstream texts does not assert their terms
apply to every hashed input and is not legal advice.

## CI verification

The release-package suite is run in CI with
`python3 -I .github/install/tests/test_release.py`. Do not treat this workflow
documentation as evidence that the workflow has been generated or executed.
