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

The package command uses the supplied vendor directory and does not fetch Cargo
registry source. For only Rust 1.99.1 at the reviewed commit and the two reviewed
musl targets, packaging additionally fetches the fixed, SHA-256-pinned musl
evidence set described below. No extraction or execution of those downloads
occurs; non-musl targets do not gain source downloads or version pins. Plain
publisher `verify` does not refetch reviewed musl evidence; it validates those
packaged files against independent hardcoded SHA-256 pins. Separately, `verify`
invokes locked `cargo vendor --versioned-dirs` from the release checkout with a
fresh `CARGO_HOME`, then compares every path and byte in `cargo-vendor/` to
Cargo's regenerated output; this can fetch registry data.
`verify --installed-native` additionally recollects the selected installation,
including refetching and pin-checking reviewed musl evidence, and compares it
with the packaged bytes. Network or registry failures fail verification closed.
The bundle also binds the named source archive to commit, target, and binary
archive digests; these bindings are not build receipts and do not prove the
binary was built from that source. Bundled checksum maps are structural
self-consistency checks only, not authenticity proofs. This boundary relies on
the publisher's Cargo executable and checkout/configuration trust. Use a clean
checkout: the helper checks that the working `Cargo.lock` exactly matches the
requested Git commit, but relies on other tracked manifests being clean as in
CI. It supports only the exact crates.io source in the current lockfile and
rejects Git, alternate-registry, and other external sources. Local path crates
are retained in `project.tar`.

## CI real-Cargo smoke hook

Run this in a clean CI checkout with Rust/Cargo installed. It packages GNU and
musl targets from the installed Rust distribution using non-executable marker
archives; no build or publication occurs. For musl, the installed rustc must be
Rust 1.99.1 at commit `58cf8f9c35b355199727627d07ae34a4e2846d67`, and only
`x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` are reviewed.
Rust standard-library targets are added if absent, and `verify --installed-native`
refetches and compares each bundle with its selected installation and the pinned
musl evidence. The explicit vendor step and companion `verify` both use Cargo's
real locked vendor generation; the latter regenerates independently in the
helper's fresh Cargo home. Network failures are expected to fail closed.
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

The helper byte-for-byte preserves the installed
`share/doc/rust/licenses/Apache-2.0.txt`,
`share/doc/rust/licenses/MIT.txt`, `share/doc/rust/COPYRIGHT.html`,
`share/doc/rust/COPYRIGHT-library.html`, and all other installed files under
`share/doc/rust/licenses/` from the selected sysroot. For the selected target it
preserves the installed Rust standard-library component manifest and hashes
manifest-listed regular `.rlib`, archive, shared-library, and object inputs
under that target's `lib` directory; `libstd` and `libcompiler_builtins` rlibs
are required. The reviewed `generatecopyright` inputs are the REUSE tree and
Cargo dependencies; they exclude the external musl recipe. Therefore the report
filename alone cannot establish that generated attribution covers the
Rust-distributed musl libc.

### Reviewed musl source evidence

For the exact installed identity Rust 1.99.1, commit
`58cf8f9c35b355199727627d07ae34a4e2846d67`, and targets
`x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`, the bundle adds a
finite evidence set under `native-material/musl/`: the original
`musl-1.2.5.tar.gz`, four exact patch files, `musl-toolchain.sh`, both musl
Dockerfiles used by Rust's distribution build, the musl-cross-make `Makefile`
and `litecross/Makefile`, the recipe's `musl-1.2.5.tar.gz.sha1` file, and the
authentic musl-cross-make `LICENSE` and `COPYRIGHT` files. Each downloaded file
has an independent hardcoded SHA-256 pin in the helper; its pinned URLs are
recorded there. The musl archive SHA-256 is
`a9a118bbe84d8764da0ea0d28b3ab3fae8477fc7e4085d90102b8596fc7c75e4`.

The source chain is anchored to Rust's pinned distribution manifest,
https://static.rust-lang.org/dist/channel-rust-1.99.1.toml, and the full Rust
commit above. The pinned musl-cross-make recipe at
`3635262e4524c991552789af6f36211a335a77b3` specifies musl 1.2.5 and its
`0001`/`0002` patches; Rust's pinned CI source contributes the two additional
2026 diffs (`musl-cve-2026-6042.diff` and `musl-cve-2026-40200.diff`). The
recipe's SHA-1 file records `36210d3423172a40ddcf83c762207c5f760b60a6` for the
musl archive. The source archive and all four patches are preserved as
downloaded; they are not extracted, executed, or presented as an
applied/fabricated source tree. Original source file notices remain in the
archive. Musl's primary copyright text is at
https://git.musl-libc.org/cgit/musl/plain/COPYRIGHT?h=v1.2.5: the general MIT
notice attributes copyright to Rich Felker, 2005–2020, and references third-party
notices; its explicit CRT/header attribution exception applies to its listed
files, not as a blanket attribution for all of libc. The musl-cross-make
`COPYRIGHT` states that its patches are under the upstream project license;
retaining the recipe's authentic MIT/Expat `LICENSE` and `COPYRIGHT` documents
preserves those notices and does not grant new rights.

The Rust distribution Dockerfiles build and install musl using the pinned
recipe. During Rust's distribution bootstrap, `compile.rs` copies musl-root
`libc.a` and CRT objects and stamps them `TargetSelfContained`; `dist.rs` then
copies those stamped inputs into ruststd's self-contained target. Separately
collected `libunwind` or LLVM CRT inputs are not musl and are not evidence about
musl. This source/notice linkage closes the finite source-evidence gap only for
the two reviewed targets and identity. It does not prove machine-code
correspondence, a linker/build receipt, or universal legal clearance. Other
identities—including synthetic identities—remain unresolved; future stable
releases are not covered by inference. Unsupported identities fail closed and
require source review and refreshed pins rather than silent attribution.

This inventory excludes host build tools, dynamically linked host libraries,
and files outside those documented and selected-target scopes. Publisher
verification checks native structure and included-document/manifest hashes
against the bundle's self-reported values; the installed target-input digests
are self-reported, not independently authenticated. The helper's additional
independent fixed SHA-256 pins apply only to the reviewed musl evidence files.
`verify --installed-native` also compares the bundle with a fresh collection
from the selected installation, but is not a build receipt. No build receipt,
legal certification, or complete-input clearance is claimed. Preserving
upstream texts does not assert their terms apply to every hashed input and is
not legal advice.

## CI verification

The release-package suite is run in CI with
`python3 -I .github/install/tests/test_release.py`. The additional source
companion hook can run `python3 -I .github/release/test_source_companion.py`.
Do not treat this workflow documentation as evidence that the workflow has been
generated or executed.
