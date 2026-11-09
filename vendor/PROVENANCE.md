# Vendor source provenance and unresolved license evidence

This is a **scoped provenance record**, not a claim of legal clearance. It
records locally observed registry-archive identities and bounded comparisons;
the published package README offers and delivered Apache-2.0 text below are the
stated material basis. It does not establish a rights holder or grant beyond
that basis, and is not legal approval.

## Baseline evidence

The seven Arti crates' published archived `README.md` files and `Cargo.toml.orig`
metadata declare `MIT OR Apache-2.0`; `saturating-time` does too. The README
offers are the package-level licensing basis recorded here; no holder is
inferred from package author fields or the repository's root license. The
reviewed repository baseline is commit
`16239aae44407237d9fd3987e58082860b6cedcc`; the canonical upstream repository
is `https://gitlab.torproject.org/tpo/core/arti.git/`. Each
`.cargo_vcs_info.json` identifies commit
`ce8bc6e0998bd5a4efdf06dd62dce53c98ea1087` and its listed `crates/<name>`
path. The baseline archives came from the canonical crates.io static archive
URL pattern `https://static.crates.io/crates/<name>/<name>-<version>.crate`.

| Crate | Version | VCS path | SHA-256 of downloaded `.crate.gz` |
|---|---:|---|---|
| `arti-client` | 0.47.0 | `crates/arti-client` | `43e6531f26fe6f44d71dabdc63b7845bae81547cc738aa942f0e3e482f776388` |
| `tor-chanmgr` | 0.47.0 | `crates/tor-chanmgr` | `431ba53bf020ea8681ef0c2fbf0f0f854997fca9afe1b2c081f41f14ec00cf5d` |
| `tor-circmgr` | 0.47.0 | `crates/tor-circmgr` | `8b6b55747c690e0c931c5a081640ffdca6d1003c01b57b8102afcbdbaf3ec3fd` |
| `tor-dirclient` | 0.47.0 | `crates/tor-dirclient` | `f942f4ebaf2ac5275e48d02d77abe1616ce2e8854f032a1b0698ede0566dddfc` |
| `tor-dirmgr` | 0.47.0 | `crates/tor-dirmgr` | `34ea5e77b43bf1ef5fa213a89cb67080f218df6b418c82527e6bb9862a39aef5` |
| `tor-guardmgr` | 0.47.0 | `crates/tor-guardmgr` | `87694603d6dcee5e0b050f0e7ac8be86348eb78ecb90c36ee8b70bd5822f3eff` |
| `tor-ptmgr` | 0.47.0 | `crates/tor-ptmgr` | `0068103033ae2dcedf88691c4758b1e483dd31d325e4891f5e0d3bb41f24ecbc` |
| `saturating-time` | 0.5.0 | `crates/saturating-time` | `a586db154f85f3faf78398c37b6792d71f99d2253d3277571e14f8a8c6e49a65` |

The ignored evidence area is `target/task78-evidence/archives/`: it contains
those eight named `.crate.gz` files, per-archive `.crate` and `archive.tar`
files, and extracted native data copies. Extracted trees are under each
archive's `contents/extracted/<name>-<version>/`; `contents/data/` copies are
present for some archives. The observed `target/task78-evidence/upstream/`
subdirectories `LICENSE-MIT/`, `LICENSE-APACHE/`, and
`saturating-time-history/` are empty. These paths are local, ignored evidence,
not part of this deliverable.

## Comparison observations

At that reviewed repository snapshot, native `git diff --no-index --name-status`
comparisons of each pre-existing `vendor/<crate>` tree against its extracted
archive reported the following differences; this comparison excludes this new
provenance document. `M` means the named path differs. `Cargo.toml` changes
include local vendoring/patch configuration; source diffs identify divergence,
not its author or license.

| Crate | Vendor-only paths | Differing paths |
|---|---|---|
| `arti-client` | `.cargo-ok`, `src/client/stream_retry.rs` | `Cargo.toml`, `src/builder.rs`, `src/client.rs`, `src/config.rs`, `src/lib.rs`, `src/status.rs` |
| `tor-chanmgr` | `.cargo-ok` | `Cargo.toml`, `src/builder.rs`, `src/config.rs`, `src/lib.rs`, `src/mgr/select.rs`, `src/mgr/state.rs`, `src/mgr.rs` |
| `tor-circmgr` | `.cargo-ok` | `Cargo.toml`, `src/config.rs`, `src/hspool/pool.rs`, `src/hspool.rs`, `src/lib.rs`, `src/mocks.rs`, `src/path/exitpath.rs`, `src/path/hspath.rs`, `src/path.rs`, `src/timeouts/pareto.rs` |
| `tor-dirclient` | `.cargo-ok`, `src/local_test.rs` | `Cargo.toml`, `src/err.rs`, `src/lib.rs` |
| `tor-dirmgr` | `.cargo-ok` | `Cargo.toml`, `src/bridgedesc.rs`, `src/err.rs`, `src/shared_ref.rs` |
| `tor-guardmgr` | `.cargo-ok` | `Cargo.toml`, `src/events.rs`, `src/guard.rs`, `src/lib.rs`, `src/pending.rs`, `src/sample.rs` |
| `tor-ptmgr` | none observed | `Cargo.toml`, `src/ipc.rs`, `src/lib.rs`, `src/managed.rs` |
| `saturating-time` | `.cargo-ok` | `Cargo.toml`, `src/internal.rs`, `src/lib.rs` |

All eight vendor `README.md` files were byte-equal to their extracted archive
READMEs (SHA-256 comparison). The two vendor-only Rust paths above are local
additions relative to the archives; source changes and additions alone do not
establish authorship or licensing for patches. The README's patch table also
identifies local patches, including `tor-circmgr` service-circuit-hop changes;
that description is not a rights grant.

## Published license offers and delivered text

Each unchanged package README explicitly offers `MIT OR Apache-2.0`:

| Crate | Published README line |
|---|---:|
| `arti-client` 0.47.0 | 323 |
| `tor-chanmgr` 0.47.0 | 39 |
| `tor-circmgr` 0.47.0 | 43 |
| `tor-dirclient` 0.47.0 | 29 |
| `tor-dirmgr` 0.47.0 | 58 |
| `tor-guardmgr` 0.47.0 | 108 |
| `tor-ptmgr` 0.47.0 | 58 |
| `saturating-time` 0.5.0 | 106 |

A byte-for-byte copy of the complete standard Apache-2.0 license text is now
provided as `LICENSE-APACHE` in each of these eight crate directories. The
operator-authorized retained text came from a file named
`wasm-tools-upstream-capture/LICENSE-APACHE`; its SHA-256 is
`a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`, also
verified for every delivered copy. This is the standard license text, **not an
Arti upstream LICENSE download**, and does not convey or imply a wasm-tools,
LLVM, Mozilla, or other copyright grant in Arti source. No holder is inferred
from the license text, package authors, or the repository's root license.

The source package README files and any source copyright/notice material were
not edited. Apache-2.0 §4(a) license-copy delivery is in place for the README
offers. The archived package listings contained no standalone `NOTICE` member;
§4(d)'s NOTICE preservation is conditional and is not presumed required solely
because a root-file retrieval was unavailable. The scoped filename/text review of the exact registry archives (archive member
names, package READMEs, and `Cargo.toml.orig`) found no competing file-level
grant or standalone NOTICE. This is not a claim about arbitrary upstream
source or files outside that archive scope. Relevant source attribution
comments, including bridge-data references, remain unchanged. Apache-2.0 §4(c)
requires retaining applicable source notices; this task preserved existing source
content and notices/attribution comments, adding only the change notices recorded
below, and does not assert an individual notice applies or resolve every file's
applicability. A C Tor
math reference, Codeberg maintenance history, or fixture presence alone is not
treated as evidence of an additional license requirement; no independent grant
is inferred for those materials.

## Modification notices and unresolved retrieval

The comparison table above identifies the modified paths. Existing
`tor-socks5 local patch` comments occur in many modified source files. These
nine modified files were the remaining paths identified as lacking a prominent
change notice:

* `tor-chanmgr/Cargo.toml`
* `tor-chanmgr/src/config.rs`
* `tor-dirclient/Cargo.toml`
* `tor-dirmgr/Cargo.toml`
* `tor-guardmgr/Cargo.toml`
* `tor-ptmgr/Cargo.toml`
* `tor-ptmgr/src/ipc.rs`
* `tor-ptmgr/src/lib.rs`
* `tor-ptmgr/src/managed.rs`

Each listed file now carries a prominent ordinary comment directing readers to
this provenance record. This list is retained as the mutation record for this
bounded edit. Only change-notice comments were added to these source files and
manifests; no runtime tokens or manifest values were changed. These additions
document notices but do not establish that every relevant change or file has
been noticed or otherwise determine §4(b) compliance.

The retrieval worker reported HTTP 403 for the pinned upstream GitLab raw paths
`/-/raw/ce8bc6e0998bd5a4efdf06dd62dce53c98ea1087/LICENSE-MIT` and
`/-/raw/ce8bc6e0998bd5a4efdf06dd62dce53c98ea1087/LICENSE-APACHE`. That
historical retrieval remains unresolved; no retry, alternate URL, provider,
mirror, or history was used in this task. The copied standard Apache text is
not represented as that unavailable Arti file. No MIT license text was added.

Applicable Apache-2.0 §4(c) source notices remain to be retained; this task did
not alter source README/copyright/notice bytes or establish individual notice
applicability. This bounded record is not legal advice, legal approval, or global
clearance, and does not claim material closure.
