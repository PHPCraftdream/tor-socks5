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
license review was first performed at repository commit
`16239aae44407237d9fd3987e58082860b6cedcc` on the 0.47.0 archives and repeated
on 2026-11-10 for the 0.48.0 re-baseline: the README license-offer lines and
the `Cargo.toml` / `Cargo.toml.orig` license fields are unchanged, and the
archives still contain no standalone `NOTICE`, `LICENSE*` or `COPYING*` member.
The canonical upstream repository is
`https://gitlab.torproject.org/tpo/core/arti.git/`. Each 0.48.0
`.cargo_vcs_info.json` identifies commit
`7c038125baef924a4bf287429c192c5af606f79c` and its listed `crates/<name>`
path. The archives came from the canonical crates.io static archive URL pattern
`https://static.crates.io/crates/<name>/<name>-<version>.crate`.

Current baseline (synced 2026-11-10):

| Crate | Version | VCS path | SHA-256 of downloaded `.crate.gz` |
|---|---:|---|---|
| `arti-client` | 0.48.0 | `crates/arti-client` | `5bb17a5096e30f2b2bf9f7493ff7577ac66ed7059b8e435658a2884546afe70c` |
| `tor-chanmgr` | 0.48.0 | `crates/tor-chanmgr` | `6d6086ead3951f0af897d593a33e1c9ed411e8b3d97d82da971ed08838382108` |
| `tor-circmgr` | 0.48.0 | `crates/tor-circmgr` | `13157eea9e95141a327b947a4cb600525a0db229208c689c7b06b2947ed59ff8` |
| `tor-dirclient` | 0.48.0 | `crates/tor-dirclient` | `3a0b528c94c6df7ea4084ceedfc370266f5b004c0827258b4cd081bf5fd81852` |
| `tor-dirmgr` | 0.48.0 | `crates/tor-dirmgr` | `86f7ac56b491b26a6f2b73f0f16fa7a0c66b507163e0f0ed850334b86169b326` |
| `tor-guardmgr` | 0.48.0 | `crates/tor-guardmgr` | `4a300b7ee657f837bfd7fa71c546fb3a53b291d84a7c0bf2086a53ab5de79b90` |
| `tor-ptmgr` | 0.48.0 | `crates/tor-ptmgr` | `e5a85e68659fc0627daa90cb7c1993461801ace009fc22aec230a62cdef27747` |
| `saturating-time` | 0.6.0 | `crates/saturating-time` | `f950f7f265dc6fc082387eccf710b1adbf22d75f17c4ee0db4648c9b6959b50d` |

Previous baseline (synced 2026-10-13, upstream commit
`ce8bc6e0998bd5a4efdf06dd62dce53c98ea1087`). These archives were the base of the
three-way merge used for the 0.48.0 sync; they were downloaded again on
2026-11-10 and every SHA-256 below matched before the merge:

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

For the 0.47.0 baseline, the ignored evidence area
`target/task78-evidence/archives/` contained those eight named `.crate.gz`
files, per-archive `.crate` and `archive.tar` files, and extracted native data
copies. Extracted trees were under each archive's
`contents/extracted/<name>-<version>/`; `contents/data/` copies were present
for some archives. The observed `target/task78-evidence/upstream/`
subdirectories `LICENSE-MIT/`, `LICENSE-APACHE/`, and
`saturating-time-history/` were empty. These paths are local, ignored
evidence, not part of this deliverable.

## Comparison observations

After the 0.48.0 sync, native `git diff --no-index` comparisons of each
`vendor/<crate>` tree against its extracted 0.48.0 archive report the following
differences; `LICENSE-APACHE`, delivered separately below, and this provenance
document are excluded. The sync merged each file three ways (base: the
0.47.0 archive, ours: the previous `vendor/` tree, theirs: the 0.48.0 archive);
only the `version` lines of the `Cargo.toml` manifests conflicted and were
resolved by hand. `Cargo.toml` changes include local vendoring/patch
configuration; source diffs identify divergence, not its author or license.

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
that description is not a rights grant. `saturating-time` 0.6.0 itself adopted
the lazy `saturating_add`/`saturating_sub` arithmetic and a termination check
of the limit search, so its remaining differences are marker comments, ignored
tests and one regression test.

## Published license offers and delivered text

Each unchanged package README explicitly offers `MIT OR Apache-2.0`:

| Crate | Published README line |
|---|---:|
| `arti-client` 0.48.0 | 323 |
| `tor-chanmgr` 0.48.0 | 39 |
| `tor-circmgr` 0.48.0 | 43 |
| `tor-dirclient` 0.48.0 | 29 |
| `tor-dirmgr` 0.48.0 | 58 |
| `tor-guardmgr` 0.48.0 | 108 |
| `tor-ptmgr` 0.48.0 | 58 |
| `saturating-time` 0.6.0 | 106 |

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
