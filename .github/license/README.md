# Third-party license policy

Ordinary CI checks dependency license metadata with `cargo-deny`, using
[`.github/deny.toml`](../deny.toml):

```sh
cargo deny --locked --config .github/deny.toml check licenses
```

The configured allowed SPDX identifiers are MIT, Apache-2.0, BSD-2-Clause,
BSD-3-Clause, ISC, Unicode-3.0, Zlib, Unlicense, CC0-1.0, BSL-1.0, MPL-2.0,
and CDLA-Permissive-2.0, at a confidence threshold of 0.93. The exact
`priority-queue` 2.7.0 MPL-2.0 exception is also configured. These are
metadata-policy atoms, not blanket package or GPL/LGPL permissions.

This routine CI check is not legal review or release clearance. For distribution,
preserve applicable license and copyright notices, and meet applicable source-
access obligations, including for MPL-covered material. Review the CDLA
agreement accompanying any shared Data; do not assume a Data/Results
classification waiver. Vendored license materials and local modification
notices are documented in [vendor provenance](../../vendor/PROVENANCE.md).
Recipient delivery and native-input composition remain separate release
obligations. The bounded basis for the current CCADB-derived packages follows.

## Current webpki-roots redistribution

For the crates.io `webpki-roots` 0.26.11 and 1.0.7 packages pinned in
[`Cargo.lock`](../../Cargo.lock), both package manifests declare
`CDLA-Permissive-2.0` and include the complete agreement. Their packaged READMEs
refer to the CCADB Data Usage Terms with an explicit "see LICENSE" pointer.
The corresponding upstream commits are
`65a47ac297fb378a602472d447b1260439253bd4` and
`be948464fd5907af6227213a066743a161221688`.

The supplied agreement grants use, modification and sharing in section 1.1;
section 5.3 expressly includes direct or indirect receipt. Section 2.1 requires
making the agreement text available with shared Data. For this package-based
distribution path, preserve the complete package license, source notices and
certificate fixtures in the matching [source companion](../release/README.md),
and make that companion available with each binary in the same release. Treat
the shared material conservatively as Data, without relying on a Results
exemption. Version 0.26.11 re-exports its version-1 parent; the locked 1.0.7
package contains the anchor table.

These package-specific materials support the described receipt and unchanged
redistribution subject to those duties. No additional unmet condition or
contrary notice was identified in the reviewed material. This is not a title
warranty or legal certification: the external CCADB page and historical direct-
acquisition conditions were not independently verified. This decision does not
cover downloading fresh CCADB data, regenerating the packages, or disregarding
a concrete contrary notice; those changes require a scoped reassessment. Keep
the upstream references and authentic notices intact.
