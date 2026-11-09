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
Recipient delivery, native-input composition, and CCADB/external-terms review
remain separate release obligations.
