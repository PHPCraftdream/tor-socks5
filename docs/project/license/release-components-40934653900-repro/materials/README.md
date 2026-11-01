# Source distribution materials: research p/q

## Confirmed parent recomputation

Parent performed two independent bounded data-only runs with `python -I` after reviewing the source and input pins. Both exited with code 0; all three p/q results also matched in direct `cmp` and SHA-256 comparisons. The p/q results contain 727 components, 727 processed archives and 0 archive failures; all 15 programmatically false `branch_substantive_text_not_located_by_content` entries disappeared. Actual external/missing materials remain blockers. This is not a project test, a complete per-file audit or legal approval. Command used for run p (a new reproduction requires a different exclusive output name):

```sh
python -I docs/project/license/release-components-40934653900-repro/materials/research.py \
  --report target/materials-20261030-d/report.json \
  --report-size 14665213 \
  --report-sha256 ca11d57b71928b2d23400d2df0cb04fc08580f3b97cd2988fa7ea083d2fa0055 \
  --materials target/materials-20261030-d/materials.json \
  --materials-size 86208679 \
  --materials-sha256 aa67048c936c30403499338457aee93af52a2b05ff64e6897e8468c10e1ff399 \
  --target-root target \
  --output target/materials-research-20261030-p
```

The directories `target/materials-research-20261030-p` and `-q` were created exclusively. The inputs are the previously pinned `report.json` 14665213/`ca11d57b…fa0055` and `materials.json` 86208679/`aa67048c…1ff399`, checked before and after parsing. Historical n/o outputs are retained without overwriting.

| p/q result | Size | SHA-256 |
| --- | ---: | --- |
| `research.json` | 96454549 | `43f39d841bf58b128c07f5cecd7359209e0cb1cd6da019c82328e1ab5b81d2a6` |
| `summary.json` | 1711 | `8daf33662c94c5dd1b8d64d54a6e9c6877b106e22920e6a845dc64713aae4a88` |
| `components.md` | 2462522 | `f56c80f8186fb3f4e33ce649ae0f9638292b3cfa3e00f9448969a803e64d07e7` |

The p/q results still contain 164 `absent_standalone_branch_material`, 2 `branch_material_missing_from_named_text_set`, 2 `declaration_and_missing_named_license`, 2 `declaration_not_full_license`, 10 `declaration_or_referral_only`, 2 `external_ccadb_terms_not_saved`, 4 `llvm_exception_full_text_not_found_in_retained_materials`, 2 `outside_crate_readme_referral`, 83 `referenced_material_not_in_archive_inventory`. These are separate records, not a count of unique components. The other figures below, marked n, are retained as history; parent does not present them as a new independent substantive reading of all texts.

## Work completed

### Archives/copies layer

Complete and reproducible: 727/727 registry crates were parsed (`DATA_COMPLETE`, exit 0, blockers 0); 1212/1212 copies matched byte for byte; an independent audit rerun produced identical hashes. The 18 previously rejected raw modes are supported only as cases with redundant regular-file type information (type bit `0o100000` with typeflag `0`/NUL and permissions ≤ `0o777`), with 0 devices. Compatibility is confirmed by the local Python standard-library text; this is **not** proof of producer provenance.

### New substantive text-reading layer (complete for available full retained texts serving license roles)

- 1184 material records, 402 unique groups of full texts (SHA-256). All 1184 have `substantively_read=true`; 0 unread.
- 366 groups were read anew in this round; 36 were already covered by earlier verified readings.
- New evidence is associated with 624 components.
- 645 of 727 components have condition evidence; each of the 727 has either condition evidence or an explicit blocker; 0 have neither.

### Group decisions — exactly 366 groups read anew

The distribution below covers **only the 366 groups read anew in this round**, not all 402 covered groups: `full_terms_observed` 353; `mixed_terms_observed` 6; `native_or_data_specific_terms` 3; `referral_only` 2; `declaration_only` 2. Total covered groups: **402 = 366 new + 36 previously verified**; the decision distribution across all 402 groups cannot be inferred from these values.

Decision distribution across all 1184 records: `full_terms_observed` 1114; `mixed_terms_observed` 23; `native_or_data_specific_terms` 22; `declaration_only` 7; `declaration_only_candidate` 8; `referral_only` 7; `explicit_no_license_statement` 1; `pointer_multiple_materials` 1; `substantive_terms_observed` 1.

These are **observations of text**, not legal conclusions or approval.

### Evidence semantics

`condition_evidence` contains only manually reviewed/substantive spans, not keyword matches. The automated marker scan is labeled separately and does not establish permissions/conditions/limits. `conclusion_ru` does not infer legal effects. Branch observations distinguish substantive manual evidence from keyword marker matches.

### Provenance of semantic span review

35 part1 records (reopened/suspect), plus the named group `c144680885b29e4719e2a51f0aab5439a1e02d980692b5aaf086cae12727f28b`, underwent semantic review through read-only text reading; in `research.py`, this is the `SEMANTIC_SPAN_REVIEWED_HASHES` set (36 hashes), and `semantic_span_review: 'confirmed_by_read_only_text_review'` is added to the corresponding `manual_observation` entries. Source pins: part1 review JSON 24996 bytes, SHA-256 `9aea66865464fa3c9b464417a564c6e2030e4610d5d45131c85ea4dfbc48f5b4`; named-group review JSON 5623 bytes, SHA-256 `269b45b3049aaf4fbe74fee96a84256024e2678100d1ce53dc4c691fef761892`. This confirms the provenance of these records and **does not itself approve** any license.

Before run p, parent reread the full libm and Apache-with-LLVM texts from `target/unread-groups-20261030-a/unread-groups.txt` (1519674 bytes, SHA-256 `6aec8686bbbb5bc21bc603cb20a2ffc26690b7ce5cae457461e4238323b0571d`; the hash was checked before and after reading). For libm `3823dda7…16bb7`, the corrections include the contributor declaration, full Apache text and native/source notices through local line 258. For LLVM `268872b9…86bc5`, section 9 through line 175 and the GPLv2-conflict clause at 212–219 are included. `PARENT_SPAN_CORRECTIONS` changes the actual input spans before they are constructed; earlier review JSON files are retained as history, not presented as corrected. The absence of a quotation shorter than 1500 bytes no longer implies the absence of substantive reading: the summary refers to the full `condition_evidence`.

Branch-matcher reconciliation: the `MANUAL_BRANCH_RECONCILIATION` map in `research.py` documents all 15 `branch_substantive_text_not_located_by_content` cases from n (component/version/branch + confirmed material hash). This is a review reconciliation map, not a claim that missing external texts exist or approval of a license choice.

## Research n pins

Final pinned run `target/materials-research-20261030-n`, independent rerun `target/materials-research-20261030-o`, with byte-identical outputs:

| File | Size | SHA-256 |
| --- | ---: | --- |
| `research.json` | 96294938 | `ecf783859be8bb718e093c669f8242ae7bc14903a3900ddbb52eec379f303c24` |
| `summary.json` | 1763 | `ace3c424b96883fb775b10a84dc89943717b4f616ec7520b0360639c8325395d` |
| `components.md` | 2462830 | `13980e67e39473011ab3d47bda1cc8e5f9848ca6d9d0d0893da5e5a8fbc84637` |

The inputs remain pinned: `report.json` 14665213 bytes, SHA-256 `ca11d57b71928b2d23400d2df0cb04fc08580f3b97cd2988fa7ea083d2fa0055`; `materials.json` 86208679 bytes, SHA-256 `aa67048c936c30403499338457aee93af52a2b05ff64e6897e8468c10e1ff399`.

Merged substantive evidence file: `target/unread-evidence-20261030-merged-v2/all.json`, 425379 bytes, SHA-256 `d3c85af14dcd911355a04ee42f0503d9d36e778442a1e9b5b124ba27a5cc2d9c`; exactly 366 keys; one known key typo was corrected to the exact hash. The file records the Russian-language rationale, decision and local line spans. The evidence was obtained by reading exported full group texts, not by keyword inference.

## Exact blocker counts for n

| Blocker | Count |
| --- | ---: |
| `absent_standalone_branch_material` | 164 |
| `branch_material_missing_from_named_text_set` | 2 |
| `branch_substantive_text_not_located_by_content` | 15 |
| `declaration_and_missing_named_license` | 2 |
| `declaration_not_full_license` | 2 |
| `declaration_or_referral_only` | 10 |
| `external_ccadb_terms_not_saved` | 2 |
| `llvm_exception_full_text_not_found_in_retained_materials` | 4 |
| `outside_crate_readme_referral` | 2 |
| `referenced_material_not_in_archive_inventory` | 83 |

No `license_text_not_substantively_read` entries remain. These blockers mean that substantive review is still **incomplete** at the source/obligations level; they identify specific missing/external/declaration-only boundaries, not proof that rights or texts do not exist. No PASS or closure is claimed.

## Tools

| Tool | Size | SHA-256 |
| --- | ---: | --- |
| `audit.py` | 13553 | `fdfd1768ba9bb4d23c83dd9f3ed97022cbc5d90546190e32716e7797a9d4db0d` |
| `archive-data.py` | 12441 | `d6b5e7e2ffaa4d6dda634230ef29be43df9f05ffd43654b7ee9ad55e7fe6c8e2` |
| `tar-data.py` | 7758 | `b1ac0f8bf8e1a4b4bdf0fedb4a642c6048549eae7a5476a9469c944e62216fa9` |
| `research.py` | 503744 (855 lines) | `204b4ffe542b298dd1da120078cf193941f65a7cbba9fe31ee5e60fd6e793f6c` |
| `summarize.py` | 5024 | `cc4342ec6fe33cbd2a61e6a3093021023da3c8d149fd1e9d4737503bdd78c146` |
| `../analyze-safe.py` | 23856 | `e02523826493e5816d644bf77d802917bb7773b5d01c158ccb06227af8f43a43` |

## Reproduction

```sh
python -I docs/project/license/release-components-40934653900-repro/materials/research.py \
  --report target/materials-20261030-d/report.json \
  --report-size 14665213 \
  --report-sha256 ca11d57b71928b2d23400d2df0cb04fc08580f3b97cd2988fa7ea083d2fa0055 \
  --materials target/materials-20261030-d/materials.json \
  --materials-size 86208679 \
  --materials-sha256 aa67048c936c30403499338457aee93af52a2b05ff64e6897e8468c10e1ff399 \
  --target-root target \
  --output target/materials-research-new
```

The pin is checked before and after each parse; every run requires a new exclusive output directory name. The current tool reproduces the corrected p/q result, not historical n/o. Choose another new name for an independent rerun; parent compared all three p/q files byte for byte.

## Specific findings and missing materials

- LLVM exception: the full text is absent from retained materials for `wasip3 0.4.0+wasi-0.3.0-rc-2026-01-06`, `wasmparser 0.244.0`, `wit-component 0.244.0`, `wit-parser 0.244.0`; all have the manifest expression `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT`. A reference to the reference TEXT with SHA-256 `268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5` exists for 12 other components and remains separate. Official parent website checked by parent: https://llvm.org/; Developer Resources → Sources (GitHub): https://github.com/llvm/llvm-project/; policy: https://llvm.org/docs/DeveloperPolicy.html. Locally retained capture `target/llvm-primary-20261030-c/LICENSE.TXT`: 15141 bytes, SHA-256 `8d85c1057d742e597985c7d4e6320b015a9139385cff4cbae06ffc0ebe89afee`, blob `fa6ac540007032cbd0ec772a1c72e6cb5527a4fe`, commit `e9996a2e210d021783d597d99ccd3199b0885d49`, metadata date `2026-10-30T09:04:11Z`; the target pin/headers/contents/commit/provenance retain the details. Parent independently checked wc/hash/git hash and read all 279 lines.

  Substantive terms observed in the retained text, paraphrased here: §2 grants copyright rights to reproduce, prepare derivative works, publicly display/perform and sublicense source and object code; §3 grants a patent license only for claims necessarily infringed by a Contributor's contribution alone or in combination with the Work, and terminates the patent licenses granted for that Work as of the date of filing litigation against any entity (including a cross-claim or counterclaim) alleging that the Work or an incorporated Contribution constitutes direct or contributory patent infringement (85–91); this is not termination of the entire license. §4(a) requires giving recipients a copy of the license (98–99), (b) requires prominent notices of changes (101–102), (c) requires retaining relevant notices in the source form of a derivative work (104–108), and (d), if the original Work contains NOTICE, requires a readable copy of relevant attribution notices in NOTICE, accompanying source/documentation or the customary display of notices (110–125). §6 covers trademarks (142–145); §§7–8 cover warranty/liability (147–167); §9 covers offering support on one's own behalf and indemnity (169–178). The exception (210–213) concerns only the case where compiling YOUR source embeds portions of the Software in the Object form of YOUR source: the waiver is limited to §§4(a), 4(b), 4(d), and §4(c) is not waived; this is not a general exception for a linked binary. The GPLv2 condition (215–222) applies only when combining/linking and a court finds a conflict with §3, §9 or another section; waiver/exclusion of an entire section is permitted only for the Combined Software. Third-party terms (227–234) have separate licenses; legacy terms (236–279) do not imply universal relicensing. Capturing/quoting a license text does not prove that a license was granted or applies to the four crates, establish historical package composition, or select an OR branch. The spurious blocker “LLVM URL not locally authorized” has been withdrawn.
- webpki-roots: a supplemental CCADB snapshot capture and historical text are retained in `target/ccadb-capture-20261030-b/`; exact pins, provenance, scope and earlier capture errors are described below. This is supplemental material; it does not remove the original two dataset blockers or prove applicability to a particular acquisition.
- r-efi: LGPL-2.1-or-later is declared; the full text is absent.
- dynasm/dynasmrt: MPL is declared; the `LICENSE` file is absent.
- enum_dispatch/ident_case: the full MIT text is present; the declared Apache text is absent.
- plotters×3 and objc2×2: references point outside the crate.
- Verified full/mixed readings are retained: the breakdown of XZ `COPYING`, ring BoringSSL/other-bits/once_cell, CDLA, Text-Template Artistic/GPL, sqlcipher, and standard MIT/Apache/BSD/MPL/GPL families.

## Supplemental CCADB source capture (does not change the p/q ledger)

This is separate supplemental evidence; the 2 `external_ccadb_terms_not_saved` blockers remain in p/q, and total component/record counts have not been recomputed. Sizes known before the requests were 3455, 3795 and 9 bytes, each below 256 KiB. GitHub API repository identity: `mozilla/www.ccadb.org`, `https://github.com/mozilla/www.ccadb.org`; the Contents API points to `CNAME` blob `b3e1ca9565397ea6b38b0146c0927d6825ad2417`; raw `site-domain.raw` is 9 bytes, SHA-256 `86b0d6b8758ff0ea2f7ec6c072c5902860ddcb87f86a845c9f761cbd86174c43`, with content `ccadb.org`. This establishes repository/domain correspondence, but the official identity of the site and its operator has **not been independently confirmed**.

| Snapshot | Commit and API date | Blob | Raw file; bytes; SHA-256 |
| --- | --- | --- | --- |
| Historical snapshot | `ed227276cd5b805ebd5ff4801bf17c7be08879e5`; 2024-02-05T18:59:53Z | `00c2471031374d39ce8513997a7c64ac86fb7f88` | `historical.raw`; 3795; `571ee086badc1fba7501838444f1cd22727d11e9d16b61d6706ea2919e4350f4` |
| Attribution/CDLA snapshot (not current master) | `499b8818c174030e979041842d1d4cfb5fcbda89`; 2025-02-03T20:55:16Z | `083d4c664ff6ce5e2a4e8bc36a4fed19462038d7` | `current.raw`; 3455; `d7cd416996cde7d455e9e8a611d34a73967d92b60365b7eae3be9cde8049320a` |

Both contents were obtained through `gh api repos/mozilla/www.ccadb.org/git/blobs/<blob> -H 'Accept: application/vnd.github.raw+json'`; `current.http`/`historical.http` are `gh api -i` responses with HTTP 200, dates 2026-10-30 08:46:20Z and 08:46:21Z, and Content-Type text/plain; no Content-Length header is present. For the usage texts, pins were created before reading, but the ordering was violated for domain evidence; the exact sequence is given below. `provenance.md` contains commands, sizes, hashes, response-header details and limitations. The README/report do not replace these primary captures.

In `current.raw`, lines 5, 9–13, the text declares CDLA-Permissive 2.0; permits use, modification and redistribution subject to CDLA; requires CCADB attribution for redistribution or use in derived works; prohibits endorsement/promotion using names/marks without prior written permission; and refers to the full CDLA text. This paraphrases observations of the retained snapshot specifically, not evidence of the terms governing the historical acquisition of particular data. On 2026-10-30, parent also read matching text from the official page in transformed form; this is not a raw capture and does not close the applicability/historical-provenance gap.
In `historical.raw`, lines 5–21, the text permits redistribution/use subject to the stated endorsement/promotion restriction, followed by an AS IS warranty/liability disclaimer. The historical text is not the current snapshot. Commit dates are commit metadata dates, not proof of publication or of the terms governing a particular data acquisition.

**Exact local evidence** in pinned `target/materials-research-20261030-q/components.md` (2,462,522 bytes; SHA-256 `f56c80f8186fb3f4e33ce649ae0f9638292b3cfa3e00f9448969a803e64d07e7`), lines 648–649: both components declare `CDLA-Permissive-2.0`; each README describes the data as CCADB-derived; each has `external_ccadb_terms_not_saved`. The retained LICENSE span for both versions, SHA-256 `e271993808fec50ab29350b39539cdec611a9103f827e0aa26d61da70e2d33f8`, is paraphrased as follows: §2.1 — when sharing Data, make the agreement text available with the Data; §3.1 — the agreement imposes no restrictions/obligations on Results; §§5.1/5.4 define Data as material received under the agreement and Results as the outcome of computational analysis. The README's `derived work` wording does not automatically determine Data/Results classification. The retained materials ledger still has 2 `external_ccadb_terms_not_saved` blockers; the supplemental capture does not change them. Applicability, acquisition history, third-party rights, sufficiency/obligations and legal approval remain open.

For the two usage texts, separate current.pin/historical.pin records were written in messages 110/112 before semantic views 116/118. For site-domain.raw, the ordering was violated: view106 preceded pin114. Therefore, directory b as a whole cannot be declared pin-before-read compliant; the earlier provenance.md:14–19 contains a withdrawn generalization and is retained unchanged as history.



History A: semantic views 65/67 preceded pins 79; later pins do not remedy the violation. In the new LLVM session 07be1fbd…, raw output without a pin occurred in messages 25/26; the subsequent capture does not remedy this. Calls to gh --jq without loading the skill, and malformed calls, are retained as procedural errors. The new LLVM capture was initially created by mistake under docs/.../materials/llvm-primary-20261030-c, then moved without overwriting to target/llvm-primary-20261030-c; seven entries were restored. The exact history is retained in target/llvm-primary-20261030-c/provenance.md:15–21.


Denial of the command `curl -L --max-filesize 262144 -D - https://www.ccadb.org/rootstores/usage`: the tool returned `ERROR command is not allowed for security reasons` in session 07be1fbd… (messages 27/28). There was no bypass; the current official raw capture remains absent.

## History

The unsafe incident in the parent session remains on record; legacy procedures were not run again. The two transcript reads without a pin (messages 63 and 66) and the `components.md` read without size/hash (transcript 340–341) remain facts. Additional procedural violations in child sessions are recorded: `643f705a…$$call_6fa515…`, messages 54/60 — `python -c` and `json.load(open(...))` without `-I` or a prior pin; `643f705a…$$call_a70cc…`, message 47 — the same; `9b84faab…$$call_78eaef…` — `python - <<EOF` and repeated direct JSON reads during span normalization. Later pinned outputs **do not absolve** these violations. Rejection `a` consumed budget; three wrappers were rejected; a console encoding error occurred during reading; output limit `g` was resolved by lossless deduplication; false NOTICE/branch counts `e` were corrected; the earlier claim of closed findings (translated from the Russian historical wording) has been withdrawn. Pinning before/after is now applied to new parses, but does **not** retroactively remedy past violations.


## Scope boundaries

Source distribution only; binary composition, native linkage and production provenance are outside scope. Seven vendor notices remain open. MPL/LGPL/CDLA/CCADB alternatives require human legal review. There is no allowlist/approval JSON. Legal approval is absent. #53 remains **PARTIAL**.

## Next steps

1. Obtain and assess the specific missing external texts and references listed above.
2. Submit the terms that were read — especially mixed terms, native/data-specific terms and alternatives — for human legal review.
3. Complete vendor attribution (seven vendors).
4. Only then consider closing individual items.
