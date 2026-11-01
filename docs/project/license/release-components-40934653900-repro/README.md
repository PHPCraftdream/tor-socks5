# Reproducing run 40934653900

The toolkit consists of four scripts in this directory: `analyze-safe.py`, `verify-safe-binaries.py`, `inspect-primary.py`, `prove-source-bytes.py`. Treat this directory as trusted: three scripts explicitly load the adjacent `analyze-safe.py`, but do not import project code. Run Python in isolated mode with `-I`; do not execute archives or their contents. The retained runs of the first three scripts exited with code 0; after the Darwin format correction, the final binary-analysis rerun reports the IOKit, CoreFoundation and SystemConfiguration frameworks, not `Versions`. Two source-proof runs also exited with code 0; see [source proof](source-proof.md) for details and the [report](../release-components-40934653900.md) for the overall status.

Final script SHA-256 hashes:
- `analyze-safe.py`: `e02523826493e5816d644bf77d802917bb7773b5d01c158ccb06227af8f43a43`.
- `inspect-primary.py`: `f39b64ebe4c36f4d641c8c9d55c4c2f55a86cad555d08086fa6ca5351a151fa6`.
- `verify-safe-binaries.py`: `8241b9a49ec1d70843e1d344a125f4d821662da86b27e4b76ff27cd45cffeb0a`.
- `prove-source-bytes.py`: `967e9b1bc21c98934523ec00cf2403fe5b92b11035037a929224ed66bf481624`.

Run all commands below from this directory in Bash (Git Bash on Windows), except for the explicitly identified source-proof command run from the worktree root; the paths contain four `..` components. Local analysis requires a trusted Python 3.12 installation; retrieving artifacts additionally requires `gh`, prior authentication and access to the artifacts. Ensure that `../../../../target` exists, has no links/reparse points anywhere in its path chain, and is not being modified concurrently. The scripts do not protect against races. Do not overwrite or delete previous evidence or outputs.

## Authenticated retrieval of eight ZIP files

If the retained inputs are available, you can use `../../../../target/stage1-data-20261029/candidate.zip` and that directory's binary ZIP files read-only. Otherwise, create a **new empty** directory directly inside target; the command fails if the name is already taken:

```sh
python -I -c "import os; os.mkdir('../../../../target/repro-saved-inputs')"
```

In the following command, each group of four arguments specifies an artifact ID, output filename, expected size and SHA-256. Python invokes `gh api repos/PHPCraftdream/tor-socks5/actions/artifacts/ID/zip`, directing binary stdout straight to a file opened exclusively (`xb`), then checks the size and hash by streaming the file. Only `gh` makes network requests; Python does not import networking code. The example's `exec` executes only the explicitly supplied trusted program literal, never artifact contents. On an error or mismatch, stop and retain the incomplete file as evidence; choose a new directory for a retry rather than overwriting it. Check the metadata against the authenticated API; byte verification does not establish production origin.

```sh
python -I -c "import sys,subprocess,hashlib,os; a=sys.argv[1:]; assert len(a)%4==0; exec('for i in range(0,len(a),4):\n id,p,n,w=a[i:i+4]\n with open(p,\"xb\") as f: subprocess.run([\"gh\",\"api\",\"repos/PHPCraftdream/tor-socks5/actions/artifacts/\"+id+\"/zip\"],stdout=f,check=True)\n h=hashlib.sha256()\n with open(p,\"rb\") as f:\n  for b in iter(lambda:f.read(1048576),b\"\"): h.update(b)\n if os.path.getsize(p)!=int(n) or h.hexdigest()!=w: raise ValueError(\"size/hash mismatch: \"+p)\n print(id,\"verified\")')" 12932028389 ../../../../target/repro-saved-inputs/candidate.zip 853866809 75a58bb9393525b64f083105113771680bb561e1ff2f28f337fa584954b847d4 12931773573 ../../../../target/repro-saved-inputs/binary-12931773573.zip 12126824 bcf0edb870c0dfeb1ec71bf6262328885226ae489ddd81a6493277bde63b78f8 12930598391 ../../../../target/repro-saved-inputs/binary-12930598391.zip 12678740 351d145d890ee0d8a7de555af7a2e176c693c5a621636ba0a669e571cb7af8fd 12929435820 ../../../../target/repro-saved-inputs/binary-12929435820.zip 12747241 807a36536fc8c7558829dc3c1ba89a6f22579307c6a3a8e0e0d34cf76531b393 12927756356 ../../../../target/repro-saved-inputs/binary-12927756356.zip 12982288 46861aea32f692039d5d5ce4286265a15c1adcf3244e2e8b4de0a8c78bbc9025 12926432069 ../../../../target/repro-saved-inputs/binary-12926432069.zip 13007952 8d6909f2f42b902bdced58f91cd1a96559da5a0ed08b31f1835e88657d35803c 12925166590 ../../../../target/repro-saved-inputs/binary-12925166590.zip 13223590 fd759bd0516de84edb2b3599fc3389d8240947fa228d10a27913ad4bc6506d87 12924449353 ../../../../target/repro-saved-inputs/binary-12924449353.zip 13473713 bc92c80fa638e9ef5f1fe77b6f7dfcadc8f2b16ec5bc4a6e2777685cda2f4c44
```

The report's table maps IDs to targets and provides artifact API links; the retained artifact is not downloaded.

## Observed runs

The exact arguments and already occupied outputs of the observed runs are recorded below; **do not rerun using these names**:

```sh
python -I analyze-safe.py --candidate ../../../../target/stage1-data-20261029/candidate.zip --target-root ../../../../target --output ../../../../target/repro-saved-inventory-20261029-d
python -I verify-safe-binaries.py --candidate ../../../../target/stage1-data-20261029/candidate.zip --binary-dir ../../../../target/stage1-data-20261029 --target-root ../../../../target --output ../../../../target/repro-saved-binaries-20261029-c
python -I inspect-primary.py --candidate ../../../../target/stage1-data-20261029/candidate.zip --target-root ../../../../target --output ../../../../target/repro-saved-primary-20261029-c
```

All exited with code 0: `inventory.json` — 824 outer, 2642 nested, 736 components, 743 blockers; `primary.json` — 13 crates, 12 project/SDK files selected as candidates by filename (6 `LICENSE-*` and 6 workflow/analysis files, not primary licenses), 10 CCADB rows; `summary.json` — seven receipt matches, all true, with graph counts as stated in the report.

The field name `project_sdk_license_files` is historical: it contains results from a broad filename filter, not a classification of primary license texts. A workflow, analysis document or script appearing in this list does not establish a license obligation or increase the number of primary licenses reviewed.

## Materials from all registry archives

The subsequent [materials toolkit and report](materials/README.md) covers 727 registry archives and 1212 retained license copies. Parent's p/q recomputations matched byte for byte; source distribution and substantive records are kept distinct from filename candidates, keyword scans and legal approval. Full pins, exact missing/external blockers and the history of procedural violations are retained alongside them. This does not turn the earlier sample of 13 into a claim of a complete per-file/native/linkage audit.

## Source proof from the worktree root

For the retained candidate, without network access, using a new, unused output directly under `target`:

```sh
python -I docs/project/license/release-components-40934653900-repro/prove-source-bytes.py --candidate target/stage1-data-20261029/candidate.zip --target-root target --output target/source-proof-fresh
```

The two observed outputs `target/source-proof-20261030-a` and `target/source-proof-20261030-b` are already occupied; do not reuse them. Anchors, counts, digests, limitations and the exact trust boundary are documented in [source proof](source-proof.md); `PASS_DATA_ONLY` does not establish production authority or legal review.

## Bounded analysis: fresh outputs

The examples use the old inputs read-only; for new inputs, change both input paths to `repro-saved-inputs`. Each output must be a new directory under target; in the examples it is a direct child. The scripts create it exclusively and reject an existing name or a link/reparse point in the checked path chain. For a rerun, including after an error, choose different names that do not exist; outputs are retained.

```sh
python -I analyze-safe.py --candidate ../../../../target/stage1-data-20261029/candidate.zip --target-root ../../../../target --output ../../../../target/repro-saved-inventory
python -I verify-safe-binaries.py --candidate ../../../../target/stage1-data-20261029/candidate.zip --binary-dir ../../../../target/stage1-data-20261029 --target-root ../../../../target --output ../../../../target/repro-saved-binaries
python -I inspect-primary.py --candidate ../../../../target/stage1-data-20261029/candidate.zip --target-root ../../../../target --output ../../../../target/repro-saved-primary
```

Checks cover pinned sizes and hashes, member names and types, and streaming budgets. The manual TAR parser checks header checksums, types and padding; JSON is limited to depth 64 before `json.loads`. Selected data is limited to 150 MB in total; the approximately 600 MB peak memory figure is an estimate, not a hard RSS limit. Data is neither extracted nor executed; this is not a general-purpose archive validator, a full legal review, or confirmation of composition and production authority.

The first new analyzer run rejected the virtual PAX marker `././@PaxHeader`; the new primary runs a/b rejected a GNU longname `L` of size 102 in OpenSSL. Only the exact PAX metadata marker is supported; GNU `L` is limited to 513 bytes, a single trailing NUL and path validation. `K`, links and sparse entries are rejected; the general type and path checks have not been weakened. Failed outputs a/b are retained as evidence. See the report for the history of the initial unsafe handling; do not run the legacy scripts again.
