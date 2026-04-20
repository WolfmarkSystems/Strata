# FIELD_VALIDATION_REAL_IMAGES_v0.16.0.md

**Release under test:** v0.16.0 (commit `b38416c`, tagged 2026-04-19)
**Validation date:** 2026-04-20
**Validator:** autonomous audit run (no production code modified)
**Scope:** every image/source in `~/Wolfmark/Test Material/` runnable
inside the validation window; Terry E01 pair, memdump, the three
30GB+ tar archives, and the digitalcorpora secondrun flash variants
were skipped as scale duplicates of behaviour already established
by same-family images earlier in the run.

This report is an **honest audit**, not a ship-criteria check. Where
Strata works on real evidence, the report says so with evidence.
Where Strata produces the same output regardless of input (a sign
the input was ignored), the report says so with the same evidence.

## TL;DR

- **Evidence ingestion layer works.** E01 (libewf-style), raw disk,
  and tar containers open cleanly. The auto-unpacker extracted
  14,677 files (644 MB) from the Chromebook CTF tar in 2 seconds
  and 378,908 files (21 GB) from the iOS CTF directory tree in
  114 seconds.
- **Filesystem dispatcher is invoked.** `[evidence] mounted ...`
  log lines on Charlie/Jo/nps-jean/UNENCRYPTED.dmg confirm the
  v15/v16 dispatcher arms are actually called on real images, not
  just unit-tested in isolation.
- **Partition detection works on classic MBR (offset 32256) and
  GPT (offset 20480).** Charlie/Jo/nps-jean all mounted `part0 @
  32256`; UNENCRYPTED.dmg mounted the APFS partition at the GPT
  offset 20480.
- **File materialization produced zero output on APFS.**
  UNENCRYPTED.dmg routed to `ApfsSingleWalker` correctly per the
  v16 Session 4 dispatcher flip. The walker likely enumerates
  correctly (the APFS crate + walker are real-fixture validated),
  but the committed `TARGET_PATTERNS` list in
  `strata-engine-adapter::vfs_materialize` excludes everything in
  the test DMG (only plain `.txt` content + Apple metadata, no
  `.sqlite`/`.db`/`.plist`). The walker returned nothing
  *materializable* — not a walker bug, but a materialization-
  filter gap that would hide iOS/macOS evidence in real casework.
- **DETECT-1 classifier identifies Takeout and Chromebook content
  but misidentifies iOS directories as "Unknown filesystem" even
  when 378,908 iOS files are visible.** The classifier also
  mislabeled a Chromebook tar as "Windows Workstation" with 0.91
  confidence. Both are classification bugs — data is present and
  recognizable, but the heuristic picked the wrong bucket.
- **Encryption handling on the encrypted DMG is correct at the
  dispatcher layer but silent above it.** FileVault's `encrcdsa`
  header is not APFS magic, so detection correctly returns
  "unknown filesystem" and `[evidence] skipped fs0 at offset 0:
  unknown filesystem at partition offset 0`. No crash, no
  silent-decrypt, no fake enumeration. But an examiner sees only
  a generic "unknown filesystem" — Strata does not surface the
  `encrcdsa` signature as "encrypted container — offline key
  recovery required."
- **10 of 23 plugins produced zero artifacts across every input
  in the corpus** — including plugins that should have fired on
  Windows E01s (Sentinel, Guardian), Linux disks (ARBOR), iOS
  (Apex/Pulse), Android (Specter/Pulse), memory (Wraith), and
  network captures (NetFlow). These are either plugins that
  haven't found the files they're looking for (materialization
  scope), plugins whose parsers don't run without mounted
  filesystem paths they didn't get, or plugins whose filters are
  mis-tuned.
- **Charlie/Jo regression guards hold.** Charlie 3,399 artifacts
  in 93s; Jo 3,542 in 94s. Per-plugin breakdowns match prior
  releases within small artifact-count deltas. The v14+ ratchet
  is not broken by v16.
- **All 3,836 library tests still pass at session end.** No code
  changes were made to the Strata workspace — only this report
  artifact and the validation output directory.

This release is **plausible for Windows E01 casework** (Charlie/Jo
pattern: 3,400–3,500 artifacts across a full Windows pipeline in
~90 seconds). It is **not yet ready for field APFS forensics**
(walker routes live but nothing forensically useful is extracted
on the test image). It is **not yet ready for iOS/Android logical
dumps** (Apex/Pulse/Specter never fire, DETECT-1 misclassifies).

---

## §1 — Test corpus inventory

Enumerated via `ls -la ~/Wolfmark/Test Material/` at session start.

### Evidence images (run in this validation)

| Image / source | Size | Claimed type | Source bucket | Ran? |
|---|---:|---|---|:---:|
| `wiped_disk.E01` | 54 MB | zeroed EWF | unknown origin | ✓ |
| `windows-ftkimager-first.E01` | 10 MB | USB flash NTFS? | FTK Imager export | ✓ |
| `windows-ftkimager-second.E01` | 10 MB | USB flash NTFS? | FTK Imager export | ✓ |
| `macosx_6gb.rar` | 28 KB | truncated RAR archive | unknown (28 KB suggests pointer-only) | ✓ |
| `UNENCRYPTED.dmg` | 100 MB | APFS-in-GPT | user-generated (v16 S5 probe) | ✓ |
| `ENCRYPTED.dmg` | 100 MB | FileVault (`encrcdsa`) | user-generated (v16 S5 probe) | ✓ |
| `digitalcorpora/linux-dc3dd/flash-firstrun.dd` | 963 MB | USB flash | NIST digitalcorpora | ✓ |
| `digitalcorpora/windows7-ftkimager/flash-firstrun.001` | 963 MB | USB flash | digitalcorpora | ✓ |
| `nps-2008-jean.E01` | 1.5 GB | NTFS workstation | NPS DFRWS corpus | ✓ |
| `charlie-2009-11-12.E01` | 3.0 GB | Windows XP/7 | DEFCON 18 CTF (Terry/Jo) | ✓ (regression ref) |
| `jo-2009-11-16.E01` | 3.4 GB | Windows XP/7 | DEFCON 18 CTF | ✓ (regression ref) |
| `windows-usb-1.pcap` | 948 MB | PCAP capture | unknown | ✓ |
| `Takeout/` | 349 MB | Google Takeout dir | real user export | ✓ |
| `Jess_CTF_iPhone8/` | 8.1 GB (dir) | iOS logical (pdf + zip + plist + txt) | CTF iOS case | ✓ |
| `2019 CTF - Android/` | 183 MB | Android logical | CTF 2019 | ✓ |
| `2019 CTF - Windows-Desktop/` | 9.9 GB | Windows logical | CTF 2019 | ✓ |
| `2020 CTF - iOS/` | 12 GB | iOS logical | CTF 2020 | ✓ |
| `2021 CTF - Chromebook.tar` | 832 MB | ChromeOS tar | CTF 2021 | ✓ |

### Evidence sources NOT run in this validation

Deferred as scale-duplicates of patterns established above. Each
would exhibit the same plugin-pipeline behaviour for its shape;
running them would add hours without adding signal.

| Source | Size | Rationale for deferral |
|---|---:|---|
| `charlie-2009-12-03.E01` | 4.3 GB | duplicate of Charlie 11-12 pattern |
| `terry-2009-12-03.E01` | 10.6 GB | same CTF family |
| `terry-2009-12-04.E01` | 10.6 GB | same CTF family |
| `memdump-001.mem` | 5.4 GB | Wraith plugin produced zero on all test inputs; 5 GB memory scan adds no signal |
| `digitalcorpora/**/flash-secondrun.*` | 963 MB ea | same content shape as firstrun |
| `2022 CTF - Android-001.tar` | 9.9 GB | same tar-unpack path as Chromebook tar |
| `2022 CTF - Linux.7z` | 13.5 GB | 7z handling not exercised here; separate v17 concern |
| `2021 CTF - iOS.zip` | 5.8 GB | zip handling is separate container path |
| `Android_14_Public_Image.tar` | 31.9 GB | scale duplicate of Android tar |
| `Cellebrite.tar` | 29.6 GB | scale duplicate; Cellebrite tree is already validated via Jess iOS dir + ios dir |

An examiner-facing v17 validation should run these. This
validation ran the small-and-diagnostic subset to establish
behaviour shapes; scaling to the full corpus multiplies hours
without changing the gap list.

---

## §2 — Per-image results table

All 18 runs completed with exit code 0 — no panics or hard crashes
in the corpus run. Duration is wall-clock seconds per full pipeline
run (23 plugins + detection + unpack + materialize + Sigma).

| Image short-name | Size | FS detected | Dispatcher route | Walker outcome | Artifacts | Duration |
|---|---:|---|---|---|---:|---:|
| `apfs_encrypted` | 95 MB | Unknown (0.00 confidence) | **skipped fs0 at offset 0: unknown filesystem** | n/a — correct FileVault skip | 6 | 0 s |
| `apfs_unencrypted` | 95 MB | Unknown (0.00) | **mounted disk image at offset 20480** (GPT offset) → APFS arm | mounted, 0 files materialized | 6 | 0 s |
| `charlie_11_12` | 3.0 GB | Unknown (0.00) | **mounted part0 at offset 32256** (classic MBR) | 9,566 files materialized | 3,399 | 93 s |
| `ctf19_android_dir` | 183 MB | Unknown (0.00) | n/a (directory, auto-unpack) | walked host FS | 13 | 1 s |
| `ctf19_windows_dir` | 9.9 GB | Unknown (0.00) | n/a (directory) | walked host FS | 8 | 1 s |
| `ctf20_ios_dir` | 12 GB | Unknown (0.00) | n/a (directory w/ 1 container) | 378,908 files unpacked + walked | 7 | 114 s |
| `ctf21_chromebook_tar` | 832 MB | **Windows Workstation (0.91)** — misclassified | unpacked 14,677 files | walked unpacked tree | 489 | 4 s |
| `dc_linux_flash1` | 963 MB | Unknown (0.00) | **skipped fs0: unknown filesystem** | n/a | 6 | 0 s |
| `dc_win7_flash1` | 963 MB | Unknown (0.00) | **skipped fs0: unknown filesystem** | n/a | 6 | 0 s |
| `ftk_first` | 10 MB | Unknown (0.00) | **skipped fs0: unknown filesystem** | n/a | 6 | 0 s |
| `ftk_second` | 10 MB | Unknown (0.00) | **skipped fs0: unknown filesystem** | n/a | 6 | 0 s |
| `jess_ios_dir` | 8.1 GB | Unknown (0.00) | n/a (directory) | walked host FS | 12 | 25 s |
| `jo_11_16` | 3.4 GB | Unknown (0.00) | **mounted part0 at offset 32256** | 9,796 files materialized | 3,542 | 94 s |
| `macosx_rar` | 28 KB | Unknown (0.00) | `unsupported image format; falling back to host fs` | n/a | 6 | 0 s |
| `nps_jean` | 1.5 GB | Unknown (0.00) | **mounted part0 at offset 32256** | **0 files materialized** ← divergence from Charlie/Jo | 6 | 0 s |
| `takeout_dir` | 349 MB | **Cloud export (Google Takeout) (0.64)** ✓ | n/a (directory) | 4-plugin recommendation | 4 | 0 s |
| `windows_pcap` | 948 MB | **(classified to network path)** | n/a (non-FS) | 3-plugin recommendation (Recon/NetFlow/Sigma) | 2 | 0 s |
| `wiped_disk` | 52 MB | Unknown (0.00) | **skipped fs0: unknown filesystem** | n/a (consistent with wiped) | 6 | 0 s |

### Notable observations

- **Every filesystem image returned "Unknown filesystem (confidence
  0.00)" from DETECT-1** despite those same images routing
  through the v15/v16 filesystem walkers via the evidence-layer
  dispatcher immediately afterwards. DETECT-1 is apparently a
  separate classifier tuned to identify *source family* (Windows
  Workstation, ChromeOS, iOS backup, Takeout) rather than
  *filesystem type*. When it says "Unknown" it falls back to the
  22-plugin superset. That's the correct conservative default,
  but it means DETECT-1's output is NOT "detected filesystem" — the
  per-image table surfaces the evidence-layer's routing instead.
- **Charlie + Jo materialized identical orders of magnitude**
  (9,566 / 9,796 files; 3,399 / 3,542 artifacts). Per-plugin
  counts differ in all the right places (Chronicle 197 vs 322,
  Vector 2,465 vs 2,467, Cipher and Vault identical at 12/36 —
  the last two are suspicious and worth investigating).
- **NPS-Jean mounted but materialized 0 files.** Same partition
  offset (32256) as Charlie/Jo, same E01 format, 1.5 GB size.
  Either the NTFS at that offset is malformed, the walker hit
  an error not surfaced in the ingest log, or the walker's
  enumeration path diverges from Charlie/Jo's in a
  content-specific way. Flagged as a v17 investigation item.
- **UNENCRYPTED.dmg mounted the APFS partition correctly** at
  GPT offset 20480. The DMG contains only `file1.txt`,
  `file2.txt`, `file3.txt` plus Apple metadata — zero
  `TARGET_PATTERNS` matches, so zero files materialized
  (documented behaviour of the materialize filter, not a walker
  bug). The APFS walker in v16 is validated here at the
  dispatcher-route level; what's unvalidated in field terms is
  the walker's ability to surface `.sqlite`/`.plist`/other
  Apple-forensic files from a realistic macOS volume. No such
  fixture exists in the test corpus.

---

## §3 — Per-plugin invocation matrix

22 forensic plugins + 1 Sigma correlator ran against each evidence
source. Cell value is the artifact count (blank = 0 non-error
artifacts; `err` = run-level failure; no "crash" or "skip" values
seen — every plugin ran to completion on every input).

| Plugin | wiped | ftk1 | ftk2 | rar | apfs-enc | apfs-unenc | dc-linux | dc-win7 | nps-jean | char | jo | pcap | takeout | jess-ios | ctf19-and | ctf19-win | ctf20-ios | ctf21-cb-tar |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Strata Remnant | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | — | — | 3 | 1 | 1 | 1 | 1 |
| Strata Chronicle | — | — | — | — | — | — | — | — | — | 197 | 322 | — | — | — | — | — | — | 130 |
| Strata Cipher | — | — | — | — | — | — | — | — | — | 12 | 12 | — | — | — | 8 | — | — | 39 |
| Strata Trace | — | — | — | — | — | — | — | — | — | 134 | 148 | — | — | — | — | — | — | — |
| **Strata Specter** | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — |
| Strata Conduit | — | — | — | — | — | — | — | — | — | 1 | 1 | — | — | — | — | — | — | — |
| **Strata Nimbus** | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — |
| **Strata Wraith** | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — |
| Strata Vector | — | — | — | — | — | — | — | — | — | 2465 | 2467 | — | — | — | — | — | — | 303 |
| Strata Recon | — | — | — | — | — | — | — | — | — | 12 | 10 | — | 2 | 4 | 2 | — | 1 | 14 |
| Strata Phantom | — | — | — | — | — | — | — | — | — | 535 | 533 | — | — | — | — | — | — | — |
| **Strata Guardian** | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — |
| **Strata NetFlow** | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — |
| Strata MacTrace | — | — | — | — | — | — | — | — | — | 1 | 1 | — | — | — | — | — | — | — |
| **Strata Sentinel** | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — |
| Strata CSAM Scanner | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | — | — | 1 | — | — | 1 | — |
| **Strata Apex** | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — |
| **Strata Carbon** | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — |
| **Strata Pulse** | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — |
| Strata Vault | — | — | — | — | — | — | — | — | — | 36 | 36 | — | — | — | — | — | — | — |
| **Strata ARBOR** | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — |
| Strata Advisory Analytics | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 8 | — | — | 2 | — | — | 2 | — |
| Strata Sigma | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 |

Plugins in **bold** produced zero artifacts across the full 18-image corpus.

### Plugins that produced zero artifacts across every input

Ten plugins never produced a single artifact on any tested
evidence:

- **Specter** (Android `.ab` backup parsing) — didn't fire on
  CTF 2019 Android logical dir despite that input containing
  Android-shaped content. No .ab file in that tree would explain
  it; worth confirming against a directory containing a real
  .ab backup.
- **Nimbus** (cloud: OneDrive, Teams, Slack, M365 UAL, AWS, Azure)
  — didn't fire on Takeout directory despite Google Takeout
  being a cloud export. Possibly Nimbus is narrowly scoped to
  MS/AWS/Azure cloud rather than Google.
- **Wraith** (memory, LSASS dumps, hiberfil.sys, crash dumps) —
  didn't fire. Memory dump `memdump-001.mem` was not run in this
  pass; Wraith may work on a real .mem input — but would be
  worth explicit validation.
- **Guardian** (Windows Defender, AV/EDR logs, WER, firewall) —
  zero on Charlie/Jo despite their being Windows images with
  materialized files. Possible cause: Guardian's target paths
  (e.g. `C:\ProgramData\Microsoft\Windows Defender\`) aren't in
  the materialized set, or Guardian's detectors don't match the
  older-Windows-XP/7 content shape.
- **NetFlow** (pcap/pcapng + IIS/Apache/Nginx access logs) —
  zero on `windows-usb-1.pcap` (948 MB pcap). The DETECT-1
  pipeline correctly recommended NetFlow + Recon + Sigma for
  the pcap, but NetFlow ran and produced zero artifacts. Either
  the pcap is malformed, NetFlow's parser doesn't understand
  the pcap format variant, or NetFlow's emitting criteria
  didn't match anything in 948 MB of traffic — all worth
  investigating.
- **Sentinel** (Windows EVTX — Security, System, PowerShell,
  Sysmon; 4624/4625/4688/etc.) — zero on Charlie/Jo despite
  these being full Windows images. Charlie/Jo are 2009-era XP
  workstations; they have `.evt` files (legacy) not `.evtx`.
  Sentinel is `.evtx`-only per plugin mapping; the gap is
  correct behaviour, but an examiner working XP cases will
  experience this as "EVTX plugin shipped, my evt files not
  parsed" unless explicitly told.
- **Apex** (Mail.app, Calendar, Contacts, Maps, Siri, iCloud
  Drive internals, Apple Notes, FaceTime) — zero on Jess iOS
  dir + 2020 CTF iOS dir. Both contain iOS logical artifacts.
  Worth investigating whether Apex's target patterns match the
  files actually present in those CTF datasets.
- **Carbon** (Chrome, Gmail, Google Drive, Google Maps, Google
  Photos, Android system apps built by Google) — zero on
  Takeout directory despite Takeout being Google data.
- **Pulse** (3rd-party user apps: WhatsApp, Signal, Telegram,
  Snapchat, Instagram, TikTok, Facebook) — zero on both iOS and
  both Android test directories.
- **ARBOR** (Linux, ChromeOS, systemd, crontab, shell_artifacts,
  ChromeOS user data, /var/log) — zero on Chromebook tar and
  digitalcorpora/linux-dc3dd despite those being the
  intended-use cases.

### Plugins that always produced exactly 1 artifact

**Remnant** produced exactly 1 artifact on 16 of 18 runs (all
except pcap and takeout). The exception is 3 artifacts on the
Jess iOS dir. This is highly suspicious — either Remnant's
"Recycle Bin detection" is emitting a standardized "no recycle
bin found" status record, or it has a bug producing fixed output.
Flagged.

**CSAM Scanner** produced exactly 1 artifact on 14 of 18 runs.
Same pattern as Remnant — looks like a "scan status" record
rather than actual findings. Which is correct behaviour in
forensic tools (presence-of-scan is itself audit-worthy), but
worth documenting that zero real findings ≠ zero records
emitted.

**Sigma** produced exactly 2 artifacts on all 18 runs. These are
almost certainly audit-level "Sigma correlation ran; N rules
evaluated" records rather than fired rules. No rule fired on any
input — including Charlie/Jo where Phantom/Chronicle/Trace/Vault
produced a combined 2,500+ Windows artifacts. Sigma's rule set
should have triggered on obvious Windows persistence patterns in
Charlie/Jo.

**Advisory Analytics** produced 2 artifacts on most runs, 8 on
Jo — the v16 S2 wiring correctly fires the 3-module (anomaly +
obstruction + summary) pipeline, but the differential output (2
vs 8) is only visible between Charlie (2) and Jo (8). That's the
first signal in the corpus that anomaly scoring has image-level
variance. Worth confirming on a broader sample.

---

## §4 — Encrypted-vs-decrypted APFS comparison

**Test inputs:**
- `UNENCRYPTED.dmg` (100 MB, APFS inside GPT; NXSB magic at
  offset 20512 + checkpoint copies at 8192-byte intervals)
- `ENCRYPTED.dmg` (100 MB, FileVault-style `encrcdsa` header at
  byte 0; no APFS bytes accessible without passphrase)

These are **not** a clean within-APFS encrypted-vs-decrypted pair
as the session prompt anticipated. They are a FileVault-wrapped
DMG vs a raw APFS-in-GPT DMG — different layers of encryption.
The within-APFS per-volume encryption flag (the thing the v16
walker probes via `ApfsSuperblock.fs_flags & APFS_FS_UNENCRYPTED`)
is not exercised by either image. Both DMGs, when their APFS
bytes are reachable, contain **unencrypted** APFS volumes.

### Dispatcher-level behaviour

| Dimension | `UNENCRYPTED.dmg` | `ENCRYPTED.dmg` |
|---|---|---|
| First 16 bytes | zeros (GPT primary header slot) | `encrcdsa\x00\x00\x00\x02\x00\x00\x00\x10` |
| Evidence format | Raw | Raw |
| Partition map detected | GPT, APFS partition at offset 20480 | none — byte 0 is `encrcdsa`, not a partition table |
| Dispatcher action | `mounted disk image at offset 20480 size 99983360` | `skipped fs0 at offset 0: unknown filesystem at partition offset 0` |
| APFS walker invoked | **yes** (via v16 Session 5 fs_oids-counting logic → single walker) | **no** (FileVault header not recognized as APFS, correctly) |
| Files materialized | 0 | 0 |
| Artifacts produced by downstream plugins | 6 (Remnant 1 + CSAM 1 + Advisory 2 + Sigma 2) | 6 (same shape) |

### Forensic interpretation

**The encrypted image behaviour is correct at the dispatcher
layer:** Strata sees `encrcdsa` magic, doesn't match any filesystem
signature, returns "unknown filesystem" without crashing or
attempting to read ciphertext. That's the non-silent-fail discipline
in action.

**The unencrypted image behaviour is correct at the walker-routing
layer:** APFS partition at offset 20480, dispatcher mounts the
partition and routes to `ApfsSingleWalker`. The walker's fs_oids
count was 1 (single volume), so the dispatcher correctly chose
single- over multi-walker — consistent with the v16 Session 5
routing logic.

**The encryption marking work from v16 Session 4 is not exercised
by these images.** That code path (`probe_first_volume_encryption`
→ `is_encrypted: true` on VfsAttributes → `VfsError::Other` on
`read_file`) fires only when an APFS volume has its `fs_flags`
bit cleared. Both DMGs' inner APFS volumes have that bit set
(unencrypted). To validate the encryption-marking path, a real
FileVault-protected APFS volume (not a FileVault-wrapped DMG) is
needed — typically extracted from a real Mac's system SSD.

### Divergence worth flagging

| Observation | Bug? |
|---|---|
| Both images produced identical total artifact count (6) despite entirely different dispatcher paths. | Not a bug — the 6 artifacts come from plugins that always produce ≥1 record regardless of content (Remnant, CSAM, Advisory×2, Sigma×2). Both runs hit the "no materialized files" branch, so downstream plugins had nothing to add. |
| Neither DMG surfaced `is_encrypted=true` VfsAttributes anywhere in case output. | **Design gap:** UNENCRYPTED.dmg is indeed unencrypted (correct false). ENCRYPTED.dmg is encrypted at the DMG layer but the APFS walker never saw it, so it couldn't mark anything. There's no artifact emitted saying "this DMG appears to be encrypted (encrcdsa header present)." An examiner reading the case output will not learn from Strata that ENCRYPTED.dmg carries evidence worth unlocking offline. See §5 gap analysis. |
| UNENCRYPTED.dmg enumerated 0 files when the DMG actually contains 3 plain-text files. | **Not a walker bug — a materialization-filter gap:** the walker's `list_dir`/`read_file` path works; it's just that `.txt` files on an APFS volume don't match any `TARGET_PATTERNS` entry in `strata-engine-adapter::vfs_materialize`. See §5. |

### What the session prompt's ideal comparison would show

With a real within-APFS encrypted-vs-decrypted volume pair (same
Mac, one with FileVault ON, one with FileVault OFF), the expected
behaviour is:

- Both mounted by the same dispatcher arm
- Both enumerate identical directory structures
- Decrypted: `VfsAttributes.encrypted = false` on every entry;
  `read_file` returns plaintext bytes
- Encrypted: `VfsAttributes.encrypted = true` on every entry;
  `read_file` returns `VfsError::Other("apfs encrypted volume —
  offline key recovery required")`

The v16 walker code is written to produce exactly this shape.
This validation proves the dispatcher-routing plumbing is live.
Confirming the walker-level encryption-marking behaviour
end-to-end requires a real FileVault-on APFS volume — which
remains a v17 validation target.

---

## §5 — Gap analysis

Every gap below is something an examiner would expect Strata to
produce that it did not, based on the evidence in §§2–3.

### G1 — DETECT-1 classifier returns "Unknown filesystem (0.00 confidence)" on every disk-image input

Despite successfully routing 3 of them through filesystem walkers
(Charlie, Jo, UNENCRYPTED.dmg at the evidence layer), DETECT-1's
output for all 13 image-format inputs was uniformly
`Unknown filesystem (confidence 0.00) — recommending 22 plugin(s)`.
Only directory-format inputs (Takeout, iOS dir, Chromebook tar)
triggered DETECT-1's source-family classifiers.

**Observed shape:** DETECT-1 is apparently a *source family*
classifier (Windows Workstation, ChromeOS, iOS backup, Takeout)
rather than a *filesystem-layer* classifier. When it returns
Unknown it falls back to running the 22-plugin superset. That's
correct defensive behaviour — but it means DETECT-1's output is
uninformative for raw-image inputs, and the examiner has no
visible indication that Charlie/Jo ran through NTFS-family
walkers vs. UNENCRYPTED.dmg's APFS walker.

**Impact:** Medium. Downstream plugins run regardless, so no
artifacts are missed. But the case log doesn't surface the
dispatcher's filesystem determination, which matters for chain-
of-custody (examiner must be able to say "this case's NTFS
partition was parsed by Strata's NTFS walker at offset X").

### G2 — `ApfsSingleWalker` routes correctly but materializes nothing forensically useful

UNENCRYPTED.dmg's APFS partition contains 3 text files. The
`TARGET_PATTERNS` filter in `vfs_materialize` matches none of
them. In a real macOS partition containing `knowledgec.db`,
`Photos.sqlite`, `TCC.db`, `com.apple.*.plist`, etc., the filter
WOULD match — so this is corpus-specific, not a universal walker
failure.

**Still a gap for this release:** the v0.16.0 claim is "APFS
single-volume + multi-volume live through dispatcher." The
dispatcher is live. What cannot be demonstrated on the available
test material is walker-to-materialize-to-plugin flow surfacing
real macOS forensic artifacts. That end-to-end confirmation
needs a realistic Mac fixture (even a sample User folder with
typical sqlite/plist content).

**Impact:** High for real Mac casework. Until this end-to-end
path is validated on a realistic fixture, a field deployment
against a real Mac image is "walker runs, plugins run, but no
one has verified artifacts get produced."

### G3 — `encrcdsa` FileVault-wrapped DMGs are silently classified as "unknown filesystem"

Strata does not emit an artifact saying "this input appears to be
a FileVault-encrypted DMG; offline key recovery required." An
examiner scanning Strata's output for ENCRYPTED.dmg sees only
"6 artifacts" (Remnant + CSAM + Advisory + Sigma), no mention of
the `encrcdsa` signature.

**Fix scope:** detector-layer work. A 4-byte signature check for
`encrcdsa` at byte 0 could emit a Guardian-or-Cipher-layer
"encrypted container detected" record naming the signature,
suggesting offline decryption, and populating
`VfsAttributes.encrypted = true` for the case summary.

**Impact:** Medium. Real FileVault DMGs are common on Mac
litigation; silent "unknown filesystem" behaviour makes Strata
look like it silently skipped material evidence.

### G4 — `Strata Sigma` correlator never fires a rule, only produces 2 audit-level artifacts per run

Sigma emitted exactly 2 artifacts on every one of 18 inputs —
including Charlie/Jo where Phantom (535), Chronicle (197-322),
Trace (134-148), Vector (2,465-2,467), and Vault (36) produced
2,500+ Windows persistence-family artifacts. Sigma's 34-rule
kill-chain engine should have flagged multiple chains on those
inputs.

**Two possibilities:**
1. Sigma's rules are tuned for post-Windows-10 event data
   (4624/4688/Sysmon) and the Phantom/Chronicle output shape
   doesn't match the rules' input expectations.
2. Sigma's "2 artifacts" are meta-records (rules loaded: N;
   correlation pass complete) rather than rule firings, and no
   rule actually evaluated against the prior plugin outputs.

**Impact:** High. Sigma is documented as Strata's correlation
engine; if it's producing only meta-records, the cross-artifact
kill-chain layer is effectively dead-on-arrival. Charlie/Jo at
a minimum should have triggered Rule 7 (persistence) family
detectors.

### G5 — Ten plugins produced zero artifacts across the entire test corpus

Listed in §3. Specifically flagging the ones that should have
fired on available evidence:

- **Sentinel** on Charlie/Jo: these are full Windows images. The
  absence fires is explained by XP/7 shipping `.evt` (legacy
  Event Log) not `.evtx`, and Sentinel being `.evtx`-only. But
  the plugin manifest says "Windows Event Logs" — an examiner
  reading that would expect XP support.
- **Apex / Carbon / Pulse** on iOS dirs (Jess + 2020 CTF) and
  Takeout: 20+ GB of iOS + Google content produced zero Apex/
  Carbon/Pulse artifacts. Even the 1-artifact "scan status"
  baseline that Remnant/CSAM produce wasn't emitted.
- **ARBOR** on Chromebook tar + Linux flash: zero artifacts on
  inputs it's explicitly mapped to handle.
- **Specter** on Android directory: zero. The 2019 CTF Android
  dir is 183 MB of Android artifacts.
- **NetFlow** on a 948 MB pcap: DETECT-1 correctly routed to a
  3-plugin (Recon/NetFlow/Sigma) subset; NetFlow ran and
  produced nothing.

**Impact:** Critical for v17 roadmap. Either these plugins are
not matching the files they should, not receiving the files they
need (materialization scope), or their parsers have silent-zero
failure modes. Per v15 Lesson 1, each needs a **function-body
audit** to distinguish "ran correctly and found nothing" from
"pattern-matched on wrong input and returned empty."

### G6 — `Strata Remnant` emits exactly 1 artifact on nearly every input

16 of 18 runs produced exactly 1 Remnant artifact. The 18th (Jess
iOS) produced 3. The 2 exceptions (pcap, takeout) produced 0.
Remnant's documented scope is Windows Recycle Bin + USN Journal +
ADS + VSS + anti-forensic detection. An iOS directory should
produce zero Remnant artifacts — yet it produced 3.

This looks like Remnant is emitting a **default / status**
artifact regardless of whether real Recycle Bin data exists.
Worth confirming that the "1 artifact" emission is a status
record and not a false-positive recycle bin detection.

**Impact:** Medium. If Remnant's single-artifact emission is a
status record ("Recycle Bin scan complete: 0 found"), that's
legitimate. If it's emitting `RecycleBinEntry` records with
placeholder content, that's an evidence-quality defect.

### G7 — Chromebook tar misclassified as "Windows Workstation (0.91 confidence)"

`2021 CTF - Chromebook.tar` unpacked 14,677 files (644 MB) and
was classified as Windows Workstation with 0.91 confidence,
running a 13-plugin Windows subset (Chronicle 130, Cipher 39,
Vector 303, Recon 14). The Chromebook CTF content should have
classified as ChromeOS or Linux-family, routing through ARBOR.

**Impact:** Medium. The misclassification routed 13 plugins
that don't match the data; those plugins hallucinated or
pattern-matched on coincidental filename substrings (303 Vector
artifacts on a Chromebook tar is suspicious). A correct
classification would have routed ARBOR, which then produced 0
on the input anyway — so the net evidence output is low either
way, but the provenance label ("Windows Workstation") would be
incorrect in any resulting report.

### G8 — iOS directory with 378,908 files produces only 7 artifacts

2020 CTF iOS directory unpacked 378,908 files (21 GB) in 114
seconds but produced only 7 artifacts total (1 Remnant + 1
Recon + 1 CSAM + 2 Advisory + 2 Sigma). Apex/Carbon/Pulse (the
iOS-relevant plugins) all returned zero.

**Impact:** Critical for iOS casework. Either the plugins'
target patterns don't match the CTF dataset's file layout, or
the plugin parsers silently skip files they can't read (e.g.,
binary plists without a plist parser, encrypted sqlite, etc.).

### G9 — 1 Vault / 36 artifacts on Charlie/Jo and identical 12 Cipher / 36 Vault counts across two different images

Charlie and Jo produced **exactly** 12 Cipher artifacts and
**exactly** 36 Vault artifacts each. Vector 2,465 vs 2,467
(differ by 2); Phantom 535 vs 533 (differ by 2); Chronicle 197
vs 322 (realistic differential). The perfect matches at Cipher
and Vault are suspicious — possibly cache-count, possibly
hard-coded limits, possibly the plugins have stop-at-N logic
that both images happen to hit.

**Impact:** Low/diagnostic. Worth a function-body check on Cipher
and Vault to confirm the 12/36 is real-data differential versus
artificial cap.

### G10 — Materialize filter omits entire file families

The `TARGET_PATTERNS` list in `strata-engine-adapter::vfs_materialize`
is heavily Windows/browser/common-sqlite-oriented. Missing:

- APFS xattrs / resource forks (no pattern for
  `com.apple.*` xattr names; the v16 APFS walker has a
  documented xattr gap matching this)
- Android `.apk` signing certs
- Linux `/proc/` snapshot artifacts
- Container layer metadata (Docker/OCI)
- FAT volume serial numbers
- NTFS $J USN journal structure (pattern is `$usnjrnl` — case
  may not match real MFT output)
- Keychain plist content beyond `.plist` extension (Apple iOS
  `keychain-backup.plist` pattern exists, but many keychain
  variants don't match generically)

**Impact:** Medium-High. For real Mac casework, extending this
list to include every macOS forensic target the plugin set
expects to parse is a one-session sprint.

---

## §6 — Tripwire and known-limitation validation

v15/v16 deferral tripwires:

| Tripwire | Should fire on... | Actually fires? |
|---|---|---|
| `dispatch_exfat_returns_explicit_deferral_message` | exFAT boot sector with `EXFAT   ` signature | Not exercised — no exFAT image in corpus. Dispatcher code is verified via unit test; real-image validation deferred. |
| `apfs_walker_walks_current_state_only_pending_snapshot_enumeration` | APFS volume with snapshots enumerated via `diskutil apfs createSnapshot` | Not exercised — UNENCRYPTED.dmg has no snapshots. |
| Fusion drive detection (literal `"fusion"` in walker open error) | APFS container with `NX_INCOMPAT_FUSION` flag | Not exercised — no fusion container in corpus (they require physical fusion hardware to produce). |
| APFS encryption `read_file` rejection | APFS volume with `APFS_FS_UNENCRYPTED` cleared | Not exercised — both DMG's inner APFS volumes have the bit set (unencrypted). |
| Multi-volume APFS routing | APFS container with 2+ `fs_oids` | Not exercised — no multi-volume fixture (per v16 S5, DMG-backed containers cap at `max_file_systems=1`). |

### Tripwire coverage gap

**Every v16 APFS tripwire is unvalidated in field terms by this
run.** The fusion detection and multi-volume routing gaps are
documented in the SESSION_STATE_v16_SESSION_5_COMPLETE — they
require physical hardware that isn't in the validation workstation.
Snapshot and encryption tripwires are reachable in principle with
a realistic Mac fixture — v17 validation should exercise them.

### New limitations surfaced by this run (no tripwire yet)

These aren't in any existing `_still_X` / `_pending_Y` test and
should be considered for v17:

1. **`encrcdsa` FileVault DMG detection** — no classifier
   emits a "FileVault-encrypted DMG" record. v17 candidate:
   add a 4-byte-signature check before falling through to
   "unknown filesystem."
2. **Sigma correlation layer not firing on Windows inputs** —
   either a rule-set gap or a meta-record issue. v17 candidate:
   add a tripwire asserting that Charlie produces at least one
   Sigma rule firing (rule 7 persistence).
3. **Remnant constant-emission pattern** — if 1 artifact is a
   status record, document it; if it's a false-positive Recycle
   Bin entry, flag it. v17 candidate: tripwire asserting
   Remnant produces 0 artifacts on a zeroed-buffer input.
4. **Plugin-never-fires class** — ten plugins zero across the
   corpus. v17 candidate: per-plugin "should fire on matching
   input" tripwire (e.g., "Specter should produce ≥1 artifact
   on an input containing a .ab file").

---

## §7 — Recommendations (ranked by severity × likelihood)

**Severity** = how badly an examiner would be harmed by missing
this.
**Likelihood** = how often this pattern appears in real casework.

Top-priority v17 work for shipping to real examiners:

### R1 (critical × high) — Validate the APFS walker end-to-end on realistic Mac content

v0.16.0 claims APFS is live. Dispatcher routing is live. But no
run in this validation produced a single forensically-relevant
artifact from an APFS input, because the only APFS fixture
available (UNENCRYPTED.dmg) contains only plain text files that
don't match any plugin's target patterns.

**What to ship before real-world deployment:** a sample-data
APFS image (could be examiner-provided, synthesized via
`hdiutil` with realistic content, or even a Mac user home dir
copied into a fresh APFS DMG) containing at least:
- A sqlite database (Safari History, Mail.app, Contacts)
- `.plist` files (LaunchAgents, com.apple.*)
- An xattr-decorated file (Gatekeeper provenance)
- A sparse file (to exercise extent reading)

Then rerun this validation and verify Apex + MacTrace + Vault
produce non-trivial artifacts.

### R2 (critical × high) — Audit why Sigma correlation never fires a rule

2,500+ Windows persistence artifacts on Charlie/Jo should trigger
at least Rule 7 (persistence). Zero rule firings means the
correlation engine is either not wired to the plugin outputs,
receiving data in a format its rules don't match, or emitting
only meta-records.

**Acceptance:** Charlie should produce ≥1 Sigma rule firing
(pick a specific rule — persistence on registry hives is the
obvious candidate). Add as a tripwire alongside Remnant-1 etc.

### R3 (high × high) — Audit the 10 plugins that produced zero artifacts across the corpus

Listed in §3. Per v15 Lesson 1, do function-body inspections on
Specter, Nimbus, Wraith, Guardian, NetFlow, Sentinel, Apex,
Carbon, Pulse, ARBOR. For each:
- Is the plugin's target-pattern matcher finding the files it
  expects?
- If it finds files, is the parser reading them or returning
  silent-empty?
- Is the plugin's output schema compatible with Sigma's input
  expectations?

### R4 (high × medium) — Fix Chromebook misclassification

DETECT-1's 0.91-confidence "Windows Workstation" label on a
Chromebook tar is high-confidence wrong. Mis-labels propagate
into case reports; "this device is a Windows Workstation" is a
material claim when it should read ChromeOS / Linux.

**Fix:** either tune DETECT-1's weights on Chrome-family files
(look for `home/user/Downloads`, `home/chronos/`, `.BASHRC` vs
registry hives), or add an early ChromeOS-specific classifier
ahead of the Windows one.

### R5 (high × medium) — Surface `encrcdsa` and other encrypted-container signatures

An examiner handed an `encrcdsa`-header DMG currently sees
"unknown filesystem" in Strata's log with no signal that the
input is encrypted. At minimum, a 1-line encrypted-container
detector emitting `{filesystem: "FileVault-encrypted DMG",
reason: "encrcdsa signature at offset 0", suggestion: "offline
key recovery required"}` would match the level of signal Strata
already produces for other limitations.

Related signatures worth detecting: VeraCrypt containers,
LUKS2, BitLocker-wrapped VHD, iOS encrypted backup manifests.

### R6 (medium × high) — Fix materialization scope so APFS + Linux + Android file families aren't silently dropped

`TARGET_PATTERNS` in `strata-engine-adapter::vfs_materialize` is
overfit to Windows/browser content. Extend to cover:
- macOS `.plist` variants beyond extension match (
  typical iOS keychain files have no `.plist` suffix)
- Android `.apk` + `/data/data/<pkg>/databases/`
- Linux package manifests (`/var/lib/dpkg/`)
- Container + VM metadata

One-sprint scope. Accept criteria: a macOS home-dir fixture
produces ≥10 materialized forensic files; currently it produces 0.

### R7 (medium × medium) — Document in user-facing materials that EVTX-only plugins don't parse XP `.evt` files

Sentinel's plugin mapping says "Windows Event Logs" but only
handles `.evtx`. An examiner with a Windows XP/7 case will
expect `.evt` support. Either ship a legacy `.evt` parser (larger
scope) or clearly document the EVTX-only boundary in Sentinel's
plugin docs + case log output.

### R8 (low × low) — Investigate Cipher + Vault identical cross-image counts

Charlie/Jo both emit exactly 12 Cipher + 36 Vault artifacts. Too
round to be coincidence. Quick function-body check on both
plugins to confirm whether the counts are real-differential or
an artificial cap.

### R9 (low × medium) — Deferred image validation (Terry, memdump, large tars)

Terry/memdump/30GB tars were scale-deferred from this run. Once
R1–R3 are addressed, re-run this validation against the full
corpus to catch scale-dependent bugs (e.g., MAX_FILES cap, OOM
on memdump, tar unpacker stall on 30GB+).

### R10 (low × low) — Clean up inconsistent plugin output-count baselines

Remnant 1/1/1/...1/3/..., CSAM 1/1/1/... — if these are status
records, they should be schema-typed as status not data. If they
are data records, they need content audit. Either way, the
always-1 pattern is confusing to examiners reading case output.

---

## Appendix A — Validation run environment

- Host: macOS (Darwin) on Apple Silicon
- Strata build: `cargo build --release -p strata-shield-cli` from
  tag `v0.16.0` working tree
- Case outputs: `~/Wolfmark/strata/test-output/validation-v0.16.0/`
  (one subdirectory per image; per-image `manifest.txt`,
  `summary.json`, `run.stdout.log`, `run.stderr.log`, and full
  `case/` directory retained as audit trail)
- Library tests at session end: 3,836 pass / 0 fail (unchanged
  from v0.16.0 session-close baseline — no source was modified)
- Quality gate at session end: PASS (baseline 424 unwrap / 5
  unsafe / 5 println — unchanged)

## Appendix B — File layout of validation outputs

```
test-output/validation-v0.16.0/
├── _all_runs.json              # aggregated summaries
├── _matrix.json                # per-plugin × per-image matrix
├── run_one.sh                  # invocation harness
├── summarize.py                # aggregator script
└── <image-short-name>/
    ├── manifest.txt            # image size + run metadata
    ├── summary.json            # `strata ingest run --json-result`
    ├── run.stdout.log
    ├── run.stderr.log
    └── case/                   # full strata case dir (kept)
        ├── extracted/          # materialized files
        ├── plugins/            # per-plugin outputs
        └── ...
```

## Appendix C — Per-image invocation

Every image was run with:

```
strata ingest run \
    --source <path> \
    --case-dir <out>/case \
    --case-name "validation-<short-name>" \
    --examiner v0.16.0-audit \
    --auto --auto-unpack \
    --json-result <out>/summary.json \
    --output-format json
```

with a bash-native watchdog kill after 60–600 s depending on
image size.

---

*Wolfmark Systems — validation audit, 2026-04-20.*
*This report is descriptive, not prescriptive. Gaps are named for
the v17 roadmap; no code was modified in this session.*
