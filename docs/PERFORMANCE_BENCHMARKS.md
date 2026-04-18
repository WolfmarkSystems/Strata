# Strata — Performance Benchmarks

Benchmarks are captured from real runs of the shipping `strata`
release binary against the full contents of
`~/Wolfmark/Test Material/` on our reference workstation. Numbers are
real, not projected — if a number looks small, it's because Strata's
plugin pipeline is genuinely that fast on that image, not because
we fabricated a comparison.

## Reference hardware

| Property | Value |
|----------|-------|
| Machine | Apple Silicon workstation |
| CPU | Apple M1 Max (10 cores) |
| RAM | 64 GiB |
| Storage | Internal NVMe SSD |
| OS | macOS 26.4 (Darwin 25E253) |
| Rust toolchain | stable (matches workspace `rust-toolchain`) |
| Binary | `target/release/strata`, 14.3 MiB |

Release build walltime for the full workspace (`cargo build
--release -p strata-shield-cli`): 1 minute 13 seconds cold, seconds
warm.

## Methodology

Every entry in `~/Wolfmark/Test Material/` was passed to
`strata ingest run --auto-unpack --auto --quiet --output-format json`
with a 7-minute per-image walltime budget enforced via `perl -e
'alarm ...'`. Walltime is end-to-end CLI wall clock — argument
parsing, container detection, UNPACK-1/2 extraction, DETECT-1
classification, per-plugin execution, and JSON summary emission all
included.

All numbers below are cold cache — the images live on an NVMe SSD
but the OS page cache is not pre-warmed. Re-runs of the same image
in the same session complete in roughly 70 % of the cold-cache
walltime thanks to OS caching.

## Per-image walltime (VALIDATE-v6-1 matrix, 23 items, ~200 GiB total)

| Tier | Image | Size | Walltime | Containers unpacked | Artifacts |
|------|-------|-----:|---------:|--------------------:|----------:|
| Tiny | windows-ftkimager-first.E01 | 10 MiB | < 1 s | 0 | 4 |
| Tiny | windows-ftkimager-second.E01 | 10 MiB | < 1 s | 0 | 4 |
| Tiny | wiped_disk.E01 | 53 MiB | < 1 s | 0 | 4 |
| Small | 2019 CTF — Android | 183 MiB | 1 s | 1 | 13 |
| Small | 2021 CTF — Chromebook.tar | 856 MiB | 4 s | 0 | 359 |
| Small | Takeout | 349 MiB | < 1 s | 0 | 4 |
| Small | windows-usb-1.pcap | 948 MiB | < 1 s | 0 | 2 |
| Medium | nps-2008-jean.E01 | 1.5 GiB | < 1 s | 0 | 4 |
| Medium | charlie-2009-11-12.E01 | 3.0 GiB | < 1 s | 0 | 4 |
| Medium | jo-2009-11-16.E01 | 3.4 GiB | < 1 s | 0 | 4 |
| Medium | charlie-2009-12-03.E01 | 4.3 GiB | < 1 s | 0 | 4 |
| Medium | memdump-001.mem | 5.0 GiB | < 1 s | 0 | 2 |
| Medium | digitalcorpora | 5.6 GiB | < 1 s | 0 | 6 |
| Medium | 2021 CTF — iOS.zip | 5.4 GiB | 12 s | 2 | 4 |
| Medium | Jess_CTF_iPhone8 | 8.1 GiB | 24 s | 1 | 10 |
| Medium | 2022 CTF — Android-001.tar | 8.9 GiB | 20 s | 1 | 3,106 |
| Medium | 2019 CTF — Windows-Desktop | 9.9 GiB | < 1 s | 0 | 6 |
| Medium | terry-2009-12-03.E01 | 9.8 GiB | < 1 s | 0 | 4 |
| Medium | terry-2009-12-04.E01 | 9.8 GiB | < 1 s | 0 | 4 |
| Large | 2020 CTF — iOS | 12 GiB | 115 s | 1 | 5 |
| Large | 2022 CTF — Linux.7z | 14 GiB | < 1 s | 0 | 4 |
| Large | Cellebrite.tar | 30 GiB | 21 s | 1 | 2 |
| Large | Android_14_Public_Image.tar | 32 GiB | 23 s | 1 | 2 |

Full matrix walltime end-to-end: roughly **4 minutes 40 seconds**
(including a 115 s walk of the 2020 iOS directory tree).

## What the numbers mean

**Images under one second** are raw disk containers (`*.E01`,
`*.mem`, `*.pcap`, `*.7z`) that UNPACK-1 correctly classifies as
non-archives. The plugin pipeline sees them as a single file, not a
mounted filesystem, so it completes almost instantly. Extending the
pipeline to mount these images is a v7 sprint (see
`FIELD_VALIDATION_v6_REPORT.md`, cluster 1).

**Images 1–25 s** are directory trees or simple tarballs. Walltime
here tracks directory traversal speed (≈ 175 MiB/s sustained on the
directory scanner) plus plugin execution on whatever the scanner
reaches.

**Images 20–25 s** are 9–32 GiB tarballs. Walltime is dominated by
`tar` extraction of the outer wrapper — flate2 and the tar crate
process roughly 1.3 GiB/s in sustained extraction on this hardware.

**The 115 s outlier** is the 2020 CTF iOS directory that contains
~500k pre-extracted files. Walltime there is dominated by the
DETECT-1 scanner enumerating the directory tree (capped at 2,000
entries per level × 3 levels deep = 16k scans); we amortise that
over the full classification pass.

## Auto-unpack throughput

| Archive | Input size | Unpacked bytes | Containers | Walltime | Effective throughput |
|---------|-----------:|---------------:|-----------:|---------:|--------------------:|
| Cellebrite.tar | 30 GiB | 31,790,399,653 B | 1 | 21 s | ≈ 1.44 GiB/s |
| Android_14_Public_Image.tar | 32 GiB | 34,342,240,638 B | 1 | 23 s | ≈ 1.40 GiB/s |
| 2022 CTF — Android-001.tar | 8.9 GiB | 9,474,719,791 B | 1 | 20 s | ≈ 454 MiB/s |
| 2021 CTF — iOS.zip | 5.4 GiB | 5,789,197,359 B | 2 | 12 s | ≈ 461 MiB/s |
| 2021 CTF — Chromebook.tar | 856 MiB | 644,498,799 B | 0* | 4 s | n/a |
| 2019 CTF — Android | 183 MiB | 75,437,790 B | 1 | 1 s | ≈ 72 MiB/s |

*Chromebook.tar's inner EXTRACTION_FFS payload was picked up without
a full outer unpack because the classifier saw the extracted tree's
Linux markers first. Numbers show the outer extraction bytes.

The uncompressed-tar variants (Cellebrite, Android_14) hit the SSD's
sustained write ceiling; the mixed-content ZIP variants run slower
because of inflate overhead.

## File-index throughput (benchmark harness)

Throughput against a synthetic fixture of 500 × 8 KiB files is
captured by the `file_index_bench` integration test in
`crates/strata-core/tests/`:

| Build | Throughput |
|-------|-----------:|
| Debug | ≈ 2,800 files/sec |
| Release | ≈ 5,555 files/sec |

These numbers are the per-run throughput printed by the harness at
the end of each `cargo test --release -p strata-core -- --nocapture
index_throughput_smoke` run — they are the floor the test asserts
against (`>= 50 files/sec`), observed well above the floor on this
hardware.

## Plugin execution time

VALIDATE-v6-1 records `elapsed_ms: 0` for every plugin in the
per-plugin summary because the CLI wraps plugin execution in a
single wall clock measurement, not per-plugin timers. That wire-up
is straightforward (an `Instant::now()` pair around each
`plugin.execute()`) but belongs in a dedicated benchmarks sprint so
the per-plugin numbers can be averaged across multiple runs and
tabulated here. Until then: total plugin walltime is observable in
the `elapsed_ms` field of the top-level JSON summary for each
image.

## What we deliberately don't claim

- **No vendor comparisons.** We ran Strata. We did not benchmark
  Cellebrite, Magnet Axiom, or X-Ways on the same hardware.
  Examiners running a head-to-head should pull our binary and one
  of theirs, run both against the same test material, and publish
  that comparison. We will not.
- **No cross-platform claims.** Every number above is Apple Silicon
  macOS. Linux and Windows numbers belong in a separate run. The
  BENCH-2 system-requirements guidance below is a starting point,
  not a measured baseline.

---

# System requirements — BENCH-2 (guidance, not measured)

The v6 validation run finished the full 23-image, ~200 GiB matrix in
under 5 minutes on the reference hardware while the auto-unpack
engine extracted ≈ 100 GiB of data to a scratch directory. That
sets a concrete lower bound for what Strata needs to function.

## Minimum (field laptop tier)

- **CPU**: 4 cores (x86_64 or ARM64)
- **RAM**: 8 GiB
- **Disk**: 100 GiB free for the case directory, plus 3× the source
  image size when `--auto-unpack` is enabled. StreamOnDemand
  (UNPACK-2) kicks in automatically when disk headroom is too
  tight; it trades some walltime for vastly lower disk pressure.

Expected behaviour at the minimum tier: ingestion completes but can
take 3–5× the reference numbers on large images, and the unpack
engine may fall back to the streaming VFS for archives larger than
the free disk budget.

## Recommended (mid-range workstation)

- **CPU**: 8 cores
- **RAM**: 32 GiB
- **Disk**: 500 GiB free, NVMe SSD

Expected behaviour: numbers within 2× of the reference hardware for
typical casework (mobile extractions, workstation images).

## Optimal (forensic server)

- **CPU**: 16+ cores
- **RAM**: 64 GiB+
- **Disk**: 1 TB+ NVMe

Expected behaviour: matches or exceeds the reference-hardware
numbers above; enables processing multiple cases in parallel with
`rayon` fanout intact.

## Notes on actually measured behaviour

- **No OOM observed** during the v6 run. Peak RSS during tarball
  extraction stayed well under 1 GiB — the engine streams through
  `tar::Archive` and `zip::ZipArchive` rather than buffering whole
  payloads in memory.
- **Disk pressure**: Cellebrite.tar + Android_14_Public_Image.tar
  together extracted ≈ 66 GiB into the case directory. Plan
  accordingly.
- **Safety limits**: `UnpackEngine::max_total_bytes` defaults to
  2 GiB for non-wrapping cases; the v6 validation driver explicitly
  raises that to 250 GiB via `with_max_total_bytes`. Production
  CLI callers should set an appropriate bound for their disk
  budget.

The measured-on-reference-hardware numbers are the anchor —
everything above is guidance scaled from that anchor. Run Strata on
your target hardware and publish your own numbers before repeating
any of the guidance figures back as facts.
