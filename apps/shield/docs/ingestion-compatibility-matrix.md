# Strata Shield Ingestion Compatibility Matrix

This matrix tracks ingest-level support (open + route + parser adapter selection).

| Format Family | Status | Adapter | Notes |
| --- | --- | --- | --- |
| RAW / DD / IMG / 001 | supported | `container::raw` | Primary baseline disk ingest path. |
| E01 / Ex01 | supported | `container::e01` | Core evidence image support. |
| VHD / VHDX | supported | `container::vhd` | Virtual disk ingest path. |
| VMDK | supported | `container::vmdk` | Virtual disk ingest path. |
| AFF / AFF4 | partial | `container::aff` | Handler exists; parser depth varies by sample. |
| UFED export folders | partial | `ios::cellebrite` | Import parser profile detection by source naming. |
| GrayKey export folders | partial | `ios::graykey` | Import parser profile detection by source naming. |

## Validation policy (phase 1)

- Every supported format must have at least one fixture-backed ingest test.
- Unsupported sections must be reported via ingest manifest rows.
- Parser adapter selection must be deterministic for the same source path.
