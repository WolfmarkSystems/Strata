use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRegion {
    pub start: u64,
    pub end: u64,
    pub source: String,
}

impl ScanRegion {
    pub fn new(start: u64, end: u64, source: &str) -> Self {
        Self {
            start,
            end,
            source: source.to_string(),
        }
    }

    pub fn length(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    pub fn is_valid(&self) -> bool {
        self.end > self.start
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionSet {
    pub regions: Vec<ScanRegion>,
    pub total_bytes: u64,
    pub region_count: usize,
}

impl RegionSet {
    pub fn new(regions: Vec<ScanRegion>) -> Self {
        let total_bytes = regions.iter().map(|r| r.length()).sum();
        let region_count = regions.len();
        Self {
            regions,
            total_bytes,
            region_count,
        }
    }

    pub fn empty() -> Self {
        Self::new(Vec::new())
    }
}

pub fn coalesce_regions(mut regions: Vec<ScanRegion>, max_gap: u64) -> RegionSet {
    if regions.is_empty() {
        return RegionSet::empty();
    }

    regions.sort_by(|a, b| a.start.cmp(&b.start));

    let mut coalesced: Vec<ScanRegion> = Vec::new();

    let mut current = regions[0].clone();

    for next in regions.iter().skip(1) {
        if next.start <= current.end {
            if next.end > current.end {
                current.end = next.end;
            }
            if current.source.is_empty() && !next.source.is_empty() {
                current.source = next.source.clone();
            }
        } else if next.start.saturating_sub(current.end) <= max_gap {
            current.end = next.start + (next.end - next.start);
        } else {
            if current.is_valid() {
                coalesced.push(current);
            }
            current = next.clone();
        }
    }

    if current.is_valid() {
        coalesced.push(current);
    }

    RegionSet::new(coalesced)
}

pub fn offset_regions(regions: &[ScanRegion], offset: u64) -> Vec<ScanRegion> {
    regions
        .iter()
        .map(|r| ScanRegion {
            start: r.start + offset,
            end: r.end + offset,
            source: r.source.clone(),
        })
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionSummary {
    pub fs_type: String,
    pub region_count: usize,
    pub total_bytes: u64,
    pub coalesce_gap: u64,
    pub fallback_used: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coalesce_empty() {
        let result = coalesce_regions(vec![], 1024);
        assert!(result.regions.is_empty());
        assert_eq!(result.total_bytes, 0);
    }

    #[test]
    fn test_coalesce_single_region() {
        let regions = vec![ScanRegion::new(0, 1000, "test")];
        let result = coalesce_regions(regions, 1024);
        assert_eq!(result.regions.len(), 1);
        assert_eq!(result.regions[0].start, 0);
        assert_eq!(result.regions[0].end, 1000);
    }

    #[test]
    fn test_coalesce_overlapping() {
        let regions = vec![
            ScanRegion::new(0, 1000, "test1"),
            ScanRegion::new(500, 1500, "test2"),
            ScanRegion::new(1400, 2000, "test3"),
        ];
        let result = coalesce_regions(regions, 1024);
        assert_eq!(result.regions.len(), 1);
        assert_eq!(result.regions[0].start, 0);
        assert_eq!(result.regions[0].end, 2000);
    }

    #[test]
    fn test_coalesce_with_gap() {
        let regions = vec![
            ScanRegion::new(0, 1000, "test1"),
            ScanRegion::new(1100, 2000, "test2"),
        ];
        let result = coalesce_regions(regions, 200);
        assert_eq!(result.regions.len(), 1);
    }

    #[test]
    fn test_coalesce_within_gap() {
        let regions = vec![
            ScanRegion::new(0, 1000, "test1"),
            ScanRegion::new(1100, 2000, "test2"),
        ];
        let result = coalesce_regions(regions.clone(), 200);
        assert_eq!(result.regions.len(), 1);

        let result2 = coalesce_regions(regions.clone(), 150);
        assert_eq!(result2.regions.len(), 1);

        let result3 = coalesce_regions(regions, 100);
        assert_eq!(result3.regions.len(), 1);
    }

    #[test]
    fn test_coalesce_deterministic() {
        let regions = vec![
            ScanRegion::new(1000, 2000, "a"),
            ScanRegion::new(0, 500, "b"),
            ScanRegion::new(500, 1000, "c"),
        ];

        let result1 = coalesce_regions(regions.clone(), 1024);

        let result2 = coalesce_regions(regions.clone(), 1024);

        assert_eq!(result1.regions.len(), result2.regions.len());
        for (r1, r2) in result1.regions.iter().zip(result2.regions.iter()) {
            assert_eq!(r1.start, r2.start);
            assert_eq!(r1.end, r2.end);
        }
    }

    #[test]
    fn test_offset_regions() {
        let regions = vec![
            ScanRegion::new(0, 1000, "test"),
            ScanRegion::new(2000, 3000, "test"),
        ];

        let offset = 1000;
        let result = offset_regions(&regions, offset);

        assert_eq!(result[0].start, 1000);
        assert_eq!(result[0].end, 2000);
        assert_eq!(result[1].start, 3000);
        assert_eq!(result[1].end, 4000);
    }

    #[test]
    fn test_region_length() {
        let r = ScanRegion::new(100, 200, "test");
        assert_eq!(r.length(), 100);

        let r2 = ScanRegion::new(200, 100, "test");
        assert_eq!(r2.length(), 0);
    }
}
