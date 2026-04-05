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
