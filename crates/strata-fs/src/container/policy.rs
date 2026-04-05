use crate::audit::event::AuditEventType;
use crate::audit::logger::AuditLogger;
use crate::container::EvidenceContainerRO;
use crate::errors::ForensicError;

use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PolicyMode {
    Phase1Metadata,
    Hashing,
}

impl PolicyMode {
    fn as_str(&self) -> &'static str {
        match self {
            PolicyMode::Phase1Metadata => "phase1_metadata",
            PolicyMode::Hashing => "hashing",
        }
    }
}

/// Phase-1 read policy with explicit mode transitions and explicit allow-ranges.
///
/// Hardening rules:
/// - Phase1Metadata:
///   - Reads in allowlisted ranges are allowed (even if non-sector-aligned).
///   - Any non-allowlisted read MUST be sector-aligned (offset and length).
/// - Hashing:
///   - Disabled until begin_hashing() is called (audited).
///   - Only large sequential forward reads are allowed.
/// - Any blocked read emits ReadBlocked audit event.
pub struct ReadPolicyContainer<C: EvidenceContainerRO> {
    inner: C,

    case_id: Uuid,
    audit: Arc<AuditLogger>,

    mode: Mutex<PolicyMode>,
    allowed_ranges: Mutex<Vec<(u64, u64)>>, // (start, end exclusive)

    seq_state: Mutex<SeqState>,
    seq_min_len: u64,
}

#[derive(Debug, Clone)]
struct SeqState {
    next_offset: u64,
    initialized: bool,
}

impl<C: EvidenceContainerRO> ReadPolicyContainer<C> {
    /// Create Phase-1 policy in metadata-only mode.
    ///
    /// Defaults:
    /// - Whitelist first 4 MiB (layout + probing)
    /// - Whitelist last 4 MiB (GPT backup)
    /// - Hashing reads DISALLOWED until begin_hashing() is called
    pub fn phase1(inner: C, case_id: Uuid, audit: Arc<AuditLogger>) -> Self {
        let size = inner.size();

        let head = 4u64 * 1024 * 1024;
        let tail = 4u64 * 1024 * 1024;

        let head_end = head.min(size);
        let tail_start = size.saturating_sub(tail);

        Self {
            inner,
            case_id,
            audit,
            mode: Mutex::new(PolicyMode::Phase1Metadata),
            allowed_ranges: Mutex::new(vec![(0, head_end), (tail_start, size)]),
            seq_state: Mutex::new(SeqState {
                next_offset: 0,
                initialized: false,
            }),
            seq_min_len: 1024 * 1024, // 1 MiB minimum for hashing reads
        }
    }

    /// Add an explicit allowed range (end-exclusive) and audit it.
    pub fn allow_range(&self, offset: u64, length: u64, label: &str) -> Result<(), ForensicError> {
        if length == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "allow_range length is zero",
            )
            .into());
        }

        let end = offset.checked_add(length).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "allow_range overflow")
        })?;

        let size = self.inner.size();
        if offset > size || end > size {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "allow_range beyond EOF",
            )
            .into());
        }

        {
            let mut guard = match self.allowed_ranges.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            guard.push((offset, end));
        }

        self.audit.log(
            self.case_id,
            AuditEventType::AllowedRangeAdded {
                offset,
                length,
                label: label.to_string(),
            },
        );

        Ok(())
    }

    /// Explicitly enable hashing mode (audited). Idempotent.
    pub fn begin_hashing(&self) {
        let mut guard = match self.mode.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        if *guard == PolicyMode::Hashing {
            return;
        }

        let from = guard.as_str().to_string();
        *guard = PolicyMode::Hashing;
        let to = guard.as_str().to_string();

        self.audit
            .log(self.case_id, AuditEventType::PolicyModeChanged { from, to });
    }

    fn current_mode(&self) -> PolicyMode {
        match self.mode.lock() {
            Ok(g) => *g,
            Err(poisoned) => *poisoned.into_inner(),
        }
    }

    fn lock_seq_state(&self) -> MutexGuard<'_, SeqState> {
        match self.seq_state.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn is_sequential_bulk_read(&self, offset: u64, length: u64) -> bool {
        if length < self.seq_min_len {
            return false;
        }

        let mut seq = self.lock_seq_state();

        if !seq.initialized {
            seq.initialized = true;
            seq.next_offset = offset.saturating_add(length);
            return true;
        }

        if offset != seq.next_offset {
            return false;
        }

        seq.next_offset = seq.next_offset.saturating_add(length);
        true
    }

    fn in_allowed_ranges(&self, offset: u64, length: u64) -> bool {
        let end = match offset.checked_add(length) {
            Some(v) => v,
            None => return false,
        };

        let guard = match self.allowed_ranges.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        guard.iter().any(|(s, e)| offset >= *s && end <= *e)
    }

    fn sane_sector_size(&self) -> u64 {
        match self.inner.sector_size() {
            512 | 1024 | 2048 | 4096 => self.inner.sector_size(),
            _ => 512,
        }
    }

    fn is_sector_aligned(&self, offset: u64, length: u64) -> bool {
        let ss = self.sane_sector_size();
        offset.is_multiple_of(ss) && length.is_multiple_of(ss)
    }

    fn block(&self, offset: u64, length: u64, reason: &str) -> ForensicError {
        self.audit.log(
            self.case_id,
            AuditEventType::ReadBlocked {
                offset,
                length,
                reason: reason.to_string(),
            },
        );
        std::io::Error::new(std::io::ErrorKind::PermissionDenied, reason).into()
    }
}

impl<C: EvidenceContainerRO> EvidenceContainerRO for ReadPolicyContainer<C> {
    fn description(&self) -> &str {
        self.inner.description()
    }

    fn source_path(&self) -> &Path {
        self.inner.source_path()
    }

    fn size(&self) -> u64 {
        self.inner.size()
    }

    fn sector_size(&self) -> u64 {
        self.inner.sector_size()
    }

    /// Allocate + fill helper for APIs that still want Vec<u8>.
    fn read_at(&self, offset: u64, length: u64) -> Result<Vec<u8>, ForensicError> {
        let len_usize: usize = length.try_into().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "read_at length too large")
        })?;

        let mut buf = vec![0u8; len_usize];
        self.read_into(offset, &mut buf)?;
        Ok(buf)
    }

    /// Policy-enforced read into caller-provided buffer.
    fn read_into(&self, offset: u64, buf: &mut [u8]) -> Result<(), ForensicError> {
        let length = buf.len() as u64;

        // Allow explicit allowlisted reads (can be non-aligned; explicit + audited via allow_range()).
        if self.in_allowed_ranges(offset, length) {
            return self.inner.read_into(offset, buf);
        }

        // In metadata mode, block non-sector-aligned reads unless allowlisted.
        if self.current_mode() == PolicyMode::Phase1Metadata
            && !self.is_sector_aligned(offset, length)
        {
            return Err(self.block(
                offset,
                length,
                "ReadPolicy: blocked non-sector-aligned read in phase1_metadata (not allowlisted)",
            ));
        }

        // Hashing reads only after begin_hashing(), and only sequential bulk.
        if self.current_mode() == PolicyMode::Hashing
            && self.is_sequential_bulk_read(offset, length)
        {
            return self.inner.read_into(offset, buf);
        }

        Err(self.block(
            offset,
            length,
            "ReadPolicy: blocked read (outside allowlist / mode rules)",
        ))
    }
}
