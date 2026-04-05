use crate::audit::event::AuditEventType;
use crate::audit::logger::AuditLogger;
use crate::container::EvidenceContainerRO;
use crate::errors::ForensicError;

use std::path::Path;
use std::sync::Arc;
use uuid::Uuid;

/// Evidence container wrapper that emits audit events for every action.
pub struct AuditedContainer<C: EvidenceContainerRO> {
    inner: C,
    case_id: Uuid,
    audit: Arc<AuditLogger>,
}

impl<C: EvidenceContainerRO> AuditedContainer<C> {
    pub fn new(inner: C, case_id: Uuid, audit: Arc<AuditLogger>) -> Self {
        audit.log(case_id, AuditEventType::EvidenceOpened);

        Self {
            inner,
            case_id,
            audit,
        }
    }

    pub fn into_inner(self) -> C {
        self.inner
    }
}

impl<C: EvidenceContainerRO> EvidenceContainerRO for AuditedContainer<C> {
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

    fn read_into(&self, offset: u64, buf: &mut [u8]) -> Result<(), ForensicError> {
        let length = buf.len() as u64;

        match self.inner.read_into(offset, buf) {
            Ok(()) => {
                self.audit.log(
                    self.case_id,
                    AuditEventType::EvidenceRead { offset, length },
                );
                Ok(())
            }
            Err(e) => {
                self.audit.log(
                    self.case_id,
                    AuditEventType::Error {
                        message: format!(
                            "Evidence read failed at offset={} length={}: {}",
                            offset, length, e
                        ),
                    },
                );
                Err(e)
            }
        }
    }
}
