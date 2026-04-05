pub mod correlation;
pub mod entities;

pub use correlation::{correlate_records, CorrelationInput, CorrelationResult};
pub use entities::{
    Account, AppEvent, Call, CanonicalRecord, Device, Identity, Location, Media, Message,
    SystemEvent, WebEvent,
};
