use serde::Serialize;

#[derive(Debug, Serialize)]
pub enum DiskLayout {
    MBR,
    GPT,
    DMG,
    Sparsebundle,
    Unknown,
}
