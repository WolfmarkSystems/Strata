//! Append-only audit trail helpers.

use anyhow::Result;
use crate::case::project::VtpProject;

pub fn log_action(project: &VtpProject, examiner: &str, action: &str, detail: Option<&str>) -> Result<()> {
    project.log(examiner, action, detail)
}
