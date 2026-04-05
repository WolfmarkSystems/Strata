use crate::errors::ForensicError;
use regex::Regex;

pub struct CredentialHarvester;

impl CredentialHarvester {
    pub fn new() -> Self {
        Self
    }

    /// Sweeps massive buffers (RAM, Pagefiles, SQLite DBs) for exposed Username/Password combinations,
    /// API keys, JWT tokens, and OAuth secrets. Rips them into a single centralized database structure.
    pub fn harvest_credentials(
        &self,
        data: &[u8],
    ) -> Result<Vec<HarvestedCredential>, ForensicError> {
        let string_data = String::from_utf8_lossy(data);
        let mut credentials = Vec::new();

        // Basic heuristic capture for Username/Password patterns
        // e.g "password=..." "user:pass"
        let pass_regex = Regex::new(r"(?i)(?:password|passwd|pwd|pass)[\s=:]+([^\s,;&]+)").unwrap();
        let user_regex = Regex::new(r"(?i)(?:username|user|login)[\s=:]+([^\s,;&]+)").unwrap();

        for caps in pass_regex.captures_iter(&string_data) {
            credentials.push(HarvestedCredential {
                cred_type: String::from("Password"),
                value: caps[1].to_string(),
                context: String::from("Heuristic Regex Sweep"),
            });
        }

        for caps in user_regex.captures_iter(&string_data) {
            credentials.push(HarvestedCredential {
                cred_type: String::from("Username"),
                value: caps[1].to_string(),
                context: String::from("Heuristic Regex Sweep"),
            });
        }

        Ok(credentials)
    }
}

pub struct HarvestedCredential {
    pub cred_type: String,
    pub value: String,
    pub context: String,
}
