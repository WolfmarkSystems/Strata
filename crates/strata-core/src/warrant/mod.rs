//! Warrant scope enforcement (WF-9).
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use strata_plugin_sdk::Artifact;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnforcementMode {
    Advisory,
    Strict,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WarrantScope {
    pub description: String,
    pub date_from: Option<DateTime<Utc>>,
    pub date_to: Option<DateTime<Utc>>,
    pub authorized_accounts: Vec<String>,
    pub authorized_categories: Vec<String>,
    pub authorized_plugins: Vec<String>,
    pub enforcement_mode: Option<EnforcementMode>,
    pub authorized_by: String,
    pub authorization_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeCheck {
    pub in_scope: bool,
    pub reasons: Vec<String>,
}

impl WarrantScope {
    pub fn mode(&self) -> EnforcementMode {
        self.enforcement_mode.unwrap_or(EnforcementMode::Advisory)
    }

    pub fn check(&self, a: &Artifact) -> ScopeCheck {
        let mut reasons: Vec<String> = Vec::new();
        if let Some(from) = self.date_from {
            if let Some(ts) = a.timestamp {
                if (ts as i64) < from.timestamp() {
                    reasons.push(format!("artifact predates authorised range ({})", from));
                }
            }
        }
        if let Some(to) = self.date_to {
            if let Some(ts) = a.timestamp {
                if (ts as i64) > to.timestamp() {
                    reasons.push(format!("artifact postdates authorised range ({})", to));
                }
            }
        }
        if !self.authorized_accounts.is_empty() {
            let account = a
                .data
                .get("account")
                .or_else(|| a.data.get("user_id"))
                .or_else(|| a.data.get("username"))
                .cloned()
                .unwrap_or_default();
            if !account.is_empty() && !self.authorized_accounts.contains(&account) {
                reasons.push(format!("account '{}' outside authorisation", account));
            }
        }
        if !self.authorized_categories.is_empty() {
            let cat = a
                .data
                .get("file_type")
                .cloned()
                .unwrap_or_else(|| a.category.clone());
            if !self.authorized_categories.contains(&cat) {
                reasons.push(format!("category '{}' outside authorisation", cat));
            }
        }
        if !self.authorized_plugins.is_empty() {
            let plugin = a.data.get("plugin").cloned().unwrap_or_default();
            if !plugin.is_empty() && !self.authorized_plugins.contains(&plugin) {
                reasons.push(format!("plugin '{}' outside authorisation", plugin));
            }
        }
        ScopeCheck {
            in_scope: reasons.is_empty(),
            reasons,
        }
    }

    pub fn apply<'a>(&self, artifacts: &'a [Artifact]) -> (Vec<&'a Artifact>, Vec<&'a Artifact>) {
        let mut in_scope: Vec<&Artifact> = Vec::new();
        let mut out_of_scope: Vec<&Artifact> = Vec::new();
        for a in artifacts {
            if self.check(a).in_scope {
                in_scope.push(a);
            } else {
                out_of_scope.push(a);
            }
        }
        (in_scope, out_of_scope)
    }

    pub fn filter_for_display<'a>(&self, artifacts: &'a [Artifact]) -> Vec<&'a Artifact> {
        let (in_scope, out_of_scope) = self.apply(artifacts);
        match self.mode() {
            EnforcementMode::Strict => in_scope,
            EnforcementMode::Advisory => {
                let mut combined = in_scope;
                combined.extend(out_of_scope);
                combined
            }
        }
    }

    pub fn html_summary(&self, in_scope: usize, out_of_scope: usize) -> String {
        format!(
            "<section class=\"warrant-scope\"><h2>Warrant Scope</h2>\n\
             <p>Authorisation: {}</p><p>Reference: {}</p><p>Issued by: {}</p>\n\
             <p>Artifacts in scope: {} | Out of scope: {}</p></section>\n",
            escape(&self.description),
            escape(&self.authorization_ref),
            escape(&self.authorized_by),
            in_scope,
            out_of_scope
        )
    }
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact(file_type: &str, ts: u64, account: &str) -> Artifact {
        let mut a = Artifact::new(file_type, "/evidence/x");
        a.timestamp = Some(ts);
        a.add_field("file_type", file_type);
        if !account.is_empty() {
            a.add_field("account", account);
        }
        a
    }

    #[test]
    fn date_range_check_flags_out_of_scope() {
        let scope = WarrantScope {
            date_from: Some(DateTime::<Utc>::from_timestamp(1_000_000_000, 0).expect("ts")),
            date_to: Some(DateTime::<Utc>::from_timestamp(1_800_000_000, 0).expect("ts")),
            ..Default::default()
        };
        let a = artifact("Prefetch", 500_000_000, "");
        let check = scope.check(&a);
        assert!(!check.in_scope);
        assert!(check.reasons.iter().any(|r| r.contains("predates")));
    }

    #[test]
    fn authorized_accounts_and_categories_enforced() {
        let scope = WarrantScope {
            authorized_accounts: vec!["alice".into()],
            authorized_categories: vec!["Prefetch".into()],
            ..Default::default()
        };
        let ok = artifact("Prefetch", 1_700_000_000, "alice");
        assert!(scope.check(&ok).in_scope);
        let bad_account = artifact("Prefetch", 1_700_000_000, "bob");
        assert!(!scope.check(&bad_account).in_scope);
        let bad_cat = artifact("Registry", 1_700_000_000, "alice");
        assert!(!scope.check(&bad_cat).in_scope);
    }

    #[test]
    fn apply_splits_in_scope_and_out_of_scope() {
        let scope = WarrantScope {
            authorized_categories: vec!["Prefetch".into()],
            ..Default::default()
        };
        let arts = vec![
            artifact("Prefetch", 1, ""),
            artifact("Registry", 2, ""),
            artifact("Prefetch", 3, ""),
        ];
        let (inside, outside) = scope.apply(&arts);
        assert_eq!(inside.len(), 2);
        assert_eq!(outside.len(), 1);
    }

    #[test]
    fn strict_mode_filters_out_of_scope_entirely() {
        let scope = WarrantScope {
            enforcement_mode: Some(EnforcementMode::Strict),
            authorized_categories: vec!["Prefetch".into()],
            ..Default::default()
        };
        let arts = vec![artifact("Prefetch", 1, ""), artifact("Registry", 2, "")];
        let visible = scope.filter_for_display(&arts);
        assert_eq!(visible.len(), 1);
    }

    #[test]
    fn advisory_mode_shows_all_artifacts() {
        let scope = WarrantScope {
            authorized_categories: vec!["Prefetch".into()],
            ..Default::default()
        };
        let arts = vec![artifact("Prefetch", 1, ""), artifact("Registry", 2, "")];
        let visible = scope.filter_for_display(&arts);
        assert_eq!(visible.len(), 2);
    }

    #[test]
    fn html_summary_includes_counts() {
        let scope = WarrantScope {
            description: "Scope".into(),
            authorization_ref: "Warrant 1".into(),
            authorized_by: "Judge".into(),
            ..Default::default()
        };
        let html = scope.html_summary(5, 2);
        assert!(html.contains("Warrant 1"));
        assert!(html.contains("5"));
        assert!(html.contains("2"));
    }
}
