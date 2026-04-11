//! Charge selector panel — Gov/Mil exclusive.
//!
//! Shows the charge database search, selection, and examiner notes for
//! the current case. Only rendered when `state.charges_available()` is true.

use crate::state::AppState;

pub fn render(ui: &mut egui::Ui, state: &mut AppState) {
    if !state.charges_available() {
        return;
    }

    // Ensure charge DB is loaded.
    if state.charge_db.is_none() {
        state.init_charge_db();
    }

    ui.heading("CHARGES & STATUTES");
    ui.label(
        egui::RichText::new("Gov/Mil")
            .small()
            .color(egui::Color32::from_rgb(100, 200, 100)),
    );
    ui.separator();

    // ── Search bar ──
    ui.horizontal(|ui| {
        ui.label("Search:");
        let response = ui.text_edit_singleline(&mut state.charge_search_query);
        if response.changed() {
            if let Some(db) = &state.charge_db {
                if state.charge_search_query.len() >= 2 {
                    state.charge_search_results =
                        db.search(&state.charge_search_query).unwrap_or_default();
                } else {
                    state.charge_search_results.clear();
                }
            }
        }
    });

    // ── Search results ──
    if !state.charge_search_results.is_empty() {
        ui.separator();
        ui.label(format!(
            "Results ({})",
            state.charge_search_results.len()
        ));
        let results = state.charge_search_results.clone();
        egui::ScrollArea::vertical()
            .max_height(200.0)
            .show(ui, |ui| {
                for entry in results.iter().take(20) {
                    ui.horizontal(|ui| {
                        let already = state
                            .selected_charges
                            .charges
                            .iter()
                            .any(|c| c.citation == entry.citation);
                        if already {
                            ui.label("✓");
                        } else if ui.small_button("+").clicked() {
                            state.add_charge(entry.clone());
                        }
                        ui.label(
                            egui::RichText::new(&entry.citation).strong(),
                        );
                        ui.label(&entry.short_title);
                    });
                }
            });
    }

    // ── Selected charges ──
    ui.separator();
    ui.label(format!(
        "SELECTED CHARGES ({})",
        state.selected_charges.charges.len()
    ));

    let mut to_remove = Vec::new();
    for charge in &state.selected_charges.charges {
        ui.horizontal(|ui| {
            if ui.small_button("×").clicked() {
                to_remove.push(charge.citation.clone());
            }
            ui.label(
                egui::RichText::new(&charge.citation).strong(),
            );
            ui.label(&charge.short_title);
        });
    }
    for citation in to_remove {
        state.remove_charge(&citation);
    }

    // ── Examiner notes ──
    ui.separator();
    ui.label("Examiner Notes:");
    ui.text_edit_multiline(&mut state.selected_charges.examiner_notes);
}

/// Format the charge block for text-based report output (PDF, Word).
///
/// Returns the formatted text block that goes at the top of reports,
/// or an empty string if no charges are selected.
#[allow(dead_code)]
pub fn format_charge_block(charges: &strata_charges::SelectedCharges) -> String {
    if charges.charges.is_empty() {
        return String::new();
    }

    let mut out = String::new();
    out.push_str("═══════════════════════════════════════════════════════════════\n");
    out.push_str("CHARGES UNDER INVESTIGATION\n");
    out.push_str("═══════════════════════════════════════════════════════════════\n\n");
    out.push_str(
        "The following charges have been identified as relevant to this\n\
         examination. Digital evidence recovered during this examination\n\
         should be evaluated in the context of these statutes.\n\n",
    );

    let usc: Vec<_> = charges
        .charges
        .iter()
        .filter(|c| c.code_set == strata_charges::ChargeSet::USC)
        .collect();
    let ucmj: Vec<_> = charges
        .charges
        .iter()
        .filter(|c| c.code_set == strata_charges::ChargeSet::UCMJ)
        .collect();
    let state_charges: Vec<_> = charges
        .charges
        .iter()
        .filter(|c| c.code_set == strata_charges::ChargeSet::State)
        .collect();

    if !usc.is_empty() {
        out.push_str("FEDERAL CHARGES (USC)\n");
        out.push_str("─────────────────────\n");
        for c in &usc {
            out.push_str(&format!("  {}\n", c.citation));
            out.push_str(&format!("  {}\n", c.short_title));
            if let Some(penalty) = &c.max_penalty {
                out.push_str(&format!("  Penalty: {}\n", penalty));
            }
            out.push('\n');
        }
    }

    if !ucmj.is_empty() {
        out.push_str("MILITARY CHARGES (UCMJ)\n");
        out.push_str("────────────────────────\n");
        for c in &ucmj {
            out.push_str(&format!("  {}\n", c.citation));
            out.push_str(&format!("  {}\n", c.short_title));
            if let Some(penalty) = &c.max_penalty {
                out.push_str(&format!("  Penalty: {}\n", penalty));
            }
            out.push('\n');
        }
    }

    if !state_charges.is_empty() {
        out.push_str("STATE CHARGES\n");
        out.push_str("──────────────\n");
        for c in &state_charges {
            out.push_str(&format!("  {}\n", c.citation));
            out.push_str(&format!("  {}\n", c.short_title));
            if let Some(penalty) = &c.max_penalty {
                out.push_str(&format!("  Penalty: {}\n", penalty));
            }
            out.push('\n');
        }
    }

    if !charges.examiner_notes.is_empty() {
        out.push_str(&format!("Examiner Notes: {}\n\n", charges.examiner_notes));
    }

    out.push_str(
        "This report was generated by Strata. All findings should be\n\
         reviewed by qualified legal counsel before use in charging decisions.\n",
    );
    out.push_str("═══════════════════════════════════════════════════════════════\n");

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use strata_charges::schema::*;

    fn test_selected() -> SelectedCharges {
        SelectedCharges {
            charges: vec![
                ChargeEntry {
                    id: 1,
                    code_set: ChargeSet::USC,
                    title: Some(18),
                    section: "2252".to_string(),
                    subsection: None,
                    citation: "18 U.S.C. § 2252".to_string(),
                    short_title: "Sexual Exploitation of Minors".to_string(),
                    description: "Possession/distribution".to_string(),
                    category: "Child Exploitation".to_string(),
                    artifact_tags: vec!["Media".into()],
                    severity: ChargeSeverity::Felony,
                    state_code: None,
                    max_penalty: Some("20 years".to_string()),
                    notes: None,
                },
                ChargeEntry {
                    id: 2,
                    code_set: ChargeSet::UCMJ,
                    title: None,
                    section: "120".to_string(),
                    subsection: None,
                    citation: "UCMJ Art. 120".to_string(),
                    short_title: "Rape and Sexual Assault".to_string(),
                    description: "Primary military sexual assault statute".to_string(),
                    category: "Sexual Offenses".to_string(),
                    artifact_tags: vec!["Chat".into()],
                    severity: ChargeSeverity::UCMJArticle,
                    state_code: None,
                    max_penalty: Some("Life imprisonment".to_string()),
                    notes: None,
                },
            ],
            examiner_notes: "Primary charges identified".to_string(),
            selected_at: "2026-04-11T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn report_includes_charge_block_when_charges_selected() {
        let block = format_charge_block(&test_selected());
        assert!(!block.is_empty());
        assert!(block.contains("CHARGES UNDER INVESTIGATION"));
        assert!(block.contains("18 U.S.C. § 2252"));
        assert!(block.contains("UCMJ Art. 120"));
    }

    #[test]
    fn report_omits_charge_block_when_no_charges_selected() {
        let empty = SelectedCharges::default();
        let block = format_charge_block(&empty);
        assert!(block.is_empty());
    }

    #[test]
    fn report_groups_usc_and_ucmj_separately() {
        let block = format_charge_block(&test_selected());
        let usc_pos = block.find("FEDERAL CHARGES (USC)").unwrap();
        let ucmj_pos = block.find("MILITARY CHARGES (UCMJ)").unwrap();
        assert!(usc_pos < ucmj_pos);
    }

    #[test]
    fn report_charge_block_appears_before_disclaimer() {
        let block = format_charge_block(&test_selected());
        let charges_pos = block.find("18 U.S.C. § 2252").unwrap();
        let disclaimer_pos = block.find("qualified legal counsel").unwrap();
        assert!(charges_pos < disclaimer_pos);
    }

    #[test]
    fn report_includes_examiner_notes_when_present() {
        let block = format_charge_block(&test_selected());
        assert!(block.contains("Primary charges identified"));
    }

    #[test]
    fn report_includes_penalties() {
        let block = format_charge_block(&test_selected());
        assert!(block.contains("Penalty: 20 years"));
        assert!(block.contains("Penalty: Life imprisonment"));
    }
}
