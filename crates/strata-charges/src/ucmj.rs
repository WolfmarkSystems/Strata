//! Uniform Code of Military Justice (UCMJ) punitive articles.

use crate::schema::{ChargeEntry, ChargeSet, ChargeSeverity};

#[allow(clippy::too_many_arguments)]
fn art(
    section: &str,
    citation: &str,
    short_title: &str,
    desc: &str,
    category: &str,
    tags: &[&str],
    penalty: Option<&str>,
    notes: Option<&str>,
) -> ChargeEntry {
    ChargeEntry {
        id: 0,
        code_set: ChargeSet::UCMJ,
        title: None,
        section: section.to_string(),
        subsection: None,
        citation: citation.to_string(),
        short_title: short_title.to_string(),
        description: desc.to_string(),
        category: category.to_string(),
        artifact_tags: tags.iter().map(|s| s.to_string()).collect(),
        severity: ChargeSeverity::UCMJArticle,
        state_code: None,
        max_penalty: penalty.map(String::from),
        notes: notes.map(String::from),
    }
}

/// Returns all UCMJ charge entries for database seeding.
pub fn ucmj_charges() -> Vec<ChargeEntry> {
    vec![
        // ── Crimes Against Persons / Discipline ──
        art("80", "UCMJ Art. 80", "Attempts", "An act done with specific intent to commit an offense under the UCMJ, amounting to more than mere preparation and tending to effect its commission", "Military Discipline", &[], Some("Same as completed offense"), None),
        art("81", "UCMJ Art. 81", "Conspiracy", "Conspiracy with one or more persons to commit an offense under the UCMJ", "Military Discipline", &["Chat", "Email"], Some("Same as completed offense"), None),
        art("82", "UCMJ Art. 82", "Solicitation", "Soliciting or advising another to commit an offense under the UCMJ", "Military Discipline", &["Chat", "Email"], Some("Same as completed offense"), None),
        art("83", "UCMJ Art. 83", "Fraudulent Enlistment", "Fraudulent enlistment, appointment, or separation from the armed forces", "Military Discipline", &["Documents"], Some("Dishonorable discharge, 5 years"), None),
        art("84", "UCMJ Art. 84", "Unlawful Enlistment", "Effecting unlawful enlistment, appointment, or separation", "Military Discipline", &["Documents"], Some("Dishonorable discharge, 5 years"), None),
        art("85", "UCMJ Art. 85", "Desertion", "Absence from unit with intent to remain away permanently, or to avoid hazardous duty or important service", "Military Discipline", &["Timeline", "Mobile"], Some("Death (in time of war); dishonorable discharge, 5 years"), None),
        art("86", "UCMJ Art. 86", "AWOL", "Absence without leave — failure to go to or going from appointed place of duty", "Military Discipline", &["Timeline"], Some("Confinement 1 month to 18 months"), None),
        art("87", "UCMJ Art. 87", "Missing Movement", "Through neglect or design misses movement of ship, aircraft, or unit", "Military Discipline", &[], Some("Dishonorable discharge, 2 years"), None),
        art("88", "UCMJ Art. 88", "Contempt Toward Officials", "Contemptuous words against the President, Vice President, Congress, Secretary of Defense, or officials", "Military Discipline", &["Chat", "Email"], Some("Dismissal, 1 year"), None),
        art("89", "UCMJ Art. 89", "Disrespect — Superior Officer", "Disrespect toward superior commissioned officer", "Military Discipline", &["Chat", "Email"], Some("Bad-conduct discharge, 1 year"), None),
        art("90", "UCMJ Art. 90", "Willful Disobedience", "Willfully disobeying lawful command of superior commissioned officer", "Military Discipline", &[], Some("Dishonorable discharge, 5 years (death in time of war)"), None),
        art("91", "UCMJ Art. 91", "Insubordinate Conduct", "Insubordinate conduct toward warrant officer, noncommissioned officer, or petty officer", "Military Discipline", &[], Some("Dishonorable discharge, 5 years"), None),
        art("92", "UCMJ Art. 92", "Failure to Obey Order", "Failure to obey order or regulation — violation of or failure to obey lawful general order or regulation", "Military Discipline", &[], Some("Dishonorable discharge, 2 years"), None),
        art("93", "UCMJ Art. 93", "Cruelty and Maltreatment", "Cruelty toward or oppression or maltreatment of any person subject to the offender's orders", "Military Discipline", &["Chat", "Email", "Mobile"], Some("Dishonorable discharge, 1 year"), None),
        art("93a", "UCMJ Art. 93a", "Prohibited Activities — Special Trust", "Prohibited activities with military recruit or trainee by person in position of special trust", "Sexual Offenses", &["Chat", "Email", "Mobile", "Media"], Some("Dishonorable discharge, 5 years"), None),
        art("94", "UCMJ Art. 94", "Mutiny or Sedition", "Mutiny, sedition, or failure to suppress or report a mutiny or sedition", "Military Discipline", &["Chat", "Email"], Some("Death or life imprisonment"), None),

        // ── Sexual Offenses ──
        art("120", "UCMJ Art. 120", "Rape and Sexual Assault", "Rape, sexual assault, aggravated sexual contact, and abusive sexual contact", "Sexual Offenses", &["Chat", "Email", "Mobile", "Media", "Browser"], Some("Life imprisonment (rape); 30 years (sexual assault)"), Some("Primary sexual assault statute for military investigations")),
        art("120a", "UCMJ Art. 120a", "Mails — Obscene Matter", "Depositing obscene matter in the mail", "Obscenity", &["Media", "Email"], Some("Dishonorable discharge, 5 years"), None),
        art("120b", "UCMJ Art. 120b", "Rape/Sexual Assault of Child", "Rape and sexual assault of a child under 16", "Sexual Offenses", &["Chat", "Email", "Mobile", "Media", "Browser"], Some("Life imprisonment (rape of child under 12)"), None),
        art("120c", "UCMJ Art. 120c", "Other Sexual Misconduct", "Indecent viewing, recording, broadcasting; forcible pandering; indecent exposure", "Sexual Offenses", &["Media", "Mobile", "Chat"], Some("Dishonorable discharge, 7 years"), None),

        // ── Property / Financial Offenses ──
        art("121", "UCMJ Art. 121", "Larceny", "Larceny and wrongful appropriation of property", "Property Crime", &["Financial"], Some("Dishonorable discharge, 10 years"), None),
        art("121a", "UCMJ Art. 121a", "Receiving Stolen Property", "Knowingly receiving stolen property", "Property Crime", &["Financial"], Some("Dishonorable discharge, 7 years"), None),
        art("122", "UCMJ Art. 122", "Robbery", "Robbery — taking property from person by force or violence", "Property Crime", &[], Some("Dishonorable discharge, 15 years"), None),
        art("122a", "UCMJ Art. 122a", "Receiving Stolen Property", "Receiving stolen property with knowledge", "Property Crime", &["Financial"], Some("Dishonorable discharge, 7 years"), None),
        art("123", "UCMJ Art. 123", "Government Computer Offenses", "Offenses concerning Government computers — unauthorized access, damage, or obtaining information", "Computer Crime", &["Network", "Timeline", "Registry", "Browser"], Some("Dishonorable discharge, 10 years"), Some("Military equivalent of CFAA — critical for CI investigations")),
        art("123a", "UCMJ Art. 123a", "Bad Check", "Making, drawing, or uttering check, draft, or order without sufficient funds", "Financial Crime", &["Financial", "Documents"], Some("Dishonorable discharge, 5 years"), None),
        art("124", "UCMJ Art. 124", "Bribery", "Bribery of a person to influence official actions", "Financial Crime", &["Financial", "Email", "Chat"], Some("Dishonorable discharge, 5 years"), None),
        art("124a", "UCMJ Art. 124a", "Bribery — Public Officials", "Bribery of public officials and witnesses", "Financial Crime", &["Financial", "Email", "Chat"], Some("Dishonorable discharge, 15 years"), None),
        art("124b", "UCMJ Art. 124b", "Graft", "Graft — asking, accepting, or receiving anything of value for performing duties", "Financial Crime", &["Financial", "Email"], Some("Dishonorable discharge, 5 years"), None),
        art("125", "UCMJ Art. 125", "Kidnapping", "Kidnapping — wrongful seizure and detention of a person", "Crimes Against Persons", &["Chat", "Mobile", "Email"], Some("Life imprisonment"), None),
        art("126", "UCMJ Art. 126", "Arson", "Arson and burning property with intent to defraud", "Property Crime", &[], Some("Dishonorable discharge, 20 years"), None),
        art("127", "UCMJ Art. 127", "Extortion", "Extortion — communicating threats to obtain anything of value", "Threats & Extortion", &["Chat", "Email", "Mobile"], Some("Dishonorable discharge, 10 years"), None),
        art("128", "UCMJ Art. 128", "Assault", "Assault — attempt or offer with force or violence to do bodily harm", "Crimes Against Persons", &[], Some("Dishonorable discharge, 10 years (aggravated)"), None),
        art("128a", "UCMJ Art. 128a", "Maiming", "Intentional infliction of injury that disfigures or disables", "Crimes Against Persons", &[], Some("Dishonorable discharge, 20 years"), None),
        art("128b", "UCMJ Art. 128b", "Domestic Violence", "Domestic violence — assault of intimate partner or family member", "Domestic Violence", &["Chat", "Mobile", "Email"], Some("Dishonorable discharge, 10 years"), None),
        art("129", "UCMJ Art. 129", "Burglary", "Burglary and unlawful entry", "Property Crime", &[], Some("Dishonorable discharge, 10 years"), None),
        art("130", "UCMJ Art. 130", "Stalking", "Stalking — course of conduct directed at specific person causing reasonable fear", "Domestic Violence", &["Mobile", "Chat", "Email", "Network", "Browser"], Some("Dishonorable discharge, 5 years"), None),
        art("131", "UCMJ Art. 131", "Perjury", "Perjury — false statement under oath in judicial proceeding", "Obstruction", &["Documents"], Some("Dishonorable discharge, 5 years"), None),
        art("131a", "UCMJ Art. 131a", "Subornation of Perjury", "Inducing another to commit perjury", "Obstruction", &["Chat", "Email"], Some("Dishonorable discharge, 5 years"), None),
        art("131b", "UCMJ Art. 131b", "Obstruction of Justice", "Obstructing justice — impeding investigation or judicial proceeding", "Obstruction", &["Timeline", "Registry", "Documents"], Some("Dishonorable discharge, 5 years"), None),
        art("131c", "UCMJ Art. 131c", "Misprision of Serious Offense", "Concealing knowledge of a serious offense", "Obstruction", &[], Some("Bad-conduct discharge, 3 years"), None),
        art("131d", "UCMJ Art. 131d", "Wrongful Refusal to Testify", "Refusal to testify before court-martial or board of officers", "Obstruction", &[], Some("Dishonorable discharge, 5 years"), None),
        art("131e", "UCMJ Art. 131e", "Preventing Seizure of Property", "Prevention of authorized seizure of property", "Obstruction", &[], Some("Bad-conduct discharge, 1 year"), None),
        art("131f", "UCMJ Art. 131f", "Noncompliance — Procedural Rules", "Noncompliance with procedural rules", "Obstruction", &[], Some("Bad-conduct discharge, 6 months"), None),
        art("131g", "UCMJ Art. 131g", "Interference — Administrative Proceeding", "Wrongful interference with adverse administrative proceeding", "Obstruction", &["Email", "Chat"], Some("Bad-conduct discharge, 1 year"), None),
        art("132", "UCMJ Art. 132", "Retaliation", "Retaliation against person for reporting criminal offense or making protected communication", "Obstruction", &["Email", "Chat", "Mobile"], Some("Dishonorable discharge, 10 years"), None),
        art("133", "UCMJ Art. 133", "Conduct Unbecoming", "Conduct unbecoming an officer and a gentleman", "Military Discipline", &["Chat", "Email", "Mobile"], Some("Dismissal"), None),
        art("134", "UCMJ Art. 134", "General Article", "Conduct prejudicial to good order and discipline or service-discrediting conduct", "General Article (Art. 134)", &["Chat", "Email", "Mobile", "Media", "Browser"], Some("Varies by specific offense"), Some("Catch-all article — many offenses charged under 134 including indecent language, fraternization, wrongful cohabitation")),

        // ── Specific Article 134 Offenses ──
        art("134-adultery", "UCMJ Art. 134 — Adultery", "Adultery", "Extramarital sexual conduct (MCM ¶62)", "General Article (Art. 134)", &["Chat", "Email", "Mobile"], Some("Dishonorable discharge, 1 year"), None),
        art("134-cp", "UCMJ Art. 134 — Child Pornography", "Child Pornography Possession", "Possession, distribution, or production of child pornography", "Child Exploitation", &["Media", "Browser", "Network", "Cloud", "Mobile"], Some("Dishonorable discharge, 10 years"), None),
        art("134-threats", "UCMJ Art. 134 — Communicating Threats", "Communicating Threats", "Communicating a threat to injure person, property, or reputation", "Threats & Extortion", &["Chat", "Email", "Mobile"], Some("Dishonorable discharge, 3 years"), None),
        art("134-enemy", "UCMJ Art. 134 — Enemy Conduct", "Conduct With Enemy", "Conduct with or concerning the enemy not amounting to aiding the enemy", "National Security", &["Chat", "Email", "Network"], Some("As court-martial may direct"), None),
        art("134-disloyal", "UCMJ Art. 134 — Disloyal Statements", "Disloyal Statements", "Making disloyal statements with intent to promote disloyalty among troops", "Military Discipline", &["Chat", "Email"], Some("Dishonorable discharge, 3 years"), None),
        art("134-drugs", "UCMJ Art. 134 — Drug Distribution (Off-Post)", "Drug Distribution (Off-Post)", "Distribution or manufacture of controlled substance off-post", "Controlled Substances", &["Chat", "Mobile", "Financial"], Some("Dishonorable discharge, 15 years"), None),
        art("134-drunk", "UCMJ Art. 134 — Drunk/Disorderly", "Drunk and Disorderly Conduct", "Drunk and disorderly conduct", "Military Discipline", &[], Some("Bad-conduct discharge, 6 months"), None),
        art("134-frat", "UCMJ Art. 134 — Fraternization", "Fraternization", "Fraternization between officer and enlisted member", "General Article (Art. 134)", &["Chat", "Email", "Mobile"], Some("Dismissal, 2 years"), None),
        art("134-gambling", "UCMJ Art. 134 — Gambling", "Gambling with Subordinate", "Gambling with subordinate", "General Article (Art. 134)", &["Financial"], Some("Bad-conduct discharge, 3 months"), None),
        art("134-language", "UCMJ Art. 134 — Indecent Language", "Indecent Language", "Use of indecent language communicated to another", "General Article (Art. 134)", &["Chat", "Email", "Mobile"], Some("Bad-conduct discharge, 6 months"), None),
        art("134-recording", "UCMJ Art. 134 — Indecent Recording", "Indecent Recording", "Indecent recording or broadcasting without consent", "Sexual Offenses", &["Media", "Mobile"], Some("Dishonorable discharge, 5 years"), None),
        art("134-misprision", "UCMJ Art. 134 — Misprision of Felony", "Misprision of Felony", "Concealing knowledge of a felony", "Obstruction", &[], Some("Bad-conduct discharge, 3 years"), None),
        art("134-obstruction", "UCMJ Art. 134 — Obstruction of Justice", "Obstruction of Justice (Art. 134)", "Obstruction of justice charged under the general article", "Obstruction", &["Timeline", "Documents"], Some("Dishonorable discharge, 5 years"), None),
        art("134-pandering", "UCMJ Art. 134 — Pandering", "Pandering and Prostitution", "Pandering, prostitution, or compelling prostitution", "Sexual Offenses", &["Chat", "Mobile", "Browser", "Financial"], Some("Dishonorable discharge, 10 years (compelling)"), None),
        art("134-soliciting", "UCMJ Art. 134 — Soliciting Offense", "Soliciting Offense", "Soliciting another to commit an offense (Art. 134 variant)", "General Article (Art. 134)", &["Chat", "Email"], Some("As court-martial may direct"), None),
        art("134-stalking-legacy", "UCMJ Art. 134 — Stalking (Legacy)", "Stalking (Pre-Art 130)", "Stalking charged under Art. 134 for pre-2019 cases", "Domestic Violence", &["Mobile", "Chat", "Email"], Some("Dishonorable discharge, 3 years"), None),
        art("134-cohabitation", "UCMJ Art. 134 — Wrongful Cohabitation", "Wrongful Cohabitation", "Wrongful cohabitation with a person not their spouse", "General Article (Art. 134)", &[], Some("Bad-conduct discharge, 4 months"), None),

        // ── National Security Articles ──
        art("104", "UCMJ Art. 104", "Aiding the Enemy", "Aiding, harboring, or protecting the enemy", "National Security", &["Network", "Chat", "Email", "Documents"], Some("Death or life imprisonment"), None),
        art("104a", "UCMJ Art. 104a", "Misconduct as Prisoner", "Misconduct while prisoner of war", "National Security", &[], Some("As court-martial may direct"), None),
        art("104b", "UCMJ Art. 104b", "Spying", "Acting as a spy in time of war", "National Security", &["Network", "Documents", "Email"], Some("Death"), None),
        art("106", "UCMJ Art. 106", "Lurking as Spy", "Lurking as a spy or acting as a spy in or about military installations", "National Security", &["Network", "Documents", "Email"], Some("Death or life imprisonment"), None),
        art("106a", "UCMJ Art. 106a", "Espionage", "Espionage — communicating, delivering, or transmitting national defense information", "National Security", &["Network", "Documents", "Email", "Cloud", "Registry"], Some("Death or life imprisonment"), Some("Critical for Army CI investigations")),
    ]
}
