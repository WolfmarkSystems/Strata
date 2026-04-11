//! USC federal criminal statutes — Titles 18, 21, 26, 31, 47.

use crate::schema::{ChargeEntry, ChargeSet, ChargeSeverity};

#[allow(clippy::too_many_arguments)]
fn usc(
    title: u32,
    section: &str,
    citation: &str,
    short_title: &str,
    desc: &str,
    category: &str,
    tags: &[&str],
    severity: ChargeSeverity,
    penalty: Option<&str>,
) -> ChargeEntry {
    ChargeEntry {
        id: 0,
        code_set: ChargeSet::USC,
        title: Some(title),
        section: section.to_string(),
        subsection: None,
        citation: citation.to_string(),
        short_title: short_title.to_string(),
        description: desc.to_string(),
        category: category.to_string(),
        artifact_tags: tags.iter().map(|s| s.to_string()).collect(),
        severity,
        state_code: None,
        max_penalty: penalty.map(String::from),
        notes: None,
    }
}

/// Returns all federal USC charges for database seeding.
pub fn federal_charges() -> Vec<ChargeEntry> {
    use ChargeSeverity::*;
    vec![
        // ── Title 18 Chapter 1 — General Provisions ──
        usc(18, "2", "18 U.S.C. § 2", "Principals", "Aiding and abetting — anyone who commits, aids, abets, counsels, commands, induces or procures commission of offense is punishable as a principal", "General Provisions", &[], Felony, None),
        usc(18, "3", "18 U.S.C. § 3", "Accessory After the Fact", "Whoever, knowing that an offense has been committed, assists the offender to hinder or prevent apprehension, trial or punishment", "General Provisions", &[], Felony, Some("Half the maximum for the principal offense")),
        usc(18, "371", "18 U.S.C. § 371", "Conspiracy", "Conspiracy to commit offense or defraud the United States", "General Provisions", &["Email", "Chat", "Network"], Felony, Some("5 years")),

        // ── Title 18 Chapter 10 — Biological Weapons ──
        usc(18, "175", "18 U.S.C. § 175", "Biological Weapons", "Development, production, stockpiling, transfer or possession of biological agents for use as a weapon", "Weapons of Mass Destruction", &["Network", "Email", "Documents"], Felony, Some("Life imprisonment")),
        usc(18, "175b", "18 U.S.C. § 175b", "Biological Weapons — Restricted Persons", "Possession of biological agents or toxins by restricted persons", "Weapons of Mass Destruction", &[], Felony, Some("10 years")),

        // ── Title 18 Chapter 11B — Chemical Weapons ──
        usc(18, "229", "18 U.S.C. § 229", "Chemical Weapons", "Use, development, production, acquisition, retention or transfer of chemical weapons", "Weapons of Mass Destruction", &["Network", "Email", "Documents"], Felony, Some("Life imprisonment")),

        // ── Title 18 Chapter 11C — Terrorism ──
        usc(18, "2331", "18 U.S.C. § 2331", "Terrorism Definitions", "Definitions of domestic and international terrorism", "Terrorism", &["Network", "Email", "Chat"], InfrastructureOffense, None),
        usc(18, "2332", "18 U.S.C. § 2332", "Murder of US Nationals Abroad", "Killing or attempted killing of US nationals outside the United States", "Terrorism", &["Network", "Email", "Chat"], Felony, Some("Life imprisonment or death")),
        usc(18, "2332a", "18 U.S.C. § 2332a", "Weapons of Mass Destruction", "Use, threat or attempt to use weapons of mass destruction", "Terrorism", &["Network", "Email", "Chat", "Documents"], Felony, Some("Life imprisonment or death")),
        usc(18, "2332b", "18 U.S.C. § 2332b", "Terrorism Transcending National Boundaries", "Acts of terrorism transcending national boundaries", "Terrorism", &["Network", "Email", "Chat"], Felony, Some("Life imprisonment or death")),
        usc(18, "2339A", "18 U.S.C. § 2339A", "Material Support to Terrorists", "Providing material support or resources knowing they will be used for terrorism", "Terrorism", &["Financial", "Network", "Email", "Chat"], Felony, Some("15 years (life if death results)")),
        usc(18, "2339B", "18 U.S.C. § 2339B", "Material Support to Terrorist Organizations", "Providing material support or resources to designated foreign terrorist organizations", "Terrorism", &["Financial", "Network", "Email", "Chat"], Felony, Some("20 years (life if death results)")),
        usc(18, "2339C", "18 U.S.C. § 2339C", "Financing of Terrorism", "Providing or collecting funds with intent to carry out terrorism", "Terrorism", &["Financial", "Network", "Email"], Felony, Some("20 years")),
        usc(18, "2339D", "18 U.S.C. § 2339D", "Military Training from Terrorists", "Receiving military-type training from a foreign terrorist organization", "Terrorism", &["Network", "Email", "Chat"], Felony, Some("10 years")),

        // ── Title 18 Chapter 25 — Counterfeiting and Forgery ──
        usc(18, "470", "18 U.S.C. § 470", "Counterfeit Obligations/Securities", "Counterfeiting of obligations or securities of the United States", "Counterfeiting & Forgery", &["Documents", "Financial"], Felony, Some("25 years")),
        usc(18, "471", "18 U.S.C. § 471", "US Obligations or Securities", "Falsely making, forging, counterfeiting or altering obligations or securities of the United States", "Counterfeiting & Forgery", &["Documents", "Financial"], Felony, Some("20 years")),
        usc(18, "1028", "18 U.S.C. § 1028", "Fraud — Identification Documents", "Fraud and related activity in connection with identification documents, authentication features, and information", "Identity Theft & Fraud", &["Documents", "Network", "Financial"], Felony, Some("15 years")),
        usc(18, "1028A", "18 U.S.C. § 1028A", "Aggravated Identity Theft", "Use of stolen identity during commission of specified felony — mandatory consecutive 2-year term", "Identity Theft & Fraud", &["Documents", "Network", "Financial", "Email"], Felony, Some("Mandatory 2 years consecutive")),
        usc(18, "1029", "18 U.S.C. § 1029", "Fraud — Access Devices", "Fraud and related activity in connection with access devices (credit cards, account numbers)", "Identity Theft & Fraud", &["Financial", "Network", "Browser"], Felony, Some("15 years")),

        // ── Title 18 Chapter 31 — Embezzlement and Theft ──
        usc(18, "641", "18 U.S.C. § 641", "Public Money/Property/Records", "Theft or embezzlement of public money, property, or records", "Theft & Embezzlement", &["Documents", "Financial"], Felony, Some("10 years")),
        usc(18, "666", "18 U.S.C. § 666", "Theft from Federal Programs", "Theft or embezzlement from programs receiving federal funds", "Theft & Embezzlement", &["Financial", "Documents"], Felony, Some("10 years")),

        // ── Title 18 Chapter 41 — Extortion and Threats ──
        usc(18, "875", "18 U.S.C. § 875", "Interstate Threats/Extortion", "Interstate threats and extortion including cyberstalking and threats via electronic communication", "Threats & Extortion", &["Email", "Chat", "Network"], Felony, Some("20 years")),
        usc(18, "876", "18 U.S.C. § 876", "Mailing Threatening Communications", "Mailing threatening communications with intent to extort", "Threats & Extortion", &["Email", "Chat"], Felony, Some("20 years")),
        usc(18, "880", "18 U.S.C. § 880", "Receiving Proceeds of Extortion", "Receiving proceeds of extortion", "Threats & Extortion", &["Financial"], Felony, Some("3 years")),

        // ── Title 18 Chapter 44 — Firearms ──
        usc(18, "922", "18 U.S.C. § 922", "Unlawful Firearms Acts", "Unlawful acts — prohibited persons, straw purchases, interstate firearms offenses", "Firearms", &["Documents", "Chat", "Browser"], Felony, Some("10 years")),
        usc(18, "924", "18 U.S.C. § 924", "Firearms Penalties", "Enhanced penalties for using firearm in crime of violence or drug trafficking", "Firearms", &[], Felony, Some("Life imprisonment")),

        // ── Title 18 Chapter 46 — Forfeiture ──
        usc(18, "981", "18 U.S.C. § 981", "Civil Forfeiture", "Civil forfeiture of property involved in certain federal offenses", "Forfeiture", &["Financial"], InfrastructureOffense, None),
        usc(18, "982", "18 U.S.C. § 982", "Criminal Forfeiture", "Criminal forfeiture of property derived from or used in commission of offenses", "Forfeiture", &["Financial"], InfrastructureOffense, None),

        // ── Title 18 Chapter 47 — Fraud and False Statements ──
        usc(18, "1001", "18 U.S.C. § 1001", "False Statements", "Knowingly making false statements to federal investigators or agencies", "Fraud & False Statements", &["Email", "Documents"], Felony, Some("5 years (8 years for terrorism)")),
        usc(18, "1030", "18 U.S.C. § 1030", "Computer Fraud and Abuse (CFAA)", "Unauthorized access to protected computers, exceeding authorized access, trafficking passwords, causing damage", "Computer Crime", &["Network", "Timeline", "Registry", "Browser"], Felony, Some("10 years (20 years second offense)")),
        usc(18, "1031", "18 U.S.C. § 1031", "Major Fraud Against US", "Major fraud against the United States exceeding $1 million", "Fraud & False Statements", &["Financial", "Documents", "Email"], Felony, Some("10 years")),
        usc(18, "1341", "18 U.S.C. § 1341", "Mail Fraud", "Scheme to defraud using postal service or private carrier", "Fraud & False Statements", &["Email", "Documents", "Financial"], Felony, Some("20 years (30 years for financial institution)")),
        usc(18, "1343", "18 U.S.C. § 1343", "Wire Fraud", "Scheme to defraud using wire, radio, or television communication", "Fraud & False Statements", &["Email", "Chat", "Network", "Financial"], Felony, Some("20 years (30 years for financial institution)")),
        usc(18, "1344", "18 U.S.C. § 1344", "Bank Fraud", "Scheme to defraud a financial institution", "Fraud & False Statements", &["Financial", "Documents", "Email"], Felony, Some("30 years")),
        usc(18, "1347", "18 U.S.C. § 1347", "Health Care Fraud", "Scheme to defraud health care benefit program", "Fraud & False Statements", &["Financial", "Documents", "Email"], Felony, Some("10 years (life if serious injury/death)")),
        usc(18, "1349", "18 U.S.C. § 1349", "Attempt and Conspiracy (Fraud)", "Attempt or conspiracy to commit mail fraud, wire fraud, bank fraud, or health care fraud", "Fraud & False Statements", &["Email", "Chat", "Financial"], Felony, Some("Same as substantive offense")),
        usc(18, "1350", "18 U.S.C. § 1350", "Securities Fraud", "False certifications of periodic financial reports by corporate officers", "Fraud & False Statements", &["Financial", "Documents", "Email"], Felony, Some("20 years")),

        // ── Title 18 Chapter 50A — Genocide ──
        usc(18, "1091", "18 U.S.C. § 1091", "Genocide", "Genocide — killing members of a group with intent to destroy in whole or in part", "Crimes Against Humanity", &[], Felony, Some("Life imprisonment or death")),

        // ── Title 18 Chapter 55 — Kidnapping ──
        usc(18, "1201", "18 U.S.C. § 1201", "Kidnapping", "Federal kidnapping — interstate or international", "Crimes Against Persons", &["Mobile", "Chat", "Email"], Felony, Some("Life imprisonment or death")),
        usc(18, "1203", "18 U.S.C. § 1203", "Hostage Taking", "Seizing or detaining a person as hostage", "Crimes Against Persons", &["Mobile", "Chat", "Email"], Felony, Some("Life imprisonment or death")),

        // ── Title 18 Chapter 63 — Mail Fraud / Money Laundering ──
        usc(18, "1956", "18 U.S.C. § 1956", "Money Laundering", "Laundering of monetary instruments — conducting financial transactions with proceeds of unlawful activity", "Money Laundering", &["Financial", "Network", "Email"], Felony, Some("20 years")),
        usc(18, "1957", "18 U.S.C. § 1957", "Monetary Transactions — Criminal Property", "Engaging in monetary transactions in property derived from specified unlawful activity exceeding $10,000", "Money Laundering", &["Financial", "Email", "Documents"], Felony, Some("10 years")),

        // ── Title 18 Chapter 65 — Malicious Mischief ──
        usc(18, "1362", "18 U.S.C. § 1362", "Communication System Sabotage", "Willful destruction of communication lines, stations, or systems", "Infrastructure Crime", &["Network"], Felony, Some("10 years")),

        // ── Title 18 Chapter 71 — Obscenity ──
        usc(18, "1460", "18 U.S.C. § 1460", "Possession — Obscene Matter for Sale", "Possession with intent to sell or distribute obscene matter on federal property", "Obscenity", &["Media", "Browser"], Felony, Some("5 years")),
        usc(18, "1461", "18 U.S.C. § 1461", "Mailing Obscene Matter", "Mailing obscene or crime-inciting matter", "Obscenity", &["Media", "Email"], Felony, Some("5 years")),
        usc(18, "1462", "18 U.S.C. § 1462", "Importing/Transporting Obscene Matter", "Importing or transporting obscene matters in interstate or foreign commerce", "Obscenity", &["Media", "Network"], Felony, Some("5 years")),
        usc(18, "1466A", "18 U.S.C. § 1466A", "Obscene Visual Representations — Child Abuse", "Production, distribution, receipt or possession of obscene visual representations of sexual abuse of children", "Child Exploitation", &["Media", "Browser", "Network", "Cloud"], Felony, Some("20 years (30 years if prior)")),

        // ── Title 18 Chapter 73 — Obstruction of Justice ──
        usc(18, "1503", "18 U.S.C. § 1503", "Obstruction — Officer or Juror", "Influencing or injuring officer, juror, or witness", "Obstruction of Justice", &["Email", "Chat"], Felony, Some("10 years")),
        usc(18, "1512", "18 U.S.C. § 1512", "Witness Tampering", "Tampering with a witness, victim, or informant — intimidation, threat, corrupt persuasion", "Obstruction of Justice", &["Email", "Chat", "Mobile"], Felony, Some("20 years (30 years if physical force)")),
        usc(18, "1519", "18 U.S.C. § 1519", "Destruction of Records", "Destruction, alteration, or falsification of records in federal investigations or bankruptcy", "Obstruction of Justice", &["Timeline", "Registry", "Documents"], Felony, Some("20 years")),
        usc(18, "1621", "18 U.S.C. § 1621", "Perjury", "Perjury — false statement under oath in judicial proceeding", "Obstruction of Justice", &["Documents", "Email"], Felony, Some("5 years")),

        // ── Title 18 Chapter 77 — Peonage, Slavery, Trafficking ──
        usc(18, "1581", "18 U.S.C. § 1581", "Peonage", "Holding or returning a person to peonage", "Human Trafficking", &["Chat", "Email", "Financial"], Felony, Some("20 years")),
        usc(18, "1589", "18 U.S.C. § 1589", "Forced Labor", "Obtaining labor or services through force, threats, or abuse of legal process", "Human Trafficking", &["Chat", "Email", "Financial"], Felony, Some("20 years (life if death/kidnapping)")),
        usc(18, "1590", "18 U.S.C. § 1590", "Trafficking — Peonage/Slavery", "Trafficking with respect to peonage, slavery, involuntary servitude, or forced labor", "Human Trafficking", &["Chat", "Email", "Financial", "Mobile"], Felony, Some("20 years (life if death/kidnapping)")),
        usc(18, "1591", "18 U.S.C. § 1591", "Sex Trafficking", "Sex trafficking of children or by force, fraud, or coercion", "Human Trafficking", &["Chat", "Email", "Mobile", "Browser", "Media"], Felony, Some("Life imprisonment (victim under 14)")),
        usc(18, "1594", "18 U.S.C. § 1594", "Trafficking — General Provisions", "Attempt, conspiracy, and forfeiture for trafficking offenses", "Human Trafficking", &["Chat", "Email", "Financial"], Felony, Some("Same as substantive offense")),

        // ── Title 18 Chapter 90A ──
        usc(18, "1841", "18 U.S.C. § 1841", "Protection of Unborn Children", "Enhanced penalties when offense causes death or bodily injury to unborn child", "Crimes Against Persons", &[], Felony, Some("Same as underlying offense")),

        // ── Title 18 Chapter 95 — Racketeering ──
        usc(18, "1961", "18 U.S.C. § 1961", "RICO Definitions", "Definitions for racketeer influenced and corrupt organizations", "Racketeering (RICO)", &["Financial", "Email", "Chat"], InfrastructureOffense, None),
        usc(18, "1962", "18 U.S.C. § 1962", "RICO Prohibited Activities", "Operating enterprise through pattern of racketeering activity", "Racketeering (RICO)", &["Financial", "Email", "Chat", "Network"], Felony, Some("20 years per count (life if predicate carries life)")),
        usc(18, "1963", "18 U.S.C. § 1963", "RICO Criminal Penalties", "Criminal penalties and forfeiture for RICO violations", "Racketeering (RICO)", &["Financial"], InfrastructureOffense, None),

        // ── Title 18 Chapter 109A — Sexual Abuse ──
        usc(18, "2241", "18 U.S.C. § 2241", "Aggravated Sexual Abuse", "Sexual act by force, threat, or rendering unconscious/drugged", "Sexual Assault", &["Media", "Chat", "Mobile"], Felony, Some("Life imprisonment")),
        usc(18, "2242", "18 U.S.C. § 2242", "Sexual Abuse", "Sexual act by threatening or placing in fear", "Sexual Assault", &["Media", "Chat", "Mobile"], Felony, Some("20 years")),
        usc(18, "2243", "18 U.S.C. § 2243", "Sexual Abuse of Minor or Ward", "Sexual act with minor (12-15) or ward in custody/supervision", "Sexual Assault", &["Chat", "Mobile", "Media"], Felony, Some("15 years")),
        usc(18, "2244", "18 U.S.C. § 2244", "Abusive Sexual Contact", "Sexual contact without consent", "Sexual Assault", &["Chat", "Mobile"], Felony, Some("10 years")),
        usc(18, "2246", "18 U.S.C. § 2246", "Sexual Abuse Definitions", "Definitions for Chapter 109A sexual abuse offenses", "Sexual Assault", &[], InfrastructureOffense, None),

        // ── Title 18 Chapter 110 — Child Exploitation (CRITICAL) ──
        usc(18, "2251", "18 U.S.C. § 2251", "Sexual Exploitation of Children — Production", "Employing, using, persuading, inducing, enticing, or coercing a minor to engage in sexually explicit conduct for visual depiction", "Child Exploitation", &["Media", "Network", "Cloud", "Mobile", "Chat"], Felony, Some("30 years (mandatory minimum 15 years)")),
        usc(18, "2251A", "18 U.S.C. § 2251A", "Selling or Buying of Children", "Selling or buying of children for production of sexually explicit material", "Child Exploitation", &["Chat", "Financial", "Mobile"], Felony, Some("30 years to life")),
        usc(18, "2252", "18 U.S.C. § 2252", "Sexual Exploitation of Minors — Possession/Distribution", "Possession, distribution, receipt, or transportation of material involving sexual exploitation of minors", "Child Exploitation", &["Media", "Network", "Cloud", "Mobile", "Browser", "Chat"], Felony, Some("20 years (mandatory minimum 5 years)")),
        usc(18, "2252A", "18 U.S.C. § 2252A", "Child Pornography", "Material constituting or containing child pornography — possession, distribution, production", "Child Exploitation", &["Media", "Network", "Cloud", "Mobile", "Browser", "Chat"], Felony, Some("20 years (mandatory minimum 5 years)")),
        usc(18, "2256", "18 U.S.C. § 2256", "Child Exploitation Definitions", "Definitions for Chapter 110 — minor, sexually explicit conduct, visual depiction, computer", "Child Exploitation", &[], InfrastructureOffense, None),
        usc(18, "2258A", "18 U.S.C. § 2258A", "ESI Provider Reporting", "Mandatory reporting requirements for electronic service providers regarding CSAM", "Child Exploitation", &["Network"], InfrastructureOffense, None),
        usc(18, "2260", "18 U.S.C. § 2260", "Production for Import", "Production of sexually explicit depictions of a minor for importation into the United States", "Child Exploitation", &["Media", "Network", "Cloud"], Felony, Some("30 years")),

        // ── Title 18 Chapter 110A — Domestic Violence and Stalking ──
        usc(18, "2261", "18 U.S.C. § 2261", "Interstate Domestic Violence", "Interstate domestic violence — travel with intent to injure, harass, or intimidate intimate partner", "Domestic Violence & Stalking", &["Mobile", "Chat", "Email"], Felony, Some("Life imprisonment (if death results)")),
        usc(18, "2261A", "18 U.S.C. § 2261A", "Stalking", "Interstate stalking — course of conduct placing person in reasonable fear of death or serious bodily injury", "Domestic Violence & Stalking", &["Email", "Chat", "Mobile", "Network", "Browser"], Felony, Some("5 years (life if death results)")),
        usc(18, "2262", "18 U.S.C. § 2262", "Interstate Violation of Protection Order", "Interstate violation of protective order", "Domestic Violence & Stalking", &["Mobile", "Chat"], Felony, Some("Life imprisonment (if death results)")),

        // ── Title 18 Chapter 113 — Stolen Property ──
        usc(18, "2314", "18 U.S.C. § 2314", "Transportation of Stolen Goods", "Interstate or foreign transportation of stolen goods, securities, or money exceeding $5,000", "Stolen Property", &["Financial", "Documents"], Felony, Some("10 years")),
        usc(18, "2315", "18 U.S.C. § 2315", "Receipt of Stolen Goods", "Sale or receipt of stolen goods, securities, or money transported interstate", "Stolen Property", &["Financial", "Documents"], Felony, Some("10 years")),

        // ── Title 18 Chapter 113B — Terrorism (Domestic) ──
        usc(18, "2332f", "18 U.S.C. § 2332f", "Bombings — Public Places", "Bombings of places of public use, government facilities, infrastructure, or transport systems", "Terrorism", &["Network", "Email", "Chat"], Felony, Some("Life imprisonment or death")),
        usc(18, "2332g", "18 U.S.C. § 2332g", "Missile Systems — Aircraft", "Missile systems designed to destroy aircraft", "Terrorism", &[], Felony, Some("25 years")),
        usc(18, "2332h", "18 U.S.C. § 2332h", "Radiological Dispersal Devices", "Production, transfer, or use of radiological dispersal devices", "Terrorism", &[], Felony, Some("Life imprisonment")),

        // ── Title 18 Chapter 119 — Wire/Electronic Interception ──
        usc(18, "2511", "18 U.S.C. § 2511", "Interception of Communications", "Unauthorized interception and disclosure of wire, oral, or electronic communications", "Electronic Surveillance", &["Network", "Mobile", "Email"], Felony, Some("5 years")),
        usc(18, "2512", "18 U.S.C. § 2512", "Interception Devices", "Manufacture, distribution, possession, and advertising of wire/electronic communication interception devices", "Electronic Surveillance", &["Network"], Felony, Some("5 years")),

        // ── Title 18 Chapter 121 — Stored Communications ──
        usc(18, "2701", "18 U.S.C. § 2701", "Unlawful Access to Stored Communications", "Intentionally accessing electronic communication service facility without authorization", "Electronic Surveillance", &["Network", "Email", "Cloud"], Felony, Some("5 years")),
        usc(18, "2702", "18 U.S.C. § 2702", "Voluntary Disclosure", "Prohibited voluntary disclosure of customer communications or records by service provider", "Electronic Surveillance", &["Email", "Cloud"], Misdemeanor, None),
        usc(18, "2703", "18 U.S.C. § 2703", "Required Disclosure", "Required disclosure of customer communications or records — warrants, subpoenas, court orders", "Electronic Surveillance", &["Email", "Cloud"], InfrastructureOffense, None),

        // ── Title 18 Chapter 123 ──
        usc(18, "2721", "18 U.S.C. § 2721", "DMV Personal Information", "Prohibition on release and use of certain personal information from state motor vehicle records", "Privacy", &["Documents"], Misdemeanor, Some("$5,000 fine")),

        // ── Title 21 — Controlled Substances ──
        usc(21, "841", "21 U.S.C. § 841", "Drug Manufacturing/Distribution", "Manufacture, distribution, or dispensing of controlled substances", "Controlled Substances", &["Chat", "Financial", "Mobile", "Email"], Felony, Some("Life imprisonment (depending on schedule/quantity)")),
        usc(21, "843", "21 U.S.C. § 843", "Prohibited Acts — Communication Facility", "Use of communication facility in committing drug felony", "Controlled Substances", &["Chat", "Mobile", "Email", "Network"], Felony, Some("4 years")),
        usc(21, "846", "21 U.S.C. § 846", "Drug Conspiracy", "Attempt and conspiracy to violate controlled substance laws", "Controlled Substances", &["Chat", "Financial", "Mobile", "Email"], Felony, Some("Same as substantive offense")),
        usc(21, "848", "21 U.S.C. § 848", "Continuing Criminal Enterprise", "Continuing criminal enterprise (CCE) — kingpin statute", "Controlled Substances", &["Financial", "Chat", "Mobile", "Network"], Felony, Some("20 years to life (mandatory minimum)")),
        usc(21, "952", "21 U.S.C. § 952", "Import of Controlled Substances", "Importation of controlled substances into the United States", "Controlled Substances", &["Financial", "Network"], Felony, Some("20 years")),
        usc(21, "960", "21 U.S.C. § 960", "Drug Trafficking Penalties", "Import/export penalties for controlled substance trafficking", "Controlled Substances", &["Financial", "Network"], Felony, Some("Life imprisonment (depending on substance/quantity)")),

        // ── Title 26 — Internal Revenue Code ──
        usc(26, "7201", "26 U.S.C. § 7201", "Tax Evasion", "Willful attempt to evade or defeat any tax imposed by the Internal Revenue Code", "Tax Crimes", &["Financial", "Email", "Documents"], Felony, Some("5 years and $250,000 fine")),
        usc(26, "7202", "26 U.S.C. § 7202", "Failure to Collect/Pay Tax", "Willful failure to collect or pay over tax", "Tax Crimes", &["Financial", "Documents"], Felony, Some("5 years")),
        usc(26, "7206", "26 U.S.C. § 7206", "Tax Fraud/False Statements", "Fraud and false statements in tax matters", "Tax Crimes", &["Financial", "Documents", "Email"], Felony, Some("3 years")),
        usc(26, "7212", "26 U.S.C. § 7212", "Interference with IRS", "Attempts to interfere with administration of internal revenue laws", "Tax Crimes", &["Email", "Documents"], Felony, Some("3 years")),

        // ── Title 31 — Money and Finance ──
        usc(31, "5313", "31 U.S.C. § 5313", "Currency Transaction Reports", "Reports on domestic coins and currency transactions exceeding $10,000", "Financial Crimes", &["Financial"], InfrastructureOffense, None),
        usc(31, "5316", "31 U.S.C. § 5316", "CMIR — Export/Import Reports", "Reports on exporting and importing monetary instruments exceeding $10,000", "Financial Crimes", &["Financial", "Documents"], Felony, Some("5 years")),
        usc(31, "5324", "31 U.S.C. § 5324", "Structuring", "Structuring transactions to evade reporting requirements — breaking deposits/withdrawals to avoid CTR filings", "Financial Crimes", &["Financial", "Email", "Documents", "Browser"], Felony, Some("5 years")),
        usc(31, "5363", "31 U.S.C. § 5363", "Unlawful Internet Gambling", "Prohibition on acceptance of any financial instrument for unlawful Internet gambling", "Financial Crimes", &["Financial", "Browser", "Network"], Felony, Some("5 years")),

        // ── Title 47 — Telecommunications ──
        usc(47, "223", "47 U.S.C. § 223", "Obscene/Harassing Phone Calls", "Obscene or harassing telephone calls in interstate or international communications", "Telecommunications", &["Chat", "Mobile", "Email"], Misdemeanor, Some("2 years")),
        usc(47, "231", "47 U.S.C. § 231", "Minors Access Restriction", "Restriction of access by minors to materials commercially distributed by means of the World Wide Web", "Telecommunications", &["Browser", "Network"], Misdemeanor, Some("$50,000 fine and 6 months")),
    ]
}
