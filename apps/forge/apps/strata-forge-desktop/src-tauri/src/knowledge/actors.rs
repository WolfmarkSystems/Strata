fn s(v: &str) -> String {
    v.to_string()
}
fn sv(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

pub fn all_actors() -> Vec<super::ThreatActor> {
    vec![
        super::ThreatActor {
            name: s("APT28"), aliases: sv(&["Fancy Bear", "Sofacy", "Sednit", "STRONTIUM", "Forest Blizzard"]),
            origin: s("Russia — GRU Unit 26165"), targets: sv(&["Government", "Military", "Defense", "Media", "Energy"]),
            techniques: sv(&["T1566.001", "T1059.001", "T1003", "T1071.001", "T1078", "T1055"]),
            tools: sv(&["X-Agent", "Zebrocy", "Mimikatz", "Responder", "Koadic"]),
            description: s("Russian military intelligence (GRU) group active since at least 2004. Known for targeting NATO countries, election interference, and Olympic organizations."),
        },
        super::ThreatActor {
            name: s("APT29"), aliases: sv(&["Cozy Bear", "The Dukes", "NOBELIUM", "Midnight Blizzard"]),
            origin: s("Russia — SVR"), targets: sv(&["Government", "Think Tanks", "Technology", "Healthcare"]),
            techniques: sv(&["T1566.002", "T1195", "T1059.001", "T1003.006", "T1071.001", "T1027"]),
            tools: sv(&["Cobalt Strike", "EnvyScout", "FoggyWeb", "MagicWeb", "WellMess"]),
            description: s("Russian foreign intelligence service (SVR) group. Responsible for SolarWinds supply chain attack (2020). Known for sophisticated, patient intrusions."),
        },
        super::ThreatActor {
            name: s("Lazarus Group"), aliases: sv(&["HIDDEN COBRA", "Zinc", "Diamond Sleet", "APT38"]),
            origin: s("North Korea — RGB"), targets: sv(&["Financial", "Cryptocurrency", "Defense", "Technology"]),
            techniques: sv(&["T1566.001", "T1059", "T1003", "T1486", "T1195", "T1190"]),
            tools: sv(&["Mimikatz", "FALLCHILL", "Manuscrypt", "HOPLIGHT", "FastCash"]),
            description: s("North Korean state-sponsored group known for financial theft, cryptocurrency heists, and destructive attacks. Responsible for WannaCry ransomware and Sony Pictures hack."),
        },
        super::ThreatActor {
            name: s("FIN7"), aliases: sv(&["Carbanak", "Carbon Spider", "Sangria Tempest"]),
            origin: s("Eastern Europe / Russia"), targets: sv(&["Retail", "Hospitality", "Financial", "Restaurant"]),
            techniques: sv(&["T1566.001", "T1059.001", "T1059.005", "T1071.001", "T1003", "T1055"]),
            tools: sv(&["Cobalt Strike", "Carbanak", "GRIFFON", "BOOSTWRITE", "Mimikatz"]),
            description: s("Financially motivated group targeting payment card data. Known for sophisticated spearphishing with malicious documents and point-of-sale malware."),
        },
        super::ThreatActor {
            name: s("APT1"), aliases: sv(&["Comment Crew", "Comment Panda", "PLA Unit 61398"]),
            origin: s("China — PLA Unit 61398"), targets: sv(&["Defense", "Technology", "Aerospace", "Energy", "Telecommunications"]),
            techniques: sv(&["T1566.001", "T1059.003", "T1003", "T1005", "T1041"]),
            tools: sv(&["WEBC2", "BISCUIT", "CALENDAR", "Mimikatz"]),
            description: s("Chinese military (PLA) cyber espionage unit. One of the first APTs publicly attributed by Mandiant in 2013. Known for large-scale IP theft."),
        },
        super::ThreatActor {
            name: s("APT41"), aliases: sv(&["Winnti", "Wicked Panda", "Barium", "Brass Typhoon"]),
            origin: s("China"), targets: sv(&["Technology", "Gaming", "Healthcare", "Telecom", "Government"]),
            techniques: sv(&["T1195", "T1190", "T1059", "T1003", "T1055", "T1070"]),
            tools: sv(&["ShadowPad", "Winnti", "Cobalt Strike", "PlugX", "POISONPLUG"]),
            description: s("Chinese dual-mission group conducting both state-sponsored espionage and financially motivated operations. Known for supply chain compromises."),
        },
        super::ThreatActor {
            name: s("Sandworm"), aliases: sv(&["Voodoo Bear", "IRIDIUM", "Seashell Blizzard", "TeleBots"]),
            origin: s("Russia — GRU Unit 74455"), targets: sv(&["Energy", "Government", "Critical Infrastructure", "Ukraine"]),
            techniques: sv(&["T1190", "T1059", "T1486", "T1490", "T1070.001", "T1021"]),
            tools: sv(&["NotPetya", "BlackEnergy", "Industroyer", "Olympic Destroyer", "CaddyWiper"]),
            description: s("Russian military intelligence (GRU) group responsible for the most destructive cyberattacks in history including NotPetya and Ukrainian power grid attacks."),
        },
        super::ThreatActor {
            name: s("Turla"), aliases: sv(&["Venomous Bear", "Snake", "Uroburos", "Secret Blizzard"]),
            origin: s("Russia — FSB"), targets: sv(&["Government", "Diplomatic", "Military", "Research"]),
            techniques: sv(&["T1071", "T1572", "T1055", "T1003", "T1027", "T1090"]),
            tools: sv(&["Snake", "Carbon", "Kazuar", "ComRAT", "LightNeuron"]),
            description: s("Russian FSB-affiliated group active since at least 2004. Known for extremely sophisticated and stealthy operations targeting government entities worldwide."),
        },
        super::ThreatActor {
            name: s("Hafnium"), aliases: sv(&["Silk Typhoon"]),
            origin: s("China"), targets: sv(&["Government", "Defense", "Technology", "Legal", "Healthcare"]),
            techniques: sv(&["T1190", "T1505.003", "T1059", "T1003", "T1560"]),
            tools: sv(&["China Chopper", "Covenant", "PowerCat", "Nishang", "SIMPLESEESHARP"]),
            description: s("Chinese state-sponsored group responsible for the ProxyLogon Exchange Server exploitation campaign (2021) affecting tens of thousands of organizations."),
        },
        super::ThreatActor {
            name: s("REvil"), aliases: sv(&["Sodinokibi", "Gold Southfield"]),
            origin: s("Russia / CIS"), targets: sv(&["Enterprise", "MSP", "Manufacturing", "Legal", "Government"]),
            techniques: sv(&["T1486", "T1490", "T1190", "T1566", "T1059.001", "T1048"]),
            tools: sv(&["Sodinokibi ransomware", "Cobalt Strike", "QakBot", "IcedID"]),
            description: s("Ransomware-as-a-Service (RaaS) operation known for high-profile attacks including Kaseya supply chain attack and JBS Foods."),
        },
        super::ThreatActor {
            name: s("Conti"), aliases: sv(&["Gold Ulrick", "Wizard Spider (overlaps)"]),
            origin: s("Russia / CIS"), targets: sv(&["Healthcare", "Government", "Enterprise", "Critical Infrastructure"]),
            techniques: sv(&["T1486", "T1490", "T1059.001", "T1003", "T1021.002", "T1570"]),
            tools: sv(&["Conti ransomware", "Cobalt Strike", "BazarLoader", "TrickBot", "Mimikatz"]),
            description: s("Major ransomware operation until 2022. Known for targeting healthcare during COVID-19 and attack on Costa Rica government. Internal chats leaked."),
        },
        super::ThreatActor {
            name: s("LockBit"), aliases: sv(&["Gold Mystic"]),
            origin: s("Russia / CIS"), targets: sv(&["Enterprise", "Government", "Healthcare", "Financial"]),
            techniques: sv(&["T1486", "T1490", "T1190", "T1078", "T1059.001", "T1048"]),
            tools: sv(&["LockBit ransomware", "Cobalt Strike", "StealBit", "Mimikatz"]),
            description: s("Most prolific ransomware-as-a-Service group as of 2023-2024. Known for fast encryption, affiliate model, and triple extortion."),
        },
        super::ThreatActor {
            name: s("Scattered Spider"), aliases: sv(&["UNC3944", "0ktapus", "Octo Tempest"]),
            origin: s("United States / United Kingdom"), targets: sv(&["Technology", "Telecom", "Gaming", "Hospitality"]),
            techniques: sv(&["T1566", "T1078", "T1098", "T1136", "T1021.001", "T1486"]),
            tools: sv(&["SIM swapping", "Social engineering", "ALPHV/BlackCat", "Cobalt Strike"]),
            description: s("Young English-speaking threat group known for social engineering, SIM swapping, and partnering with ALPHV/BlackCat ransomware. Targeted MGM Resorts and Caesars."),
        },
        super::ThreatActor {
            name: s("Volt Typhoon"), aliases: sv(&["Bronze Silhouette", "DEV-0391"]),
            origin: s("China"), targets: sv(&["Critical Infrastructure", "Telecom", "Government", "Maritime"]),
            techniques: sv(&["T1190", "T1078", "T1059.003", "T1218", "T1003", "T1016"]),
            tools: sv(&["Living-off-the-land binaries", "Earthworm", "Impacket", "Fast Reverse Proxy"]),
            description: s("Chinese state-sponsored group focused on pre-positioning in US critical infrastructure. Uses almost exclusively LOLBins to avoid detection."),
        },
        super::ThreatActor {
            name: s("MuddyWater"), aliases: sv(&["Mango Sandstorm", "Mercury", "TEMP.Zagros"]),
            origin: s("Iran — MOIS"), targets: sv(&["Government", "Telecom", "Energy", "Middle East", "South Asia"]),
            techniques: sv(&["T1566.001", "T1059.001", "T1059.005", "T1071.001", "T1105"]),
            tools: sv(&["POWERSTATS", "MuddyC3", "PhonyC2", "SimpleHarm"]),
            description: s("Iranian state-sponsored group affiliated with MOIS. Known for targeting Middle Eastern government and telecom organizations with PowerShell-based tools."),
        },
        super::ThreatActor {
            name: s("Kimsuky"), aliases: sv(&["Emerald Sleet", "Velvet Chollima", "Black Banshee"]),
            origin: s("North Korea — RGB"), targets: sv(&["Think Tanks", "Government", "Nuclear", "Academia", "South Korea"]),
            techniques: sv(&["T1566.001", "T1566.002", "T1059.005", "T1003", "T1005"]),
            tools: sv(&["BabyShark", "AppleSeed", "KGH_SPY", "GREASE"]),
            description: s("North Korean espionage group focused on intelligence collection from foreign policy experts, nuclear organizations, and South Korean entities."),
        },
        super::ThreatActor {
            name: s("BlackCat"), aliases: sv(&["ALPHV", "Noberus"]),
            origin: s("Russia / CIS"), targets: sv(&["Enterprise", "Healthcare", "Government"]),
            techniques: sv(&["T1486", "T1490", "T1078", "T1059", "T1048"]),
            tools: sv(&["ALPHV ransomware (Rust)", "Cobalt Strike", "Brute Ratel", "Mimikatz"]),
            description: s("First major ransomware written in Rust. Notable for cross-platform capability and partnership with Scattered Spider. Exit scammed affiliates in early 2024."),
        },
        super::ThreatActor {
            name: s("TA505"), aliases: sv(&["Hive0065", "Graceful Spider"]),
            origin: s("Russia / CIS"), targets: sv(&["Financial", "Retail", "Healthcare"]),
            techniques: sv(&["T1566.001", "T1059", "T1071.001", "T1486", "T1105"]),
            tools: sv(&["Dridex", "Locky", "TrickBot", "Clop ransomware", "FlawedAmmyy"]),
            description: s("Prolific cybercrime group known for massive spam campaigns distributing banking trojans and ransomware. Behind Clop ransomware and MOVEit exploitation."),
        },
        super::ThreatActor {
            name: s("Equation Group"), aliases: sv(&["EQGRP"]),
            origin: s("United States — NSA TAO"), targets: sv(&["Government", "Military", "Telecom", "Energy worldwide"]),
            techniques: sv(&["T1190", "T1195", "T1542", "T1055", "T1027"]),
            tools: sv(&["EternalBlue", "DoublePulsar", "FUZZBUNCH", "DanderSpritz"]),
            description: s("Attributed to NSA Tailored Access Operations. Leaked tools by Shadow Brokers led to WannaCry and NotPetya. Extremely sophisticated firmware-level implants."),
        },
        super::ThreatActor {
            name: s("DarkSide"), aliases: sv(&["Carbon Spider (overlaps)"]),
            origin: s("Russia / CIS"), targets: sv(&["Energy", "Critical Infrastructure", "Enterprise"]),
            techniques: sv(&["T1486", "T1490", "T1078", "T1021", "T1048"]),
            tools: sv(&["DarkSide ransomware", "Cobalt Strike", "Mimikatz"]),
            description: s("Ransomware group behind the Colonial Pipeline attack (May 2021) that caused fuel shortages across the US East Coast. Rebranded to BlackMatter."),
        },
    ]
}
