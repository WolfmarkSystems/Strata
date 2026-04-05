// Known attacker tools, LOLBins, and dual-use utilities for DFIR triage.
// Each entry maps filenames/aliases to MITRE ATT&CK techniques, threat actors,
// command-line indicators, forensic artifacts, and examiner recommendations.

use super::KnownTool;

/// Shorthand: owned String from a &str.
fn s(v: &str) -> String {
    v.to_string()
}

/// Shorthand: Vec<String> from a slice of &str.
fn sv(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

/// Build a KnownTool with the builder-style helper.
#[allow(clippy::too_many_arguments)]
fn tool(
    names: &[&str],
    description: &str,
    category: &str,
    mitre: &[&str],
    actors: &[&str],
    indicators: &[&str],
    artifacts: &[&str],
    recommendation: &str,
    confidence: u8,
) -> KnownTool {
    KnownTool {
        names: sv(names),
        description: s(description),
        category: s(category),
        mitre_techniques: sv(mitre),
        threat_actors: sv(actors),
        indicators: sv(indicators),
        forensic_artifacts: sv(artifacts),
        recommendation: s(recommendation),
        confidence,
    }
}

/// Returns the full catalog of known attacker tools, LOLBins, and dual-use utilities.
pub fn all_tools() -> Vec<KnownTool> {
    vec![
        // =====================================================================
        // CREDENTIAL DUMPING
        // =====================================================================
        tool(
            &["mimikatz", "mimikatz.exe", "mimi.exe", "mimi32.exe", "mimi64.exe"],
            "Post-exploitation credential harvesting tool. Extracts plaintext passwords, \
             hashes, PIN codes, and Kerberos tickets from LSASS memory.",
            "Credential Dumping",
            &["T1003", "T1003.001", "T1003.002"],
            &["APT28", "APT29", "Lazarus", "FIN7", "Wizard Spider"],
            &["sekurlsa", "lsadump", "kerberos::golden", "privilege::debug",
              "sekurlsa::logonpasswords", "token::elevate", "crypto::capi"],
            &[
                "Prefetch: MIMIKATZ.EXE-*.pf",
                "Event Log: Security 4688 (process creation)",
                "Event Log: Sysmon 1 (process create), 10 (process access to lsass.exe)",
                "NTFS $MFT entry for mimikatz.exe",
                "AmCache.hve entry",
                "ShimCache entry",
            ],
            "Immediate priority. Examine LSASS access events, correlate with lateral movement. \
             Capture memory image if system is live. Check for golden/silver ticket creation.",
            95,
        ),
        tool(
            &["wce.exe", "wcex64.exe", "wce32.exe"],
            "Windows Credential Editor. Dumps logon session passwords and NTLM hashes \
             from LSASS memory; can also perform pass-the-hash.",
            "Credential Dumping",
            &["T1003"],
            &[],
            &["wce.exe", "-w", "-s", "wcex64"],
            &[
                "Prefetch: WCE.EXE-*.pf or WCEX64.EXE-*.pf",
                "Event Log: Security 4688",
                "Event Log: Sysmon 1, 10 (LSASS access)",
                "ShimCache / AmCache entries",
            ],
            "High priority. Check for credential reuse and lateral movement following execution. \
             Correlate with logon events (4624/4625).",
            93,
        ),
        tool(
            &["fgdump.exe", "fgdump"],
            "Cached credential dumper that extracts password hashes from the SAM database \
             and Active Directory. Disables AV before dumping.",
            "Credential Dumping",
            &["T1003"],
            &[],
            &["fgdump", "cachedump", "pwdump"],
            &[
                "Prefetch: FGDUMP.EXE-*.pf",
                "Event Log: Security 4688",
                "Dropped files: 127.0.0.1.pwdump, cachedump.exe",
                "ShimCache / AmCache entries",
            ],
            "Examine dumped hash files on disk. Check for subsequent pass-the-hash activity. \
             Review AV tamper logs for service stops.",
            92,
        ),
        tool(
            &["pwdump7.exe", "pwdump7", "pwdump"],
            "Extracts password hashes directly from the SAM registry hive by reading raw \
             filesystem structures, bypassing OS protections.",
            "Credential Dumping",
            &["T1003"],
            &[],
            &["pwdump7", "pwdump"],
            &[
                "Prefetch: PWDUMP7.EXE-*.pf",
                "Event Log: Security 4688",
                "Output file on disk containing NTLM hashes",
                "ShimCache / AmCache entries",
            ],
            "Search for output files containing hash dumps. Correlate with pass-the-hash \
             lateral movement. Timeline the execution against other suspicious activity.",
            92,
        ),
        tool(
            &["procdump.exe", "procdump64.exe", "procdump"],
            "Sysinternals process dump utility. Legitimate admin tool frequently abused to \
             dump LSASS process memory for offline credential extraction.",
            "Credential Dumping",
            &["T1003.001"],
            &["APT28", "Kimsuky"],
            &["procdump", "-ma lsass", "lsass.dmp", "-accepteula"],
            &[
                "Prefetch: PROCDUMP.EXE-*.pf or PROCDUMP64.EXE-*.pf",
                "Event Log: Security 4688 with lsass in command line",
                "Event Log: Sysmon 1 (process create), 11 (file create for .dmp)",
                "LSASS dump file (lsass.dmp or custom name)",
                "ShimCache / AmCache entries",
            ],
            "Check command line for LSASS targeting. Legitimate use exists, but dumping LSASS \
             is almost always malicious. Search for resulting .dmp files.",
            85,
        ),
        tool(
            &["dumpert.dll", "dumpert", "outflank-dumpert"],
            "Direct syscall-based LSASS memory dumper that bypasses API hooking by EDR/AV. \
             Uses NtReadVirtualMemory syscall directly.",
            "Credential Dumping",
            &["T1003.001"],
            &[],
            &["dumpert", "NtReadVirtualMemory", "outflank"],
            &[
                "Event Log: Sysmon 7 (image load for dumpert.dll)",
                "Event Log: Sysmon 10 (process access to lsass.exe)",
                "LSASS dump file on disk",
                "NTFS $MFT entry",
            ],
            "Indicates sophisticated attacker evading EDR. Examine for LSASS dump files. \
             Check DLL load events and correlate with credential reuse.",
            94,
        ),
        tool(
            &["lsassy", "lsassy.exe", "lsassy.py"],
            "Python-based remote LSASS parser. Dumps credentials from LSASS by leveraging \
             remote execution methods (WMI, task scheduler, SMB).",
            "Credential Dumping",
            &["T1003.001"],
            &[],
            &["lsassy", "dumpmethod", "procdump_embedded"],
            &[
                "Event Log: Security 4688 (remote process creation)",
                "Event Log: Sysmon 1, 3 (network connections)",
                "SMB shares accessed for dump transfer",
                "Python execution artifacts",
            ],
            "Check for remote execution artifacts. Examine network connections for dump file \
             transfer. Correlate with SMB activity and remote service creation.",
            93,
        ),
        tool(
            &["rubeus.exe", "rubeus"],
            "Kerberos abuse toolkit. Performs kerberoasting, AS-REP roasting, ticket \
             manipulation, constrained delegation abuse, and S4U attacks.",
            "Credential Dumping",
            &["T1558", "T1558.003", "T1558.004", "T1003"],
            &["FIN7", "Wizard Spider"],
            &["rubeus", "kerberoast", "asreproast", "s4u", "ptt",
              "tgtdeleg", "harvest", "renew", "createnetonly"],
            &[
                "Prefetch: RUBEUS.EXE-*.pf",
                "Event Log: Security 4769 (Kerberos service ticket, RC4 encryption)",
                "Event Log: Security 4768 (AS-REP with no pre-auth)",
                "Event Log: Security 4688",
                "ShimCache / AmCache entries",
            ],
            "Review Kerberos ticket requests for RC4 encryption (downgrade). Examine 4769 events \
             for mass service ticket requests (kerberoasting). Check for ticket injection.",
            94,
        ),

        // =====================================================================
        // LATERAL MOVEMENT
        // =====================================================================
        tool(
            &["psexec.exe", "psexesvc.exe", "psexec64.exe", "psexec"],
            "Sysinternals remote execution tool. Creates a service on the target host to \
             execute commands. Widely abused for lateral movement.",
            "Lateral Movement",
            &["T1570", "T1021.002", "T1569.002"],
            &["APT28", "APT29", "Wizard Spider", "FIN6", "Sandworm"],
            &["psexec", "psexesvc", "-accepteula", "-s -d"],
            &[
                "Prefetch: PSEXEC.EXE-*.pf, PSEXESVC.EXE-*.pf",
                "Event Log: System 7045 (service install PSEXESVC)",
                "Event Log: Security 4688, 4624 (type 3 logon)",
                "Named pipe: \\PSEXESVC",
                "ShimCache / AmCache entries on both source and target",
            ],
            "Check for PSEXESVC service installation on target hosts. Correlate with type 3 \
             logon events and credential usage. Map lateral movement path.",
            88,
        ),
        tool(
            &["impacket", "secretsdump.py", "wmiexec.py", "smbexec.py",
              "psexec.py", "atexec.py", "dcomexec.py"],
            "Python-based collection of network protocols for remote execution, credential \
             dumping, and SMB/WMI/DCOM exploitation. Core offensive toolkit.",
            "Lateral Movement",
            &["T1021", "T1021.002", "T1021.003", "T1003", "T1047"],
            &["APT29", "Wizard Spider", "FIN7"],
            &["impacket", "secretsdump", "wmiexec", "smbexec", "atexec",
              "dcomexec", "__output", "ADMIN$"],
            &[
                "Event Log: Security 4624 (type 3), 4672 (admin logon)",
                "Event Log: System 7045 (service install for smbexec)",
                "Event Log: WMI-Activity/Operational (for wmiexec)",
                "Event Log: Security 4688 with cmd.exe /Q /c",
                "SMB share access logs (ADMIN$, C$)",
                "Python execution artifacts on source system",
            ],
            "Examine target systems for service creation, WMI activity, and DCOM lateral movement. \
             Check for cmd.exe spawned by WMI or services. Review SMB access logs.",
            93,
        ),

        // =====================================================================
        // C2 FRAMEWORKS
        // =====================================================================
        tool(
            &["beacon.dll", "beacon.exe", "artifact.exe", "cobaltstrike",
              "cobalt strike", "beacon"],
            "Commercial adversary simulation framework widely abused by threat actors. \
             Provides beaconing C2, process injection, credential theft, and lateral movement.",
            "C2 Framework",
            &["T1071.001", "T1059.001", "T1055", "T1573"],
            &["APT29", "APT41", "FIN7", "FIN12", "Wizard Spider", "Conti"],
            &["beacon", "cobaltstrike", "sleeptime", "jitter",
              "named pipe: \\\\MSSE-", "C2 profile", "metadata"],
            &[
                "Event Log: Sysmon 1 (process create), 3 (network connection)",
                "Event Log: Sysmon 22 (DNS query to C2 domain)",
                "Event Log: Sysmon 7 (reflective DLL load)",
                "Named pipes: MSSE-*, msagent_*, postex_*",
                "Network: HTTP beaconing pattern with jitter",
                "Memory: Reflectively loaded PE headers",
                "Malleable C2 profile indicators in HTTP headers",
            ],
            "Critical priority. Identify C2 infrastructure from network traffic. Analyze beacon \
             configuration from memory. Check for spawned processes, injected threads, and \
             named pipes. Correlate with lateral movement and data staging.",
            95,
        ),
        tool(
            &["meterpreter", "metsvc.exe", "msfvenom", "metasploit",
              "meterpreter.exe", "metsvc"],
            "Metasploit Framework payload. Provides in-memory C2 agent with extensible \
             post-exploitation modules for credential theft, pivoting, and persistence.",
            "C2 Framework",
            &["T1059", "T1055", "T1071.001"],
            &["FIN7", "APT41"],
            &["meterpreter", "metsvc", "msfvenom", "reverse_tcp",
              "reverse_https", "payload/windows/meterpreter"],
            &[
                "Event Log: Sysmon 1, 3 (reverse shell connection)",
                "Event Log: Sysmon 10 (process access for migration)",
                "Network: staged/stageless payload transfer",
                "Memory: Reflective DLL injection artifacts",
                "Prefetch: METSVC.EXE-*.pf (if persistent service)",
            ],
            "Analyze network connections for reverse shell patterns. Check for reflective DLL \
             injection. Examine process migration activity via Sysmon 10 events.",
            94,
        ),
        tool(
            &["empire", "powershell-empire", "invoke-empire", "empire.exe"],
            "PowerShell-based post-exploitation C2 framework. Uses encoded PowerShell \
             stagers for initial access and provides modules for credential theft and persistence.",
            "C2 Framework",
            &["T1059.001", "T1071.001"],
            &["APT33", "FIN7"],
            &["invoke-empire", "stager", "empire", "launcher_bat",
              "invoke-obfuscation", "set-dcsync"],
            &[
                "Event Log: PowerShell 4104 (script block logging)",
                "Event Log: Security 4688 (encoded PowerShell)",
                "Event Log: Sysmon 1 (powershell.exe with encoded args)",
                "PowerShell console history file",
                "Prefetch: POWERSHELL.EXE-*.pf",
            ],
            "Enable and review PowerShell script block logs (4104). Decode base64 stagers. \
             Check for Empire module execution patterns in transcript logs.",
            93,
        ),

        // =====================================================================
        // RECONNAISSANCE
        // =====================================================================
        tool(
            &["nmap.exe", "nmap", "zenmap.exe"],
            "Network port scanner and service fingerprinting tool. Used for host discovery, \
             port enumeration, OS detection, and vulnerability scanning.",
            "Reconnaissance",
            &["T1046"],
            &["APT28", "APT1"],
            &["nmap", "-sS", "-sV", "-sC", "-O", "--script",
              "-p-", "-Pn", "-oA", "-oX"],
            &[
                "Prefetch: NMAP.EXE-*.pf",
                "Event Log: Security 4688",
                "Nmap output files (-oA/-oX/-oN)",
                "Network: SYN scan traffic patterns",
                "Firewall/IDS logs: port scan alerts",
            ],
            "Examine scan output files for scope of reconnaissance. Correlate scan timing with \
             subsequent lateral movement. Check network logs for scan traffic.",
            85,
        ),
        tool(
            &["masscan.exe", "masscan"],
            "High-speed asynchronous TCP port scanner capable of scanning the entire Internet. \
             Significantly faster than nmap for large-scale host discovery.",
            "Reconnaissance",
            &["T1046"],
            &[],
            &["masscan", "--rate", "--banners", "-p", "--open"],
            &[
                "Prefetch: MASSCAN.EXE-*.pf",
                "Event Log: Security 4688",
                "Masscan output files",
                "Network: high-rate SYN traffic",
            ],
            "Review output files and command-line arguments for scan scope. High scan rates \
             likely triggered IDS alerts. Correlate with subsequent exploitation.",
            87,
        ),
        tool(
            &["sharphound.exe", "sharphound", "bloodhound", "bloodhound.exe",
              "azurehound.exe", "azurehound"],
            "Active Directory enumeration tool that maps attack paths via LDAP, SMB, and RPC \
             queries. Collects users, groups, sessions, ACLs, and trust relationships.",
            "Reconnaissance",
            &["T1087", "T1069", "T1087.002", "T1069.002"],
            &["FIN7", "Wizard Spider"],
            &["sharphound", "bloodhound", "azurehound", "--collectionmethod",
              "-c all", "invoke-bloodhound", "SharpHound.ps1"],
            &[
                "Prefetch: SHARPHOUND.EXE-*.pf",
                "Event Log: Security 4688",
                "Event Log: Security 4662 (AD object access)",
                "Event Log: LDAP query logs",
                "Output ZIP files containing JSON (e.g., *_BloodHound.zip)",
                "ShimCache / AmCache entries",
            ],
            "Search for BloodHound ZIP output files. Review LDAP query volume spike. \
             Check for enumeration of privileged groups and admin sessions.",
            92,
        ),
        tool(
            &["adrecon.ps1", "adrecon", "ADRecon"],
            "PowerShell script for comprehensive Active Directory reconnaissance. Enumerates \
             users, groups, OUs, GPOs, trusts, LAPS, and more into Excel/CSV reports.",
            "Reconnaissance",
            &["T1087", "T1087.002"],
            &[],
            &["adrecon", "invoke-adrecon", "ADRecon.ps1", "GenExcel"],
            &[
                "Event Log: PowerShell 4104 (script block logging)",
                "Event Log: Security 4688",
                "Output Excel/CSV files with AD data",
                "PowerShell console history",
            ],
            "Check for output reports containing AD enumeration data. Review PowerShell \
             logging for ADRecon invocation. Assess scope of AD data collected.",
            88,
        ),

        // =====================================================================
        // TUNNELING
        // =====================================================================
        tool(
            &["chisel.exe", "chisel", "chisel_linux"],
            "Fast TCP/UDP tunnel over HTTP using SSH protocol. Creates SOCKS5 proxy or \
             port forwards through firewalls. Written in Go, single binary.",
            "Tunneling",
            &["T1572"],
            &["Volt Typhoon"],
            &["chisel", "server --reverse", "client", "R:socks",
              "R:127.0.0.1"],
            &[
                "Prefetch: CHISEL.EXE-*.pf",
                "Event Log: Security 4688",
                "Event Log: Sysmon 1, 3 (network connections)",
                "Network: HTTP Upgrade to websocket",
                "Proxy logs: SOCKS traffic patterns",
            ],
            "Identify the tunnel endpoints and traffic flowing through. Check for data \
             exfiltration or C2 traffic routed through the tunnel.",
            92,
        ),
        tool(
            &["ngrok.exe", "ngrok", "ngrok.io"],
            "Reverse tunneling service that exposes local servers to the Internet. Provides \
             on-demand public URLs; abused for C2 callback and data exfiltration.",
            "Tunneling",
            &["T1572"],
            &[],
            &["ngrok", "ngrok.io", "tunnel.us.ngrok.com", "authtoken",
              "tcp", "http"],
            &[
                "Prefetch: NGROK.EXE-*.pf",
                "Event Log: Security 4688",
                "Event Log: Sysmon 3 (connection to ngrok.io)",
                "Network: DNS queries to *.ngrok.io",
                "ngrok configuration file",
            ],
            "Check DNS and proxy logs for ngrok.io connections. Determine what local service \
             was exposed. Review for data exfiltration or unauthorized remote access.",
            90,
        ),
        tool(
            &["plink.exe", "plink"],
            "PuTTY command-line SSH client. Abused to create SSH tunnels for port forwarding, \
             SOCKS proxying, and firewall bypass.",
            "Tunneling",
            &["T1572", "T1021.004"],
            &["APT28", "Turla"],
            &["plink", "-ssh", "-R", "-L", "-D", "-pw", "-N",
              "-batch", "-P"],
            &[
                "Prefetch: PLINK.EXE-*.pf",
                "Event Log: Security 4688",
                "Event Log: Sysmon 1, 3 (SSH connections)",
                "PuTTY host keys in registry",
                "Network: outbound SSH connections",
            ],
            "Examine command line for tunnel configuration. Check for passwords in arguments \
             (-pw flag). Identify remote endpoint and port forwards.",
            88,
        ),

        // =====================================================================
        // LOLBins (Living Off the Land)
        // =====================================================================
        tool(
            &["certutil.exe", "certutil"],
            "Windows certificate utility. Dual-use binary abused for downloading files, \
             base64 encoding/decoding, and hash computation to bypass security controls.",
            "LOLBin",
            &["T1140", "T1105"],
            &["APT33", "OilRig", "Lazarus"],
            &["-urlcache", "-decode", "-encode", "-split",
              "-f", "-decodehex", "-hashfile", "http://", "https://"],
            &[
                "Prefetch: CERTUTIL.EXE-*.pf",
                "Event Log: Security 4688 with command line",
                "Internet cache: CryptnetUrlCache folder",
                "Downloaded/decoded files on disk",
                "INetCache metadata",
            ],
            "Examine command line for -urlcache (download) or -decode (payload decode). \
             Check CryptnetUrlCache for downloaded files. Legitimate use exists for cert management.",
            75,
        ),
        tool(
            &["mshta.exe", "mshta"],
            "Microsoft HTML Application Host. Executes .hta files containing scripts; \
             abused as a proxy to execute arbitrary code and bypass application whitelisting.",
            "LOLBin",
            &["T1218.005"],
            &["APT32", "Kimsuky", "MuddyWater"],
            &["mshta", "javascript:", "vbscript:", ".hta",
              "about:hta", "http://", "https://"],
            &[
                "Prefetch: MSHTA.EXE-*.pf",
                "Event Log: Security 4688",
                "Event Log: Sysmon 1 (child process of mshta.exe)",
                "IE cache for remote HTA downloads",
                "HTA files on disk",
            ],
            "Check for mshta.exe launching scripts or child processes. Examine HTA content \
             for obfuscated payloads. Review network connections for remote HTA fetch.",
            78,
        ),
        tool(
            &["regsvr32.exe", "regsvr32"],
            "Windows COM registration utility. Abused via Squiblydoo technique to execute \
             scriptlets (SCT) from remote URLs, bypassing AppLocker.",
            "LOLBin",
            &["T1218.010"],
            &["APT19"],
            &["/s /u /i:", "scrobj.dll", ".sct", "http://",
              "regsvr32 /s /n /u /i:"],
            &[
                "Prefetch: REGSVR32.EXE-*.pf",
                "Event Log: Security 4688",
                "Event Log: Sysmon 1 (regsvr32 with network URL)",
                "IE cache for remote SCT downloads",
                "Loaded DLLs (scrobj.dll)",
            ],
            "Check command line for /i: with URL (Squiblydoo). Legitimate use registers COM DLLs \
             locally. Network-fetched SCT is almost always malicious.",
            78,
        ),
        tool(
            &["wscript.exe", "cscript.exe", "wscript", "cscript"],
            "Windows Script Host engines. Execute VBScript (.vbs) and JScript (.js) files; \
             commonly used as initial access vectors and for download/execute chains.",
            "LOLBin",
            &["T1059.005", "T1059.007"],
            &["FIN7", "Lazarus", "MuddyWater"],
            &["wscript", "cscript", ".vbs", ".js", ".wsf", ".wsh",
              "//b", "//nologo", "//e:"],
            &[
                "Prefetch: WSCRIPT.EXE-*.pf or CSCRIPT.EXE-*.pf",
                "Event Log: Security 4688",
                "Event Log: Sysmon 1 (with script file argument)",
                "Script files in Temp, Downloads, AppData",
                "WMI script event consumers",
            ],
            "Examine the script content being executed. Check for download cradles and obfuscation. \
             Review parent process (email client, browser = likely phishing).",
            72,
        ),
        tool(
            &["bitsadmin.exe", "bitsadmin"],
            "Background Intelligent Transfer Service admin tool. Abused to download payloads \
             in the background, create persistent jobs, and execute code.",
            "LOLBin",
            &["T1197", "T1105"],
            &["APT33", "APT41"],
            &["/transfer", "/download", "/addfile", "/setnotifycmdline",
              "/resume", "/complete", "bitsadmin"],
            &[
                "Prefetch: BITSADMIN.EXE-*.pf",
                "Event Log: Security 4688",
                "Event Log: BITS-Client/Operational (job events)",
                "BITS job database (QMGR queue files)",
                "Downloaded files at specified path",
            ],
            "Review BITS jobs for download URLs and notification commands. Check BITS event log \
             for job creation. Persistent BITS jobs survive reboots.",
            75,
        ),
        tool(
            &["rundll32.exe", "rundll32"],
            "Windows DLL execution host. Loads and executes exported DLL functions; \
             abused to proxy execution of malicious code and bypass application whitelisting.",
            "LOLBin",
            &["T1218.011"],
            &["APT29", "Lazarus"],
            &["rundll32", "javascript:", "shell32.dll",
              "advpack.dll,LaunchINFSection", "url.dll,FileProtocolHandler",
              "pcwutl.dll,LaunchApplication"],
            &[
                "Prefetch: RUNDLL32.EXE-*.pf",
                "Event Log: Security 4688",
                "Event Log: Sysmon 1, 7 (DLL load)",
                "Loaded DLL on disk or in temp directory",
            ],
            "Examine DLL being loaded and export function called. Suspicious when loading DLLs \
             from temp/user directories or using JavaScript protocol handler.",
            72,
        ),
        tool(
            &["msiexec.exe", "msiexec"],
            "Windows Installer service. Abused to install malicious MSI packages from \
             remote URLs or local paths, bypassing application controls.",
            "LOLBin",
            &["T1218.007"],
            &[],
            &["msiexec", "/i", "/q", "/quiet", "http://", "https://",
              "/y", "/z"],
            &[
                "Prefetch: MSIEXEC.EXE-*.pf",
                "Event Log: Security 4688",
                "Event Log: Application 1033, 1034 (MSI install events)",
                "Event Log: MsiInstaller events",
                "Installer cache in %WINDIR%\\Installer",
            ],
            "Check for remote MSI installation. Review MSI installer logs and content. \
             Legitimate software installs use msiexec, so correlate with other indicators.",
            72,
        ),
        tool(
            &["installutil.exe", "installutil"],
            ".NET Framework installation utility. Abused to execute arbitrary code in \
             .NET assemblies via custom installer classes, bypassing AppLocker.",
            "LOLBin",
            &["T1218.004"],
            &[],
            &["installutil", "/logfile=", "/LogToConsole=false", "/U"],
            &[
                "Prefetch: INSTALLUTIL.EXE-*.pf",
                "Event Log: Security 4688",
                "Event Log: Sysmon 1 (with .NET assembly argument)",
                ".NET assembly file on disk",
                "InstallUtil log files",
            ],
            "Examine the .NET assembly being loaded for malicious installer classes. \
             Check /U (uninstall) flag which is commonly abused for execution.",
            78,
        ),
        tool(
            &["cmstp.exe", "cmstp"],
            "Connection Manager Profile Installer. Abused to execute arbitrary commands via \
             malicious INF files, bypassing AppLocker and UAC.",
            "LOLBin",
            &["T1218.003"],
            &["Cobalt Group"],
            &["cmstp", "/ni", "/s", ".inf", "RegisterOCX", "UnRegisterOCX"],
            &[
                "Prefetch: CMSTP.EXE-*.pf",
                "Event Log: Security 4688",
                "Event Log: Sysmon 1 (cmstp.exe with INF argument)",
                "INF file on disk with malicious directives",
            ],
            "Examine the INF file for RegisterOCX/UnRegisterOCX directives pointing to malicious \
             DLLs or commands. CMSTP abuse is rarely legitimate.",
            80,
        ),

        // =====================================================================
        // ANTI-FORENSICS / DESTRUCTION
        // =====================================================================
        tool(
            &["vssadmin.exe", "vssadmin"],
            "Volume Shadow Copy admin tool. Commonly abused by ransomware to delete shadow \
             copies, destroying backup recovery options.",
            "Anti-Forensics",
            &["T1490"],
            &["Wizard Spider", "REvil", "Conti", "LockBit", "BlackCat"],
            &["delete shadows", "resize shadowstorage", "vssadmin",
              "delete shadows /all /quiet", "list shadows"],
            &[
                "Event Log: Security 4688 with 'delete shadows'",
                "Event Log: VSS 13 (shadow copy deleted)",
                "Event Log: System 7036 (VSS service state change)",
                "Prefetch: VSSADMIN.EXE-*.pf",
            ],
            "Shadow copy deletion is a strong ransomware indicator. Check for encryption \
             activity and ransom notes immediately. Correlate with bcdedit and wbadmin activity.",
            90,
        ),
        tool(
            &["wbadmin.exe", "wbadmin"],
            "Windows Backup admin tool. Abused by ransomware to delete system backups and \
             the backup catalog, preventing system state recovery.",
            "Anti-Forensics",
            &["T1490"],
            &["Wizard Spider", "REvil", "Conti"],
            &["delete catalog", "delete systemstatebackup", "wbadmin",
              "delete backup"],
            &[
                "Event Log: Security 4688 with 'delete catalog'",
                "Event Log: Backup events",
                "Prefetch: WBADMIN.EXE-*.pf",
            ],
            "Backup deletion alongside shadow copy deletion is a strong ransomware pattern. \
             Check for associated encryption behavior.",
            90,
        ),
        tool(
            &["bcdedit.exe", "bcdedit"],
            "Boot Configuration Data editor. Abused by ransomware to disable Windows Recovery \
             Environment and safe boot options.",
            "Anti-Forensics",
            &["T1490"],
            &["Wizard Spider", "REvil", "Conti", "LockBit"],
            &["/set recoveryenabled no", "/set bootstatuspolicy ignoreallfailures",
              "bcdedit", "safeboot"],
            &[
                "Event Log: Security 4688 with bcdedit commands",
                "Event Log: Sysmon 1 (bcdedit with recovery disable)",
                "Prefetch: BCDEDIT.EXE-*.pf",
                "BCD store modification timestamps",
            ],
            "Recovery disable combined with shadow copy deletion is a textbook ransomware \
             pattern. Immediately investigate for encryption activity and ransom notes.",
            88,
        ),
        tool(
            &["sdelete.exe", "sdelete64.exe", "sdelete"],
            "Sysinternals secure file deletion utility. Overwrites file data before deletion \
             to prevent forensic recovery. Legitimate tool abused for anti-forensics.",
            "Anti-Forensics",
            &["T1070.004"],
            &["APT29", "APT28"],
            &["sdelete", "-p", "-s", "-z", "-accepteula", "-r"],
            &[
                "Prefetch: SDELETE.EXE-*.pf or SDELETE64.EXE-*.pf",
                "Event Log: Security 4688",
                "NTFS $MFT entries showing overwritten files",
                "USN Journal entries for file modifications",
            ],
            "Determine what files were targeted for secure deletion. Check USN Journal and MFT \
             for file metadata. Correlate timing with other anti-forensic activity.",
            85,
        ),
        tool(
            &["cipher.exe", "cipher"],
            "Windows Encrypting File System utility. The /w flag wipes unallocated disk \
             space, destroying deleted file remnants for anti-forensic purposes.",
            "Anti-Forensics",
            &["T1070.004"],
            &[],
            &["cipher", "/w:", "/e", "/d"],
            &[
                "Prefetch: CIPHER.EXE-*.pf",
                "Event Log: Security 4688 with /w flag",
                "Disk write patterns (three-pass wipe)",
            ],
            "Check for /w flag usage indicating free space wiping. This destroys recoverable \
             deleted files. Assess impact on evidence recovery.",
            80,
        ),

        // =====================================================================
        // DATA EXFILTRATION
        // =====================================================================
        tool(
            &["rclone.exe", "rclone"],
            "Cloud storage synchronization tool. Frequently abused for large-scale data \
             exfiltration to attacker-controlled cloud storage (Mega, S3, etc.).",
            "Exfiltration",
            &["T1567", "T1048"],
            &["Conti", "BlackCat", "LockBit", "Karakurt"],
            &["rclone", "copy", "sync", "lsd", "--config",
              "--bwlimit", "mega:", "s3:", "--transfers"],
            &[
                "Prefetch: RCLONE.EXE-*.pf",
                "Event Log: Security 4688",
                "Event Log: Sysmon 1, 3 (cloud storage connections)",
                "Rclone config file (rclone.conf with remote definitions)",
                "Network: large data transfer to cloud storage IPs",
            ],
            "Critical. Locate rclone.conf for remote storage configuration. Measure data \
             volume transferred. Identify which files/directories were exfiltrated.",
            93,
        ),
        tool(
            &["mega.exe", "megacmd", "megacopy.exe", "megasync.exe",
              "MEGAcmdServer.exe"],
            "MEGA cloud storage client. Provides encrypted cloud storage; abused by \
             ransomware operators for data exfiltration before encryption.",
            "Exfiltration",
            &["T1567"],
            &["Conti", "BlackCat"],
            &["mega", "megacmd", "megacopy", "megasync", "mega.nz",
              "megatools"],
            &[
                "Prefetch: MEGA*.EXE-*.pf",
                "Event Log: Security 4688",
                "Event Log: Sysmon 3 (connections to mega.nz)",
                "MEGA sync database and cache files",
                "Network: DNS queries to *.mega.nz",
            ],
            "Check for unauthorized MEGA installation. Review network traffic volume to mega.nz. \
             Locate MEGA configuration and sync database to determine exfiltrated data.",
            90,
        ),
        tool(
            &["7z.exe", "7za.exe", "7zr.exe", "7zip"],
            "High-compression archive utility. Used to stage data for exfiltration, often \
             with password protection to evade DLP inspection.",
            "Exfiltration",
            &["T1560.001"],
            &["APT28", "APT29", "FIN7"],
            &["7z", "7za", "a -p", "-mx", "-mhe=on",
              "-r", ".7z", "a -t7z"],
            &[
                "Prefetch: 7Z.EXE-*.pf or 7ZA.EXE-*.pf",
                "Event Log: Security 4688 with archive commands",
                "Created archive files (.7z, .zip)",
                "Sysmon 11 (file creation for archives)",
            ],
            "Examine command line for password-protected archives (-p flag). Locate created \
             archives and determine what was collected. Check for subsequent exfiltration.",
            78,
        ),

        // =====================================================================
        // PERSISTENCE
        // =====================================================================
        tool(
            &["schtasks.exe", "schtasks"],
            "Windows task scheduler command-line interface. Dual-use binary frequently \
             abused to create persistent scheduled tasks for malware execution.",
            "Persistence",
            &["T1053.005"],
            &["APT29", "Lazarus", "APT33"],
            &["schtasks", "/create", "/sc", "/tn", "/tr",
              "/ru SYSTEM", "/f", "/xml"],
            &[
                "Prefetch: SCHTASKS.EXE-*.pf",
                "Event Log: Security 4698 (scheduled task created)",
                "Event Log: Security 4702 (scheduled task updated)",
                "Event Log: TaskScheduler/Operational 106 (task registered)",
                "Task XML files in C:\\Windows\\System32\\Tasks\\",
            ],
            "Review 4698 events for task creation details. Examine task XML for executable path \
             and triggers. Legitimate admin use exists -- correlate with other indicators.",
            75,
        ),
        tool(
            &["at.exe", "at"],
            "Legacy Windows task scheduler (deprecated). Creates scheduled tasks by time; \
             abused for persistence and remote task execution.",
            "Persistence",
            &["T1053.002"],
            &[],
            &["at", "/every:", "at \\\\"],
            &[
                "Prefetch: AT.EXE-*.pf",
                "Event Log: Security 4698 (task created)",
                "Event Log: Security 4688",
                "at.job files in Tasks folder",
            ],
            "Legacy tool; presence on modern systems is suspicious. Check for remote task \
             creation (at \\\\hostname). Review job content for malicious commands.",
            82,
        ),
        tool(
            &["sc.exe", "sc"],
            "Service Control Manager command-line tool. Dual-use binary abused to create \
             malicious services for persistence and privilege escalation.",
            "Persistence",
            &["T1543.003"],
            &["APT28", "Lazarus"],
            &["sc", "create", "config", "start=", "binpath=",
              "type= own", "sc \\\\"],
            &[
                "Event Log: System 7045 (new service installed)",
                "Event Log: System 7034 (service crashed)",
                "Event Log: Security 4688 with sc create",
                "Registry: HKLM\\SYSTEM\\CurrentControlSet\\Services\\",
                "Prefetch: SC.EXE-*.pf",
            ],
            "Review 7045 events for service creation. Examine binPath for suspicious executables \
             or command lines. Check for remote service creation (sc \\\\hostname).",
            74,
        ),
        tool(
            &["reg.exe", "reg"],
            "Windows registry command-line editor. Dual-use binary abused to modify Run keys, \
             disable security features, and establish persistence.",
            "Persistence",
            &["T1112", "T1547.001"],
            &[],
            &["reg", "add", "query", "delete", "export", "import",
              "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
              "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
              "DisableAntiSpyware"],
            &[
                "Event Log: Security 4688 with reg commands",
                "Event Log: Security 4657 (registry value modified)",
                "Event Log: Sysmon 13 (registry value set)",
                "Prefetch: REG.EXE-*.pf",
                "Registry hive backups",
            ],
            "Review registry modifications for persistence (Run/RunOnce keys), security \
             disabling, and firewall changes. Legitimate admin use common -- correlate carefully.",
            70,
        ),

        // =====================================================================
        // NETWORK TOOLS
        // =====================================================================
        tool(
            &["nc.exe", "nc64.exe", "ncat.exe", "netcat", "ncat"],
            "Raw TCP/UDP networking utility. Provides arbitrary network connections, \
             listeners, and port redirection; often called the 'Swiss Army knife' of networking.",
            "Network",
            &["T1095", "T1571"],
            &[],
            &["nc", "ncat", "netcat", "-e cmd.exe", "-e /bin/sh",
              "-lvp", "-nv", "-w"],
            &[
                "Prefetch: NC.EXE-*.pf or NCAT.EXE-*.pf",
                "Event Log: Security 4688",
                "Event Log: Sysmon 1, 3 (network connections)",
                "Network: raw TCP connections on unusual ports",
            ],
            "Check for -e flag (reverse shell). Examine listening ports and connection targets. \
             Netcat on a production system is almost always suspicious.",
            88,
        ),
        tool(
            &["socat", "socat.exe"],
            "Bidirectional data relay between two data channels. More capable than netcat; \
             supports SSL, proxying, and complex relay configurations.",
            "Network",
            &["T1095"],
            &[],
            &["socat", "TCP-LISTEN:", "TCP-CONNECT:", "EXEC:",
              "OPENSSL:", "STDIO"],
            &[
                "Prefetch: SOCAT.EXE-*.pf",
                "Event Log: Security 4688",
                "Event Log: Sysmon 1, 3 (network connections)",
                "Network: relay patterns on unusual ports",
            ],
            "Examine command line for data relay endpoints. Check for EXEC usage (command \
             execution). Identify both ends of the relay for full picture.",
            87,
        ),
        tool(
            &["curl.exe", "curl", "wget.exe", "wget"],
            "Command-line HTTP/FTP download utilities. Dual-use tools abused to download \
             payloads, exfiltrate data, and communicate with C2 infrastructure.",
            "Network",
            &["T1105"],
            &[],
            &["curl", "wget", "-o", "-O", "--output", "-d", "--data",
              "-X POST", "-k", "--insecure", "-s", "--silent"],
            &[
                "Prefetch: CURL.EXE-*.pf or WGET.EXE-*.pf",
                "Event Log: Security 4688 with URL arguments",
                "Event Log: Sysmon 1, 3 (outbound connections)",
                "Downloaded files at specified paths",
            ],
            "Examine URLs for payload download or C2 communication. Check for POST requests \
             (data exfiltration). Review downloaded file content. Common legitimate use.",
            70,
        ),
        tool(
            &["powershell.exe", "pwsh.exe", "powershell", "pwsh",
              "powershell_ise.exe"],
            "Windows PowerShell scripting engine. Extremely powerful dual-use tool; extensively \
             abused for download cradles, encoded commands, and fileless malware execution.",
            "Network",
            &["T1059.001"],
            &["APT29", "APT28", "FIN7", "Lazarus", "Wizard Spider",
              "MuddyWater", "Turla"],
            &["-enc", "-encodedcommand", "-nop", "-sta", "-w hidden",
              "iex", "invoke-expression", "downloadstring", "invoke-webrequest",
              "net.webclient", "-ep bypass", "frombase64string", "-noni",
              "invoke-mimikatz", "invoke-shellcode", "hidden -ep bypass -nop"],
            &[
                "Prefetch: POWERSHELL.EXE-*.pf or PWSH.EXE-*.pf",
                "Event Log: PowerShell 4104 (script block logging)",
                "Event Log: PowerShell 4103 (module logging)",
                "Event Log: Security 4688 (with command line)",
                "PowerShell console history: ConsoleHost_history.txt",
                "PowerShell transcription logs",
                "Event Log: Sysmon 1 (encoded arguments)",
            ],
            "Enable and review script block logging (4104) first. Decode any base64 commands. \
             Check console history file. Encoded + hidden + bypass is a strong malicious signal.",
            72,
        ),
        tool(
            &["cmd.exe", "cmd"],
            "Windows command interpreter. Ubiquitous dual-use shell; key forensic interest \
             is in parent-child process chains and command-line arguments.",
            "Network",
            &["T1059.003"],
            &[],
            &["cmd", "/c", "/k", "/q", "echo", "&&", "||", "^"],
            &[
                "Prefetch: CMD.EXE-*.pf",
                "Event Log: Security 4688 (with command line)",
                "Event Log: Sysmon 1 (parent-child chain)",
                "Command history (doskey /history if captured)",
            ],
            "Focus on parent process (Word, Excel, mshta = likely malicious). Examine full \
             command line for encoded content, chained commands, and unusual arguments.",
            70,
        ),

        // =====================================================================
        // SPECIALIZED
        // =====================================================================
        tool(
            &["mimipenguin", "mimipenguin.sh", "mimipenguin.py"],
            "Linux credential dumping tool inspired by mimikatz. Extracts cleartext \
             passwords from memory of processes such as gnome-keyring, sshd, and vsftpd.",
            "Specialized",
            &["T1003"],
            &[],
            &["mimipenguin", "gnome-keyring-daemon", "/proc/", "gcore"],
            &[
                "Bash history entries",
                "Process memory dumps",
                "/tmp/ artifacts from memory reading",
                "Auth.log entries",
            ],
            "Check bash history for execution. Examine /proc access patterns. Review \
             authentication logs for credential reuse following execution.",
            92,
        ),
        tool(
            &["lazagne.exe", "lazagne", "lazagne.py"],
            "Multi-purpose password recovery tool. Extracts stored credentials from \
             browsers, email clients, databases, Wi-Fi, and system vaults.",
            "Specialized",
            &["T1555", "T1555.003"],
            &["OilRig"],
            &["lazagne", "all", "browsers", "wifi", "sysadmin",
              "memory", "databases"],
            &[
                "Prefetch: LAZAGNE.EXE-*.pf",
                "Event Log: Security 4688",
                "Output file with recovered credentials",
                "Python execution artifacts (if .py variant)",
                "Access to browser credential stores",
            ],
            "Determine which credential stores were targeted. Search for output files \
             containing recovered passwords. Assess scope of compromised credentials.",
            93,
        ),
        tool(
            &["covenant", "covenant.exe", "grunt.exe", "grunt"],
            ".NET-based C2 framework. Provides web-based interface for managing implants \
             (Grunts) with support for multiple listeners, tasks, and lateral movement.",
            "C2 Framework",
            &["T1071.001", "T1059.001"],
            &[],
            &["covenant", "grunt", "GruntHTTP", "GruntSMB",
              "SharpSploit", "Rubeus", "Seatbelt"],
            &[
                "Event Log: Sysmon 1, 3 (HTTP connections to Covenant listener)",
                "Event Log: PowerShell 4104 (task execution)",
                "Network: HTTP beaconing with GruntHTTP profile",
                ".NET assembly artifacts in memory",
            ],
            "Identify C2 listener address from network traffic. Check for Grunt implant \
             artifacts. Review executed tasks and post-exploitation modules.",
            93,
        ),
        tool(
            &["sliver", "sliver-server", "sliver-client"],
            "Open-source C2 framework written in Go. Supports HTTP(S), mTLS, DNS, and \
             WireGuard transports with mutual TLS implant authentication.",
            "C2 Framework",
            &["T1071.001", "T1071.004", "T1573.002"],
            &[],
            &["sliver", "beacon", "session", "mtls", "wg",
              "dns", "generate", "implant"],
            &[
                "Event Log: Sysmon 1, 3 (C2 connections)",
                "Event Log: Sysmon 22 (DNS C2 queries)",
                "Network: mTLS connections to C2 server",
                "Network: DNS TXT record C2 traffic",
                "Go binary artifacts (large static binary)",
            ],
            "Identify transport method (mTLS, DNS, WireGuard). Extract C2 server address from \
             implant binary or network traffic. Check for pivoting and lateral movement.",
            93,
        ),
        tool(
            &["bruteratel", "brute ratel", "brc4", "badger.exe", "badger"],
            "Commercial adversary simulation framework (BRc4). Uses advanced evasion \
             techniques including indirect syscalls, ETW patching, and stack spoofing.",
            "C2 Framework",
            &["T1071.001", "T1055", "T1562.001"],
            &["Black Basta"],
            &["bruteratel", "brc4", "badger", "brute_ratel",
              "ratel"],
            &[
                "Event Log: Sysmon 1, 3 (C2 connections)",
                "Event Log: Sysmon 10 (process access for injection)",
                "Network: HTTP(S) beaconing with custom profile",
                "Memory: Badger payload artifacts",
                "ETW/AMSI bypass artifacts",
            ],
            "Indicates sophisticated adversary with commercial tooling. Analyze memory for Badger \
             payload. Check for ETW/AMSI tampering. Review for lateral movement and privilege \
             escalation.",
            95,
        ),
        tool(
            &["havoc", "havoc.exe", "demon.exe", "demon"],
            "Open-source C2 framework with modern evasion capabilities. Uses Demon agent \
             with indirect syscalls, sleep obfuscation, and module-based post-exploitation.",
            "C2 Framework",
            &["T1071.001", "T1055", "T1573"],
            &[],
            &["havoc", "demon", "teamserver", "yaotl",
              "sleep_obf", "dotnet_inline"],
            &[
                "Event Log: Sysmon 1, 3 (C2 connections)",
                "Event Log: Sysmon 8 (CreateRemoteThread for injection)",
                "Network: HTTP(S) beaconing pattern",
                "Memory: Demon agent artifacts",
                "Indirect syscall stubs in memory",
            ],
            "Identify C2 teamserver from network traffic. Analyze Demon agent configuration \
             from memory. Check for process injection and post-exploitation module execution.",
            93,
        ),
    ]
}
