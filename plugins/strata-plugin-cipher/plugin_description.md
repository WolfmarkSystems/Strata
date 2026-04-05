# Strata Cipher Plugin v2.0

Cipher detects and extracts credential stores, encryption key material, and authentication artifacts across forensic images. It identifies saved browser passwords (Chrome, Firefox), SSH keys, certificates, DPAPI credential blobs, remote access tool sessions, cloud synchronization activity, and FTP saved credentials.

## Detection Categories

- **Browser Credentials** -- Chrome Login Data / Web Data, Firefox logins.json
- **SSH Keys** -- known_hosts, authorized_keys, private keys (RSA, Ed25519, ECDSA, DSA)
- **Certificates** -- PEM, PFX, P12, CRT files
- **Windows Credentials** -- DPAPI encrypted credential blobs under Microsoft\Credentials
- **Remote Access Tools** -- TeamViewer, AnyDesk, LogMeIn session artifacts
- **Cloud & Sync** -- OneDrive sync logs, Dropbox activity, Google DriveFS artifacts
- **FTP Saved Credentials** -- FileZilla recentservers.xml and sitemanager.xml

## MITRE ATT&CK Coverage

| Technique | Description |
|-----------|-------------|
| T1555.003 | Credentials from Web Browsers |
| T1555     | Credentials from Password Stores (DPAPI) |
| T1021.004 | Remote Services: SSH |
| T1219     | Remote Access Software |
| T1567.002 | Exfiltration Over Web Service: Exfiltration to Cloud Storage |
| T1552.001 | Unsecured Credentials: Credentials In Files |

## Exfiltration Awareness

Cipher flags cloud synchronization artifacts that may indicate data exfiltration through legitimate services (OneDrive, Dropbox, Google Drive). Remote access tool detection covers common lateral movement and unauthorized access vectors.
