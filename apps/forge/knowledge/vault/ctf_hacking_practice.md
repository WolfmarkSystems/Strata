# CTF & Hacking Practice Resources

## Capture The Flag (CTF) Platforms

### Practice Sites
| Platform | URL | Focus |
|----------|-----|-------|
| picoCTF | https://picoctf.org/ | Beginners |
| TryHackMe | https://tryhackme.com/ | All levels |
| HackTheBox | https://www.hackthebox.com/ | Advanced |
| Root Me | https://www.root-me.org/ | All levels |
| OverTheWire | https://overthewire.org/wargames/ | Beginners |
| PentesterLab | https://pentesterlab.com/ | Web, SSL |
| PortSwigger | https://portswigger.net/web-security | Web |

### Attack/Defense
- **CTF365**: https://ctf365.com/
- **Defcon CTF**: https://defcon.org/html/ctf.html

## CTF Categories

### Web Security
**Common Vulnerabilities**:
- SQL Injection
- XSS (Reflected, Stored, DOM)
- CSRF
- SSRF
- IDOR
- LFI/RFI
- XXE
- Command Injection
- Authentication bypasses
- Race conditions

**Tools**:
- Burp Suite
- OWASP ZAP
- SQLMap
- XSStrike
- Commix

### Reverse Engineering
**Topics**:
- Assembly (x86, x64, ARM)
- Debugging
- Packing/Obfuscation
- Decompiling

**Tools**:
- IDA Pro / Ghidra
- x64dbg / GDB
- Hopper
- Radare2

### Binary Exploitation
**Topics**:
- Buffer overflows
- ROP chains
- Format strings
- Heap exploitation
- Integer overflows
- Race conditions

**Resources**:
- pwnable.kr
- pwn.college
- ROP Emporium

### Cryptography
**Topics**:
- Classical ciphers
- Modern crypto (AES, RSA)
- Hash length extension
- ECB mode attacks
- CBC bit flipping
- RSA attacks (Coppersmith, Wiener)

### Forensics
**Topics**:
- File recovery
- Steganography
- Memory forensics
- Disk forensics
- Network packet analysis
- Log analysis

**Tools**:
- Wireshark
- Volatility
- Autopsy
- Foremost

### OSINT
**Techniques**:
- WHOIS lookups
- Social media investigation
- Google dorking
- Image analysis
- Metadata extraction

## Learning Paths

### Beginner (1-3 months)
1. **Networking**
   - TCP/IP fundamentals
   - Wireshark basics
   - HTTP/HTTPS
   
2. **Linux**
   - Command line proficiency
   - Bash scripting
   - Permissions
   
3. **Python**
   - Basic scripting
   - Network programming
   
4. **Web**
   - HTML/CSS/JS
   - How browsers work

### Intermediate (3-6 months)
1. **Web Security**
   - OWASP Top 10
   - Burp Suite
   
2. **Reverse Engineering**
   - x86 assembly
   - Ghidra basics
   
3. **Malware Analysis**
   - Static analysis
   - Dynamic analysis

### Advanced (6-12 months)
1. **Binary Exploitation**
   - Buffer overflows
   - ROP
   
2. **CTF Competition**
   - Team practice
   
3. **Specialization**
   - Mobile, hardware, etc.

## Practice Writeups

### Sites with Writeups
- **CTF Writeups**: https://ctftime.org/writeups
- **0x41414141**: https://ctf-team.vulnhub.com/
- **Rainbow Rabbit**: https://github.com/easysec/gaining-continues

### Learning from Writeups
1. Try the challenge yourself first
2. Read writeup for what you missed
3. Replicate the solution
4. Research new techniques

## Certifications

### Entry Level
- **CompTIA Security+**: https://www.comptia.org/certifications/security
- **eJPT**: https://www.elearnsecurity.com/certification/ejpt/

### Intermediate
- **OSCP**: https://www.offensive-security.com/pwk-oscp/
- **CEH**: https://www.eccouncil.org/train-certify/ceh-certified-ethical-hacker/

### Advanced
- **OSEP**: https://www.offensive-security.com/pen300-osep/
- **OSCE3**: OSEE + OSEE
- **GPEN**: https://www.giac.org/paper/gpen/pen-testers/

## Essential Tools

### Network
```bash
# Recon
nmap -sV -sC target
rustscan -a target

# Traffic
wireshark
tcpdump

# WiFi
aircrack-ng
```

### Web
```bash
# Scanning
nikto -h target
gobuster dir -u target
ffuf

# Proxy
burpsuite
```

### Password
```bash
# Hash cracking
hashcat -m 0 hashes.txt wordlist.txt
john hashes.txt --wordlist=wordlist.txt

# Password lists
seclists
```

### Exploitation
```bash
# Frameworks
msfconsole
searchsploit
```

## Bug Bounty Platforms

| Platform | URL |
|----------|-----|
| HackerOne | https://www.hackerone.com/ |
| Bugcrowd | https://www.bugcrowd.com/ |
| Intigriti | https://www.intigriti.com/ |
| Open Bug Bounty | https://www.openbugbounty.org/ |

## CTF Write-up Templates

### Format
```
# Challenge Name
**Category**: Web
**Points**: 100
**Solves**: 500
**Difficulty**: Easy

## Description
[Challenge description]

## Solution
1. Initial observation
2. Finding the vulnerability
3. Exploitation
4. Getting the flag

## Flag
flag{...}
```

## Books

### Beginner
- "The Web Application Hacker's Handbook"
- "Hacking: The Art of Exploitation"
- "Metasploit: The Penetration Tester's Guide"

### Intermediate
- "The IDA Pro Book"
- "Practical Malware Analysis"
- "The Practice of Network Security Monitoring"

### Advanced
- "A Guide to Kernel Exploitation"
- "Reversing: Secrets of Reverse Engineering"

## Communities

- **r/ctf**: Reddit CTF
- **r/hacking**: General hacking
- **r/netsec**: Security research
- **Discord**: CTFtime Discord
- **IRC**: #ctf on Libera.Chat
