# Programming Languages Knowledge Base

## Overview
Wolf Sentinel can assist with coding in multiple programming languages. This knowledge base contains resources and best practices for various languages commonly used in DFIR, cybersecurity, and software development.

---

## Python

### Free Learning Resources
- **Official Docs**: https://docs.python.org/3/
- **Real Python**: https://realpython.com/ - High-quality tutorials
- **Python.org Tutorial**: https://docs.python.org/3/tutorial/
- **Automate the Boring Stuff**: https://automatetheboringstuff.com/ - Practical automation
- **FreeCodeCamp**: https://www.freecodecamp.org/learn/python/

### DFIR-Specific Python
- **SANS Institute**: https://www.sans.org/cyber-security-training/search/?keyword=python
- **Python for Security (Cybrary)**: https://www.cybrary.it/course/python-for-security-professionals/

### Best Practices
- Use virtual environments (`python -m venv venv`)
- Prefer type hints for large projects
- Use `black` for formatting, `ruff` for linting
- Security: Never use `eval()` on untrusted input

---

## C/C++

### Free Learning Resources
- **Learn C**: https://www.learn-c.org/
- **C++ Primer (free)**: https://www.learncpp.com/
- **Cprogramming.com**: https://www.cprogramming.com/

### DFIR-Specific C/C++
- Memory forensics, volatility plugins
- Malware analysis
- Windows API programming

### Best Practices
- Use `malloc`/`free` carefully or prefer smart pointers
- Prefer C++11+ features (smart pointers, range-based for)
- Security: Buffer overflow prevention, safe string functions (`strncpy` vs `strcpy`)

---

## C#

### Free Learning Resources
- **Microsoft Learn**: https://learn.microsoft.com/en-us/training/csharp/
- **C# Corner**: https://www.c-sharpcorner.com/
- **.NET Fiddle**: https://dotnetfiddle.net/ - Practice online

### DFIR-Specific C#
- .NET malware analysis
- Windows forensics tools
- Active Directory enumeration

### Best Practices
- Use `using` statements for resource disposal
- Prefer `string interpolation` over concatenation
- Enable nullable reference types

---

## JavaScript / TypeScript

### Free Learning Resources
- **MDN Web Docs**: https://developer.mozilla.org/en-US/docs/Web/JavaScript
- **JavaScript.info**: https://javascript.info/
- **FreeCodeCamp**: https://www.freecodecamp.org/learn/javascript-algorithms-and-data-structures/

### DFIR-Specific JavaScript
- Browser forensics
- Malicious script analysis
- Node.js forensics

### Best Practices
- Use TypeScript for large projects
- Prefer `const`/`let` over `var`
- Use ESLint and Prettier

---

## Go (Golang)

### Free Learning Resources
- **Go by Example**: https://gobyexample.com/
- **A Tour of Go**: https://go.dev/tour/welcome/1
- **Official Docs**: https://go.dev/doc/

### DFIR-Specific Go
- Malware analysis tools
- Cross-platform forensics tools
- Network forensics

### Best Practices
- Run `go fmt` for formatting
- Use `go vet` for static analysis
- Concurrency: Use goroutines and channels, not threads

---

## PowerShell

### Free Learning Resources
- **Microsoft Docs**: https://docs.microsoft.com/en-us/powershell/
- **PowerShell Gallery**: https://www.powershellgallery.com/
- **SS64**: https://ss64.com/ps/

### DFIR-Specific PowerShell
- Windows forensics
- Incident response automation
- Active Directory enumeration
- EDR bypass research

### Best Practices
- Use `-Confirm` for destructive operations
- Prefer cmdlets over external executables
- Use `Get-Help` for documentation

---

## Bash

### Free Learning Resources
- **Bash Guide**: https://mywiki.wooledge.org/BashGuide
- **ShellCheck**: https://www.shellcheck.net/ - Linter

### DFIR-Specific Bash
- Linux forensics
- Log analysis
- Automation scripts

### Best Practices
- Use `set -euo pipefail`
- Quote variables
- Use `[[ ]]` for tests, not `[ ]`

---

## Java

### Free Learning Resources
- **Oracle Java Tutorials**: https://docs.oracle.com/javase/tutorial/
- **JetBrains Academy**: https://www.jetbrains.com/academy/

### Best Practices
- Use streams and lambdas (Java 8+)
- Prefer composition over inheritance
- Use Lombok to reduce boilerplate

---

## Ruby

### Free Learning Resources
- **Ruby-lang.org**: https://www.ruby-lang.org/en/documentation/
- **Why's Poignant Guide**: https://poignant.guide/

### DFIR-Specific Ruby
- Metasploit framework
- Malware analysis

---

## Assembly (x86/x64)

### Free Learning Resources
- **Sandman**: https://www.sandman.pl/
- **Assembly Language for Beginners**: https://yurichev.com/Assembly/
- **Azeria Labs**: https://azeria-labs.com/writing-arm-assembly-notes/

### DFIR-Specific Assembly
- Malware analysis
- Reverse engineering
- Exploit development

---

## SQL

### Free Learning Resources
- **SQLZOO**: https://sqlzoo.net/
- **Mode Analytics SQL Tutorial**: https://mode.com/sql-tutorial/

### DFIR-Specific SQL
- Database forensics
- Log analysis

---

## General Programming Resources

### Computer Science Free Curriculum
- **OSSU Computer Science**: https://github.com/ossu/computer-science
- **CS50**: https://cs50.harvard.edu/x/

### Practice Platforms
- **LeetCode**: https://leetcode.com/
- **HackerRank**: https://www.hackerrank.com/
- **Codewars**: https://www.codewars.com/

### Security-Specific Training
- **OWASP**: https://owasp.org/
- **PortSwigger Web Security Academy**: https://portswigger.net/web-security
- **PentesterLab**: https://pentesterlab.com/

---

## Language Selection Guide

| Use Case | Recommended Language |
|----------|---------------------|
| Windows automation | PowerShell, C# |
| Linux forensics | Python, Bash |
| Cross-platform tools | Go, Rust, Python |
| Malware analysis | Python, C/C++, Assembly |
| Web forensics | JavaScript, Python |
| Speed-critical | Rust, C/C++, Go |
| Rapid prototyping | Python, JavaScript |

---

## Wolf Sentinel Capabilities

Wolf Sentinel can help you:
- Write code in any of the above languages
- Review and debug code
- Explain language concepts
- Convert code between languages
- Suggest best practices
- Help with security vulnerabilities
- Assist with DFIR-specific tooling

When asking for help, specify:
1. The language you want to use
2. What you're trying to accomplish
3. Any constraints (cross-platform, no external dependencies, etc.)
