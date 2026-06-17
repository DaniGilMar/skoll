# Evidence Collection Guide
# Auto-loads: In Phase EXPLOIT when generating POCs
# Token cost: ~400 tokens
# Purpose: Standardize evidence capture for client deliverables

## What Constitutes Valid Evidence

For penetration testing reports, each finding must include:

### 1. Discovery Evidence
```
Tool: nmap
Command: nmap -sV -sC -p 80 10.10.10.1
Output:
  PORT   STATE SERVICE VERSION
  80/tcp open  http    Apache httpd 2.4.29
```

### 2. Verification Evidence
```
Tool: whatweb
Command: whatweb http://10.10.10.1
Output:
  http://10.10.10.1 [200 OK] Apache[2.4.29], Title[Welcome]
```

### 3. Exploitation Evidence (if applicable)
```
Tool: curl / sqlmap / hydra
Command: curl -v http://10.10.10.1/?id=1' UNION SELECT 1,2,3--
Output:
  [EXACT request/response showing the vulnerability]
Payload: 1' UNION SELECT 1,2,3--
```

---

## Evidence Templates

### For Authentication Bypass
```
Finding: Default credentials on [service]
Severity: HIGH (CVSS: 7.3 AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L)
Affected: [host:port]
Command: hydra -l admin -P /usr/share/wordlists/rockyou.txt [target] [service]
Output:
  [HYDRA output showing successful login]
Credentials: admin:password123
Impact: Unauthorized access to [service], potential data breach
Remediation: Change default credentials, implement account lockout
```

### For SQL Injection
```
Finding: SQL Injection in [parameter]
Severity: CRITICAL (CVSS: 9.1 AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)
Affected: [url]
Request:
  GET /page?id=1' UNION SELECT 1,2,3-- HTTP/1.1
  Host: [target]
Response:
  [response excerpt showing injected data]
Payload: 1' UNION SELECT 1,2,3--
Impact: Full database read/write access, data exfiltration
Remediation: Use parameterized queries (prepared statements)
```

### For Directory Disclosure
```
Finding: Sensitive directory exposed on web server
Severity: MEDIUM (CVSS: 5.3 AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)
Affected: [url]
Command: gobuster dir -u [url] -w directory-list-2.3-small.txt
Output:
  /backup (Status: 200) [contents: backup.sql containing user hashes]
  /admin  (Status: 200) [login page]
Impact: Information disclosure, potential credential leak
Remediation: Remove sensitive directories, implement access controls
```

### For Version-Based Vulnerability
```
Finding: [Service] [version] — [CVE-ID]
Severity: [CRITICAL/HIGH/MEDIUM/LOW]
CVSS: [X.X] [vector]
Affected: [host:port/service]
Tool: nmap / whatweb / nikto
Evidence:
  [nmap service version output]
  [CVE details from searchsploit or NVD]
Impact: [CVE impact description]
Remediation: Upgrade to version [fixed version]
```

---

## Screenshot Guidelines

When capturing screenshots (via `capture_screenshot` action):
1. **Full window** — show the URL bar, response, and any relevant context
2. **Highlight** the vulnerability evidence (red box/arrow)
3. **Include** the payload/technique visible
4. **Filename format**: `finding-[id]-[description].png`

---

## Report Section Templates

### Executive Summary
```
## Executive Summary

Unauthorized Code Execution    [N] Critical
Authentication Bypass         [N] High  
Information Disclosure        [N] Medium
Missing Security Headers      [N] Low

Overall Risk Rating: [CRITICAL/HIGH/MEDIUM/LOW]
```
### Technical Finding
```
## [Finding ID]: [Title]
Severity: [SEVERITY]
CVSS v3.1: [X.X] [Vector]

### Description
[What the vulnerability is, in business context]

### Steps to Reproduce
1. [Step 1]
2. [Step 2]
3. [Step 3]

### Evidence
[Tool output, screenshot reference, request/response]

### Impact
[What an attacker can achieve]

### Recommendation
[How to fix it]
```

---

## Key Reminders
- **Never fabricate evidence** — reproducibility is what clients pay for
- **Timestamp everything** — each finding needs date/time of discovery
- **Redact sensitive data** in public evidence (but show enough to prove impact)
- **One finding per vulnerability** — don't merge or split artificially
- **Language** — findings in Spanish for Spanish-speaking clients
