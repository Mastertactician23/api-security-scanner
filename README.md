# API Security Scanner

### A Python tool that scans REST APIs for 15+ OWASP API Top 10 vulnerabilities and generates a full HTML pentest report with severity ratings, evidence, and remediation guidance

**Author:** Kofi Asibey-Kitiabi
**GitHub:** [Mastertactician23](https://github.com/Mastertactician23/)
**LinkedIn:** [asibey-kitiabi](https://www.linkedin.com/in/asibey-kitiabi/)
**Date:** July 2026
**Status:** Completed

---

## Table of Contents
1. [Project Overview](#1-project-overview)
2. [Vulnerabilities Tested](#2-vulnerabilities-tested)
3. [Tools & Technologies](#3-tools--technologies)
4. [Architecture](#4-architecture)
5. [How to Run It](#5-how-to-run-it)
6. [Scan Results](#6-scan-results)
7. [HTML Report](#7-html-report)
8. [MITRE ATT&CK Mapping](#8-mitre-attck-mapping)
9. [False Positive Validation](#9-false-positive-validation)
10. [Connection to Portfolio](#10-connection-to-portfolio)
11. [Skills Demonstrated](#11-skills-demonstrated)
12. [Known Limitations & Constraints](#12-known-limitations--constraints)
13. [What I Would Do Differently](#13-what-i-would-do-differently)
14. [Next Steps](#14-next-steps)

---

## 1. Project Overview

The API Security Scanner is a Python tool that performs automated security testing of REST APIs against 15 checks mapped to the OWASP API Security Top 10 (2023), plus SQL injection, XSS, JWT brute force, and HTTP method enumeration.

For each check the tool sends targeted HTTP requests, evaluates responses for vulnerability indicators, and records findings with full request/response evidence and remediation guidance. At the end it generates a colour-coded terminal report and a standalone HTML pentest report that opens in any browser.

**Two deliverables in one project:**
- `scanner.py` — the scanning tool
- `vulnerable_api.py` — a deliberately insecure Flask API built as the target, with one intentional flaw per OWASP category

This dual approach (building both the attacker tool and the vulnerable target) mirrors real-world penetration testing methodology: understand the vulnerability well enough to build it, then build the tool to find it.

---

## 2. Vulnerabilities Tested

| # | Check | OWASP ID | Severity |
|---|-------|----------|---------|
| 1 | Broken Object Level Authorization (BOLA/IDOR) | API1:2023 | Critical |
| 2 | BOLA on secondary resource (orders) | API1:2023 | High |
| 3 | Missing authentication on protected endpoint | API2:2023 | High |
| 4 | JWT none algorithm attack | API2:2023 | Critical |
| 5 | Default credentials accepted | API2:2023 | Critical |
| 6 | Excessive data exposure (SSN, card, password hash) | API3:2023 | High |
| 7 | Missing rate limiting (30 req/s accepted) | API4:2023 | High |
| 8 | Admin endpoint accessible without role check | API5:2023 | Critical |
| 9 | Server config exposed via admin endpoint | API5:2023 | Critical |
| 10 | Mass user enumeration via sequential IDs | API6:2023 | High |
| 11 | Server Side Request Forgery (SSRF) | API7:2023 | Critical |
| 12 | Missing security headers (5 headers absent) | API8:2023 | Medium |
| 13 | CORS wildcard misconfiguration | API8:2023 | High |
| 14 | Verbose error messages with stack traces | API8:2023 | Medium |
| 15 | Hidden endpoint discovery (/debug, /swagger, legacy routes) | API9:2023 | High |
| 16 | SQL injection via unsanitised query parameter | API8:2023 | Critical |
| 17 | XSS reflection in API response | API8:2023 | High |
| 18 | JWT weak secret brute force | API2:2023 | Critical |
| 19 | Unrestricted HTTP methods | API8:2023 | Medium |

---

## 3. Tools & Technologies

| Tool | Purpose |
|------|---------|
| Python 3 | Main scripting language |
| requests | HTTP client for all scan requests |
| Flask | Powers the deliberately vulnerable target API |
| PyJWT | JWT decoding for weak secret brute force check |
| colorama | Colour-coded terminal output |
| HTML/CSS | Self-contained pentest report generation |
| Docker | Container environment for all targets |
| VAmPI | Third-party vulnerable API for secondary scanning |

---

## 4. Architecture

```
scanner.py
    |
    | HTTP requests (GET, POST, OPTIONS, PUT, DELETE)
    v
Target API (one of three):
    1. vulnerable_api.py  — custom built target (localhost:8080)
    2. VAmPI vulnerable   — third-party OWASP target (vampi:5000)
    3. VAmPI secure       — hardened version for false positive testing (vampi-secure:5000)
    |
    v
findings[] → terminal report + HTML report + JSON report
```

**Why three targets:**
Testing against your own deliberately vulnerable API proves the scanner detects known flaws. Testing against VAmPI (a third-party target you didn't build) proves it generalises. Testing against VAmPI in secure mode proves it doesn't generate false positives on a hardened system — the professional standard for security tool validation.

---

## 5. How to Run It

**Prerequisites:** Python 3, Docker

**Install dependencies:**
```bash
pip install requests colorama PyJWT flask --break-system-packages
```

**Start the vulnerable target:**
```bash
python3 vulnerable_api.py &
```

**Run the scanner:**
```bash
# Against local target
python3 scanner.py --target http://localhost:8080

# Against VAmPI (pull first)
docker pull erev0s/vampi:latest
docker run -d --name vampi -p 5000:5000 erev0s/vampi:latest
python3 scanner.py --target http://localhost:5000

# Against VAmPI secure (false positive validation)
docker run -d --name vampi-secure -p 5052:5000 -e vulnerable=0 erev0s/vampi:latest
python3 scanner.py --target http://localhost:5052
```

**Reports are saved to:**
```
reports/scan_YYYYMMDD_HHMMSS.json   — structured JSON findings
reports/scan_YYYYMMDD_HHMMSS.html   — full HTML pentest report
```

---

## 6. Scan Results

### Target 1 — Custom Vulnerable API (localhost:8080)

```
Total checks    : 16
Vulnerabilities : 16
  Critical      : 7
  High          : 8
  Medium        : 1
Secure          : 0
Security Score  : 0%
Risk Rating     : CRITICAL
Duration        : 3.4s
```

All 7 Critical findings confirmed:
- BOLA/IDOR on user and order endpoints
- JWT none algorithm bypass
- Default credentials (admin:admin) accepted
- Admin config endpoint leaking JWT secret
- SSRF via /api/fetch endpoint
- SQL injection in search parameter
- JWT secret cracked in 3 attempts (secret: 'secret123')

### Target 2 — VAmPI Vulnerable Mode

Third-party target with different endpoint structure — scanner adapted dynamically. Key findings: BOLA on user books endpoint, missing authentication, excessive data exposure, no rate limiting.

### Target 3 — VAmPI Secure Mode (False Positive Validation)

Same scanner, same checks, hardened target. Result: significantly reduced finding count with most checks returning SECURE — confirming the scanner distinguishes between vulnerable and hardened configurations rather than generating noise.

---

## 7. HTML Report

The scanner generates a self-contained HTML report that opens in any browser. Features:

- Executive summary with risk rating and security score gauge
- Colour-coded severity breakdown (Critical / High / Medium / Low)
- Finding cards with full request/response evidence per vulnerability
- OWASP ID mapped to each finding
- Remediation recommendation per finding
- Passes/secure checks summary

See `reports/scan_report.html` for a sample report from the local scan.

---

## 8. MITRE ATT&CK Mapping

| Vulnerability | ATT&CK Technique | ID |
|--------------|------------------|----|
| BOLA/IDOR | Exploitation for Credential Access | T1212 |
| Broken Authentication | Valid Accounts | T1078 |
| JWT none algorithm | Forge Web Credentials | T1606 |
| SQL Injection | Exploit Public-Facing Application | T1190 |
| SSRF | Server-Side Request Forgery | T1190 |
| Hidden endpoint discovery | Active Scanning | T1595 |
| Missing rate limiting | Brute Force | T1110 |
| Admin endpoint exposure | Account Discovery | T1087 |
| XSS reflection | Drive-by Compromise | T1189 |

---

## 9. False Positive Validation

Running the scanner against VAmPI in both vulnerable (`vulnerable=1`) and secure (`vulnerable=0`) modes is a professional quality assurance technique used to validate security tools.

A scanner that finds everything on a hardened system is worse than useless — it trains analysts to ignore alerts. The comparison run confirms:

- **Vulnerable mode:** Multiple findings across all OWASP categories
- **Secure mode:** Significantly fewer findings, auth checks return SECURE, data exposure returns SECURE

This dual-target approach is the same methodology used by security teams evaluating commercial DAST tools like Burp Suite Enterprise and OWASP ZAP before deployment.

---

## 10. Connection to Portfolio

| Project | How it connects |
|---------|----------------|
| [MiniSOC](https://github.com/Mastertactician23/minisoc-threat-detection-lab) | Network-level attack detection — this project adds application-level API attack detection |
| [CIS Auditor](https://github.com/Mastertactician23/linux-cis-hardening-auditor) | OS hardening compliance — this project adds API-layer security assessment |
| [SSH Detector](https://github.com/Mastertactician23/ssh-brute-force-detector) | Detects brute force at network level — this project tests for missing rate limiting at the API level |
| [Security Dashboard](https://github.com/Mastertactician23/minisoc-security-dashboard) | Visualises network events — this project generates standalone HTML reports for API findings |

Together the five projects cover: network security, OS compliance, automated response, operational visibility, and application security — a complete security engineering portfolio.

---

## 11. Skills Demonstrated

- Python security tool development from scratch
- OWASP API Top 10 (2023) knowledge and practical testing
- HTTP request manipulation (headers, auth tokens, payloads)
- JWT security testing (none algorithm attack, weak secret brute force)
- SQL injection and XSS detection in API context
- SSRF testing and exploitation
- HTML report generation (no framework — pure Python string templating)
- Security tool validation methodology (false positive testing)
- Docker container management for multi-target testing
- Technical documentation

---

## 12. Known Limitations & Constraints

**RAM constraint — engineering decision:**
The lab environment runs on 8GB RAM with Docker Desktop allocated 3.7GB, shared across 4 existing containers. The OWASP crAPI (Completely Ridiculous API) was the intended real-world fintech-style target but requires 2–3GB RAM alone — more than half the total allocation — making it incompatible with the existing lab.

**Decision made:** Use VAmPI (50MB) as the third-party target instead. This was not a compromise — VAmPI was purpose-built for OWASP API Top 10 testing, includes proper authentication flows, and allowed the false positive validation run that crAPI would not have enabled (crAPI has no hardened mode).

**Scanner limitations:**
- Does not handle OAuth 2.0 flows or multi-step authentication sequences
- GraphQL scanning is limited to introspection check only
- No passive/traffic-based analysis — active probing only
- Rate limiting tests use fixed 30-request count

---

## 13. What I Would Do Differently

- Add OAuth 2.0 authentication flow support for more realistic target scanning
- Implement concurrent scanning with threading for faster results on large APIs
- Add a GraphQL security module (introspection, batching attacks, field suggestions)
- Build a CI/CD integration mode that exits non-zero on Critical findings
- Add PDF export of the HTML report

---

## 14. Next Steps

- [ ] Add OAuth 2.0 support
- [ ] Build GraphQL security module
- [ ] Test against OWASP Juice Shop API
- [ ] Sit CompTIA Security+ SY0-701
- [ ] Begin applying for remote SOC / AppSec Analyst roles

---

*Built on: Kali Linux 2026.2 inside Docker Desktop (WSL2 backend)*
*Targets: Custom Flask API + VAmPI (erev0s) + VAmPI secure mode*
*Purpose: Educational portfolio project — all scanning performed on local lab targets*
*Part of an active cybersecurity portfolio: [github.com/Mastertactician23](https://github.com/Mastertactician23)*
