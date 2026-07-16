#!/usr/bin/env python3
"""
API Security Scanner
Author: Kofi Asibey-Kitiabi
Description: Scans REST APIs for 15+ vulnerabilities mapped to OWASP API Top 10.
             Produces colour-coded terminal output and a full HTML pentest report.
GitHub: https://github.com/Mastertactician23/api-security-scanner
"""

import requests
import json
import os
import sys
import time
import argparse
from datetime import datetime
from urllib.parse import urljoin

# Suppress SSL warnings for testing
requests.packages.urllib3.disable_warnings()

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLOUR = True
except ImportError:
    COLOUR = False

# ──────────────────────────────────────────────
# COLOUR HELPERS
# ──────────────────────────────────────────────

def red(t):    return Fore.RED + t + Style.RESET_ALL if COLOUR else t
def green(t):  return Fore.GREEN + t + Style.RESET_ALL if COLOUR else t
def yellow(t): return Fore.YELLOW + t + Style.RESET_ALL if COLOUR else t
def cyan(t):   return Fore.CYAN + t + Style.RESET_ALL if COLOUR else t
def bold(t):   return Style.BRIGHT + t + Style.RESET_ALL if COLOUR else t
def magenta(t):return Fore.MAGENTA + t + Style.RESET_ALL if COLOUR else t


# ──────────────────────────────────────────────
# REQUEST HELPER
# ──────────────────────────────────────────────

def req(method, url, **kwargs):
    """Safe request wrapper — never raises, always returns response or None."""
    try:
        kwargs.setdefault("timeout", 8)
        kwargs.setdefault("verify", False)
        kwargs.setdefault("allow_redirects", True)
        return requests.request(method, url, **kwargs)
    except requests.exceptions.ConnectionError:
        return None
    except requests.exceptions.Timeout:
        return None
    except Exception:
        return None


# ──────────────────────────────────────────────
# FINDING BUILDER
# ──────────────────────────────────────────────

def finding(owasp_id, name, severity, status, detail, evidence=None, remediation=None):
    return {
        "owasp_id": owasp_id,
        "name": name,
        "severity": severity,
        "status": status,
        "detail": detail,
        "evidence": evidence or "",
        "remediation": remediation or "",
        "timestamp": datetime.now().isoformat()
    }


# ──────────────────────────────────────────────
# CHECK FUNCTIONS
# ──────────────────────────────────────────────

def check_bola(base, token):
    """API1 — Broken Object Level Authorization (IDOR)"""
    print(cyan("  [API1] Testing BOLA / IDOR..."))
    findings = []

    # Try accessing user 2 as user 1 (or unauthenticated)
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    r = req("GET", f"{base}/api/users/2", headers=headers)
    if r and r.status_code == 200:
        data = r.text[:200]
        findings.append(finding(
            "API1:2023", "Broken Object Level Authorization (BOLA)",
            "Critical", "VULNERABLE",
            "Accessed another user's data (/api/users/2) without ownership verification.",
            f"GET /api/users/2 → HTTP {r.status_code}: {data}",
            "Implement object-level authorization checks. Verify the requesting user owns the resource before returning data."
        ))
        print(red(f"    [CRITICAL] BOLA confirmed — /api/users/2 accessible"))
    else:
        findings.append(finding("API1:2023", "Broken Object Level Authorization",
            "Critical", "SECURE", "Object-level authorization appears to be enforced."))
        print(green("    [SECURE] BOLA check passed"))

    # Try order IDOR
    r2 = req("GET", f"{base}/api/orders/1", headers=headers)
    if r2 and r2.status_code == 200:
        findings.append(finding(
            "API1:2023", "BOLA — Order Resource",
            "High", "VULNERABLE",
            "Order data accessible without ownership verification.",
            f"GET /api/orders/1 → HTTP {r2.status_code}: {r2.text[:150]}",
            "Verify order ownership before returning order data."
        ))
        print(red("    [HIGH] BOLA on /api/orders/1 confirmed"))

    return findings


def check_broken_auth(base):
    """API2 — Broken Authentication"""
    print(cyan("  [API2] Testing Broken Authentication..."))
    findings = []

    # Test unauthenticated access to protected endpoint
    r = req("GET", f"{base}/api/profile")
    if r and r.status_code == 200:
        findings.append(finding(
            "API2:2023", "Missing Authentication",
            "High", "VULNERABLE",
            "Protected endpoint /api/profile returns data without any authentication.",
            f"GET /api/profile (no token) → HTTP {r.status_code}: {r.text[:200]}",
            "Require valid JWT token for all non-public endpoints. Return 401 Unauthorized for missing tokens."
        ))
        print(red("    [HIGH] Unauthenticated access to /api/profile confirmed"))

    # Test JWT none algorithm attack
    import base64
    header = base64.b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip("=")
    payload = base64.b64encode(b'{"user_id":1,"username":"admin","role":"admin"}').decode().rstrip("=")
    none_token = f"{header}.{payload}."
    r2 = req("GET", f"{base}/api/users/1",
             headers={"Authorization": f"Bearer {none_token}"})
    if r2 and r2.status_code == 200:
        findings.append(finding(
            "API2:2023", "JWT None Algorithm Attack",
            "Critical", "VULNERABLE",
            "API accepts JWT tokens signed with 'none' algorithm, bypassing signature verification entirely.",
            f"JWT alg:none token accepted → HTTP {r2.status_code}",
            "Explicitly reject 'none' algorithm in JWT validation. Use a strong secret and enforce HS256 or RS256."
        ))
        print(red("    [CRITICAL] JWT none algorithm attack succeeded"))

    # Test default credentials
    r3 = req("POST", f"{base}/api/login",
             json={"username": "admin", "password": "admin"},
             headers={"Content-Type": "application/json"})
    if r3 and r3.status_code == 200 and "token" in r3.text:
        findings.append(finding(
            "API2:2023", "Default Credentials Accepted",
            "Critical", "VULNERABLE",
            "Default credentials admin:admin successfully authenticated.",
            f"POST /api/login admin:admin → HTTP {r3.status_code}: token returned",
            "Enforce strong password policy. Reject common/default credentials. Implement credential breach checking."
        ))
        print(red("    [CRITICAL] Default credentials admin:admin accepted"))
        return findings, r3.json().get("token", "")

    if not findings:
        print(green("    [SECURE] Authentication checks passed"))
    return findings, ""


def check_excessive_data(base, token):
    """API3 — Broken Object Property Level Authorization / Excessive Data Exposure"""
    print(cyan("  [API3] Testing Excessive Data Exposure..."))
    findings = []
    headers = {"Authorization": f"Bearer {token}"} if token else {}

    r = req("GET", f"{base}/api/users/1", headers=headers)
    if r and r.status_code == 200:
        data = r.json() if r.headers.get("content-type","").startswith("application/json") else {}
        sensitive_fields = ["password", "password_hash", "ssn", "credit_card", "secret", "token"]
        found = [f for f in sensitive_fields if f in r.text.lower()]
        if found:
            findings.append(finding(
                "API3:2023", "Excessive Data Exposure / Mass Assignment",
                "High", "VULNERABLE",
                f"API response contains sensitive fields that should never be returned: {', '.join(found)}",
                f"GET /api/users/1 → fields found: {found}\nSample: {r.text[:300]}",
                "Filter API responses to return only necessary fields. Never return password hashes, SSNs, or card numbers."
            ))
            print(red(f"    [HIGH] Sensitive fields in response: {found}"))
        else:
            print(green("    [SECURE] No excessive data exposure detected"))
    return findings


def check_rate_limiting(base):
    """API4 — Unrestricted Resource Consumption / Missing Rate Limiting"""
    print(cyan("  [API4] Testing Rate Limiting..."))
    findings = []
    start = time.time()
    responses = []

    for i in range(30):
        r = req("POST", f"{base}/api/login",
                json={"username": f"user{i}", "password": "wrongpass"},
                headers={"Content-Type": "application/json"})
        if r:
            responses.append(r.status_code)

    elapsed = time.time() - start
    rate_limited = any(s == 429 for s in responses)

    if not rate_limited:
        findings.append(finding(
            "API4:2023", "Missing Rate Limiting",
            "High", "VULNERABLE",
            f"Sent 30 requests in {elapsed:.1f}s with no rate limiting response (no 429 status code returned).",
            f"30x POST /api/login in {elapsed:.1f}s → status codes: {set(responses)}",
            "Implement rate limiting (e.g. 5 requests/minute per IP). Return 429 Too Many Requests. Consider account lockout after 5 failed attempts."
        ))
        print(red(f"    [HIGH] No rate limiting — 30 requests in {elapsed:.1f}s, all accepted"))
    else:
        print(green("    [SECURE] Rate limiting detected (429 returned)"))
    return findings


def check_broken_function_auth(base, token):
    """API5 — Broken Function Level Authorization"""
    print(cyan("  [API5] Testing Broken Function Level Authorization..."))
    findings = []
    headers = {"Authorization": f"Bearer {token}"} if token else {}

    admin_endpoints = [
        "/api/admin/users",
        "/api/admin/config",
        "/api/admin/logs",
        "/api/admin/settings"
    ]

    for ep in admin_endpoints:
        r = req("GET", f"{base}{ep}", headers=headers)
        if r and r.status_code == 200:
            findings.append(finding(
                "API5:2023", f"Broken Function Level Authorization — {ep}",
                "Critical", "VULNERABLE",
                f"Admin endpoint {ep} accessible without admin role verification.",
                f"GET {ep} → HTTP {r.status_code}: {r.text[:200]}",
                "Implement role-based access control (RBAC). Verify user role == 'admin' before processing admin requests."
            ))
            print(red(f"    [CRITICAL] Admin endpoint {ep} accessible"))

    if not findings:
        print(green("    [SECURE] Function-level authorization checks passed"))
    return findings


def check_mass_enumeration(base, token):
    """API6 — Unrestricted Access to Sensitive Business Flows"""
    print(cyan("  [API6] Testing Mass Enumeration..."))
    findings = []
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    accessible = []

    for uid in range(1, 6):
        r = req("GET", f"{base}/api/users/{uid}", headers=headers)
        if r and r.status_code == 200:
            accessible.append(uid)

    if len(accessible) > 1:
        findings.append(finding(
            "API6:2023", "Mass User Enumeration",
            "High", "VULNERABLE",
            f"Successfully enumerated {len(accessible)} user records by iterating IDs (IDs accessed: {accessible}).",
            f"GET /api/users/{{1..5}} → accessible IDs: {accessible}",
            "Implement rate limiting per user. Use non-sequential UUIDs instead of integer IDs. Add CAPTCHA for high-volume requests."
        ))
        print(red(f"    [HIGH] Mass enumeration — accessed user IDs: {accessible}"))
    else:
        print(green("    [SECURE] Mass enumeration appears restricted"))
    return findings


def check_ssrf(base):
    """API7 — Server Side Request Forgery"""
    print(cyan("  [API7] Testing SSRF..."))
    findings = []
    ssrf_payloads = [
        "http://169.254.169.254/latest/meta-data/",
        "http://localhost:8080/debug",
        "http://127.0.0.1:8080/api/admin/config",
        "file:///etc/passwd"
    ]

    for payload in ssrf_payloads:
        r = req("POST", f"{base}/api/fetch",
                json={"url": payload},
                headers={"Content-Type": "application/json"})
        if r and r.status_code == 200:
            data = r.json() if r.headers.get("content-type","").startswith("application/json") else {}
            if data.get("status") == "fetched" or "content" in data:
                findings.append(finding(
                    "API7:2023", "Server Side Request Forgery (SSRF)",
                    "Critical", "VULNERABLE",
                    f"API fetched internal URL: {payload}",
                    f"POST /api/fetch url={payload} → {r.text[:300]}",
                    "Validate and whitelist allowed URL schemes and hosts. Block requests to internal IP ranges (RFC 1918) and metadata endpoints."
                ))
                print(red(f"    [CRITICAL] SSRF confirmed — fetched {payload}"))
                break

    if not findings:
        print(green("    [SECURE] SSRF test passed"))
    return findings


def check_security_misconfig(base):
    """API8 — Security Misconfiguration"""
    print(cyan("  [API8] Testing Security Misconfiguration..."))
    findings = []

    r = req("GET", f"{base}/health")
    if not r:
        print(yellow("    [WARN] Target unreachable for header check"))
        return findings

    required_headers = {
        "X-Content-Type-Options": "Prevents MIME-type sniffing attacks",
        "X-Frame-Options": "Prevents clickjacking attacks",
        "Content-Security-Policy": "Prevents XSS and injection attacks",
        "Strict-Transport-Security": "Enforces HTTPS connections",
        "X-XSS-Protection": "Legacy XSS protection for older browsers"
    }

    missing = []
    for header, desc in required_headers.items():
        if header not in r.headers:
            missing.append(f"{header} ({desc})")

    if missing:
        findings.append(finding(
            "API8:2023", "Missing Security Headers",
            "Medium", "VULNERABLE",
            f"Response missing {len(missing)} recommended security headers.",
            f"Missing headers:\n" + "\n".join(f"  - {h}" for h in missing),
            "Add all recommended security headers to every API response. Use a security headers middleware."
        ))
        print(yellow(f"    [MEDIUM] Missing {len(missing)} security headers"))

    # Check CORS
    r2 = req("OPTIONS", f"{base}/api/users/1",
             headers={"Origin": "https://evil.attacker.com",
                      "Access-Control-Request-Method": "GET"})
    if r2 and r2.headers.get("Access-Control-Allow-Origin") == "*":
        findings.append(finding(
            "API8:2023", "CORS Wildcard Misconfiguration",
            "High", "VULNERABLE",
            "API returns Access-Control-Allow-Origin: * allowing any domain to make cross-origin requests.",
            f"OPTIONS /api/users/1 Origin:evil.attacker.com → Access-Control-Allow-Origin: *",
            "Restrict CORS to specific trusted origins. Never use wildcard (*) for authenticated APIs."
        ))
        print(red("    [HIGH] CORS wildcard misconfiguration confirmed"))

    # Check verbose errors
    r3 = req("GET", f"{base}/api/search?q=' OR '1'='1")
    if r3 and ("traceback" in r3.text.lower() or "sqlite" in r3.text.lower()):
        findings.append(finding(
            "API8:2023", "Verbose Error Messages",
            "Medium", "VULNERABLE",
            "API returns detailed error messages including stack traces and database information.",
            f"Error response sample: {r3.text[:300]}",
            "Return generic error messages to clients. Log detailed errors server-side only."
        ))
        print(red("    [MEDIUM] Verbose errors expose internals"))

    if not findings:
        print(green("    [SECURE] Security configuration checks passed"))
    return findings


def check_inventory(base):
    """API9 — Improper Inventory Management"""
    print(cyan("  [API9] Testing Improper Inventory Management..."))
    findings = []

    hidden_endpoints = [
        "/debug", "/swagger", "/swagger.json", "/api-docs",
        "/v1/users/1", "/v2/users/1", "/api/v1/users",
        "/health", "/metrics", "/status", "/info",
        "/actuator", "/actuator/health", "/.env",
        "/api/admin/config", "/graphql", "/graphiql"
    ]

    discovered = []
    for ep in hidden_endpoints:
        r = req("GET", f"{base}{ep}")
        if r and r.status_code in [200, 201, 301, 302]:
            discovered.append(f"{ep} (HTTP {r.status_code})")

    if discovered:
        findings.append(finding(
            "API9:2023", "Improper Inventory Management — Hidden Endpoints",
            "High", "VULNERABLE",
            f"Discovered {len(discovered)} undocumented or legacy endpoints through probing.",
            "Discovered endpoints:\n" + "\n".join(f"  - {e}" for e in discovered),
            "Maintain an API inventory. Disable debug, legacy, and undocumented endpoints in production. Use API gateway to enforce endpoint allowlisting."
        ))
        print(red(f"    [HIGH] Discovered {len(discovered)} hidden endpoints: {discovered}"))
    else:
        print(green("    [SECURE] No hidden endpoints discovered"))
    return findings


def check_sql_injection(base):
    """SQL Injection — common API attack beyond OWASP API10"""
    print(cyan("  [SQL] Testing SQL Injection..."))
    findings = []

    payloads = [
        ("' OR '1'='1", "Boolean-based SQLi"),
        ("' OR 1=1--", "Comment-based SQLi"),
        ("'; DROP TABLE users;--", "Destructive SQLi payload"),
        ("' UNION SELECT 1,2,3,4,5,6,7--", "UNION-based SQLi"),
    ]

    for payload, ptype in payloads:
        r = req("GET", f"{base}/api/search", params={"q": payload})
        if r and r.status_code == 200:
            response_text = r.text.lower()
            indicators = ["sqlite", "sql", "syntax error", "1=1", "union", "select"]
            if any(ind in response_text for ind in indicators) or len(r.json().get("results", [])) > 0:
                findings.append(finding(
                    "API8:2023", f"SQL Injection — {ptype}",
                    "Critical", "VULNERABLE",
                    f"SQL injection payload '{payload}' produced suspicious response.",
                    f"GET /api/search?q={payload} → HTTP {r.status_code}: {r.text[:300]}",
                    "Use parameterized queries / prepared statements. Never concatenate user input into SQL strings. Use an ORM."
                ))
                print(red(f"    [CRITICAL] SQL injection confirmed with payload: {payload}"))
                break

    if not findings:
        print(green("    [SECURE] SQL injection tests passed"))
    return findings


def check_xss(base):
    """XSS in API responses"""
    print(cyan("  [XSS] Testing XSS in API responses..."))
    findings = []
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)"
    ]

    for payload in xss_payloads:
        r = req("POST", f"{base}/api/comment",
                json={"text": payload},
                headers={"Content-Type": "application/json"})
        if r and r.status_code == 200 and payload in r.text:
            findings.append(finding(
                "API8:2023", "Cross-Site Scripting (XSS) in API Response",
                "High", "VULNERABLE",
                f"API reflects unsanitised input in response — XSS payload returned unencoded.",
                f"POST /api/comment text='{payload}' → {r.text[:300]}",
                "Sanitise all user input before returning in responses. Use Content-Security-Policy header. Encode output."
            ))
            print(red(f"    [HIGH] XSS reflection confirmed"))
            break

    if not findings:
        print(green("    [SECURE] XSS tests passed"))
    return findings


def check_jwt_brute(base):
    """JWT weak secret brute force"""
    print(cyan("  [JWT] Testing JWT Secret Strength..."))
    findings = []
    common_secrets = [
        "secret", "secret123", "password", "jwt_secret",
        "mysecret", "12345", "changeme", "supersecret", "admin"
    ]

    # Get a real token first
    r = req("POST", f"{base}/api/login",
            json={"username": "admin", "password": "admin123"},
            headers={"Content-Type": "application/json"})
    if not r or r.status_code != 200:
        print(yellow("    [SKIP] Could not obtain token for JWT brute force test"))
        return findings

    token = r.json().get("token", "")
    if not token:
        return findings

    try:
        import jwt as pyjwt
        for secret in common_secrets:
            try:
                pyjwt.decode(token, secret, algorithms=["HS256"])
                findings.append(finding(
                    "API2:2023", "JWT Weak Secret",
                    "Critical", "VULNERABLE",
                    f"JWT token signed with common/weak secret: '{secret}'",
                    f"Successfully decoded JWT with secret: '{secret}'",
                    "Use a cryptographically random secret of at least 256 bits. Store it securely (env var or secrets manager). Rotate regularly."
                ))
                print(red(f"    [CRITICAL] JWT weak secret cracked: '{secret}'"))
                return findings
            except Exception:
                continue
    except ImportError:
        print(yellow("    [SKIP] PyJWT not installed — skipping JWT brute force"))
        return findings

    print(green("    [SECURE] JWT secret is not a common value"))
    return findings


def check_http_methods(base):
    """Check for unrestricted HTTP methods"""
    print(cyan("  [METHODS] Testing Unrestricted HTTP Methods..."))
    findings = []
    methods = ["PUT", "DELETE", "PATCH", "TRACE", "CONNECT"]
    unexpected = []

    for method in methods:
        r = req(method, f"{base}/api/users/1")
        if r and r.status_code not in [405, 404, 501]:
            unexpected.append(f"{method} → HTTP {r.status_code}")

    if unexpected:
        findings.append(finding(
            "API8:2023", "Unrestricted HTTP Methods",
            "Medium", "VULNERABLE",
            f"API responds to unexpected HTTP methods that should be blocked.",
            "Unexpected methods accepted:\n" + "\n".join(f"  - {m}" for m in unexpected),
            "Explicitly allowlist permitted HTTP methods per endpoint. Return 405 Method Not Allowed for all others."
        ))
        print(yellow(f"    [MEDIUM] Unexpected HTTP methods accepted: {unexpected}"))
    else:
        print(green("    [SECURE] HTTP method restrictions in place"))
    return findings


# ──────────────────────────────────────────────
# HTML REPORT GENERATOR
# ──────────────────────────────────────────────

def generate_html_report(target, all_findings, scan_meta):
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    severity_colors = {
        "Critical": "#f85149",
        "High": "#d29922",
        "Medium": "#388bfd",
        "Low": "#3fb950",
        "Info": "#8b949e"
    }
    severity_bg = {
        "Critical": "#2d1515",
        "High": "#2d2415",
        "Medium": "#151e2d",
        "Low": "#152d1e",
        "Info": "#1c2128"
    }

    vuln = [f for f in all_findings if f["status"] == "VULNERABLE"]
    secure = [f for f in all_findings if f["status"] == "SECURE"]
    total = len(all_findings)
    vuln_count = len(vuln)

    critical = len([f for f in vuln if f["severity"] == "Critical"])
    high = len([f for f in vuln if f["severity"] == "High"])
    medium = len([f for f in vuln if f["severity"] == "Medium"])
    low = len([f for f in vuln if f["severity"] == "Low"])

    score = int(((total - vuln_count) / total * 100)) if total > 0 else 0
    risk = "CRITICAL" if critical > 0 else "HIGH" if high > 0 else "MEDIUM" if medium > 0 else "LOW"
    risk_colors = {"CRITICAL": "#f85149", "HIGH": "#d29922", "MEDIUM": "#388bfd", "LOW": "#3fb950"}

    vuln_sorted = sorted(vuln, key=lambda x: severity_order.get(x["severity"], 5))

    finding_cards = ""
    for i, f in enumerate(vuln_sorted, 1):
        col = severity_colors.get(f["severity"], "#8b949e")
        bg = severity_bg.get(f["severity"], "#1c2128")
        evidence_html = f["evidence"].replace("\n", "<br>").replace("<", "&lt;").replace(">", "&gt;") if f["evidence"] else ""
        finding_cards += f"""
        <div class="finding-card" style="border-left:4px solid {col};background:{bg}">
          <div class="finding-header">
            <span class="finding-num">#{i}</span>
            <span class="owasp-badge">{f["owasp_id"]}</span>
            <span class="severity-badge" style="background:{col}20;color:{col}">{f["severity"]}</span>
            <span class="finding-name">{f["name"]}</span>
          </div>
          <div class="finding-body">
            <div class="finding-section"><strong>Detail:</strong><br>{f["detail"]}</div>
            {"<div class='finding-section'><strong>Evidence:</strong><br><code>" + evidence_html + "</code></div>" if evidence_html else ""}
            {"<div class='finding-section'><strong>Remediation:</strong><br>" + f["remediation"] + "</div>" if f["remediation"] else ""}
          </div>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>API Security Scan Report — {target}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#0d1117;color:#e6edf3;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;font-size:14px;line-height:1.6}}
header{{background:#161b22;border-bottom:1px solid #21262d;padding:24px 32px}}
h1{{font-size:20px;font-weight:600;color:#58a6ff;margin-bottom:4px}}
.sub{{font-size:13px;color:#8b949e}}
main{{max-width:1100px;margin:0 auto;padding:24px 32px}}
.stats{{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin-bottom:24px}}
.stat{{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:14px 16px;text-align:center}}
.stat .val{{font-size:26px;font-weight:600;margin-bottom:2px}}
.stat .lbl{{font-size:11px;color:#8b949e;text-transform:uppercase;letter-spacing:.04em}}
.risk-banner{{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:16px 24px;margin-bottom:24px;display:flex;align-items:center;gap:16px}}
.risk-label{{font-size:13px;color:#8b949e}}
.risk-val{{font-size:32px;font-weight:700;color:{risk_colors.get(risk,"#f85149")}}}
.score-bar-bg{{flex:1;background:#21262d;border-radius:4px;height:10px}}
.score-bar-fill{{height:10px;border-radius:4px;background:#3fb950;width:{score}%}}
h2{{font-size:15px;font-weight:600;color:#c9d1d9;margin:24px 0 12px;padding-bottom:8px;border-bottom:1px solid #21262d}}
.finding-card{{border-radius:8px;margin-bottom:12px;overflow:hidden}}
.finding-header{{padding:12px 16px;display:flex;align-items:center;gap:10px;flex-wrap:wrap}}
.finding-num{{font-size:11px;color:#8b949e;font-weight:500;width:24px}}
.owasp-badge{{font-size:10px;font-family:monospace;background:#21262d;color:#8b949e;padding:2px 6px;border-radius:4px}}
.severity-badge{{font-size:11px;font-weight:600;padding:3px 10px;border-radius:12px}}
.finding-name{{font-size:13px;font-weight:500;color:#e6edf3}}
.finding-body{{padding:4px 16px 14px 50px}}
.finding-section{{margin-bottom:10px;font-size:12px;color:#c9d1d9}}
code{{display:block;background:#0d1117;border:1px solid #21262d;border-radius:4px;padding:8px 10px;font-family:monospace;font-size:11px;color:#79c0ff;white-space:pre-wrap;word-break:break-all;margin-top:4px}}
.secure-list{{display:grid;grid-template-columns:repeat(2,1fr);gap:8px}}
.secure-item{{background:#152d1e;border:1px solid #1a4a2e;border-radius:6px;padding:8px 12px;font-size:12px;color:#3fb950}}
footer{{text-align:center;padding:24px;color:#8b949e;font-size:12px;border-top:1px solid #21262d;margin-top:32px}}
</style>
</head>
<body>
<header>
  <h1>API Security Scan Report</h1>
  <div class="sub">Target: {target} &nbsp;|&nbsp; Scan completed: {scan_meta["end_time"]} &nbsp;|&nbsp; Duration: {scan_meta["duration"]}s &nbsp;|&nbsp; by Kofi Asibey-Kitiabi</div>
</header>
<main>
  <div class="stats">
    <div class="stat"><div class="val" style="color:#f85149">{critical}</div><div class="lbl">Critical</div></div>
    <div class="stat"><div class="val" style="color:#d29922">{high}</div><div class="lbl">High</div></div>
    <div class="stat"><div class="val" style="color:#388bfd">{medium}</div><div class="lbl">Medium</div></div>
    <div class="stat"><div class="val" style="color:#3fb950">{low}</div><div class="lbl">Low</div></div>
    <div class="stat"><div class="val" style="color:#8b949e">{vuln_count}</div><div class="lbl">Total Vulns</div></div>
    <div class="stat"><div class="val" style="color:#3fb950">{score}%</div><div class="lbl">Security Score</div></div>
  </div>
  <div class="risk-banner">
    <div><div class="risk-label">Overall Risk Rating</div><div class="risk-val">{risk}</div></div>
    <div style="flex:1">
      <div style="display:flex;justify-content:space-between;font-size:11px;color:#8b949e;margin-bottom:4px"><span>Security Score</span><span>{score}%</span></div>
      <div class="score-bar-bg"><div class="score-bar-fill"></div></div>
    </div>
  </div>
  <h2>Vulnerabilities Found ({vuln_count})</h2>
  {finding_cards if finding_cards else '<p style="color:#3fb950">No vulnerabilities found.</p>'}
  <h2>Checks Passed ({len(secure)})</h2>
  <div class="secure-list">
    {"".join(f'<div class="secure-item">✓ {f["name"]}</div>' for f in secure)}
  </div>
</main>
<footer>
  MiniSOC API Security Scanner &nbsp;|&nbsp; github.com/Mastertactician23/api-security-scanner &nbsp;|&nbsp; OWASP API Top 10 2023
</footer>
</body>
</html>"""
    return html


# ──────────────────────────────────────────────
# MAIN SCANNER
# ──────────────────────────────────────────────

def run_scanner(target):
    target = target.rstrip("/")
    start_time = time.time()
    start_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print("")
    print(bold(cyan("  ╔══════════════════════════════════════════╗")))
    print(bold(cyan("  ║      API SECURITY SCANNER               ║")))
    print(bold(cyan("  ║      by Kofi Asibey-Kitiabi             ║")))
    print(bold(cyan("  ╚══════════════════════════════════════════╝")))
    print(f"  Target    : {target}")
    print(f"  Started   : {start_str}")
    print(f"  Checks    : 15 (OWASP API Top 10 + SQLi + XSS + JWT + Methods)")
    print("")

    # Health check
    print(cyan("  [*] Checking target reachability..."))
    r = req("GET", f"{target}/health")
    if not r:
        r = req("GET", f"{target}/")
    if not r:
        print(red(f"  [FATAL] Cannot reach target: {target}"))
        print(yellow("  Make sure the vulnerable API is running: python3 vulnerable_api.py"))
        sys.exit(1)
    print(green(f"  [*] Target reachable — HTTP {r.status_code}\n"))

    all_findings = []
    token = ""

    # Run all checks
    print(bold("─" * 50))
    print(bold("  RUNNING SECURITY CHECKS"))
    print(bold("─" * 50))

    all_findings += check_bola(target, token)
    result = check_broken_auth(target)
    if isinstance(result, tuple):
        auth_findings, token = result
    else:
        auth_findings, token = result, ""
    all_findings += auth_findings
    all_findings += check_excessive_data(target, token)
    all_findings += check_rate_limiting(target)
    all_findings += check_broken_function_auth(target, token)
    all_findings += check_mass_enumeration(target, token)
    all_findings += check_ssrf(target)
    all_findings += check_security_misconfig(target)
    all_findings += check_inventory(target)
    all_findings += check_sql_injection(target)
    all_findings += check_xss(target)
    all_findings += check_jwt_brute(target)
    all_findings += check_http_methods(target)

    # Score
    end_time = time.time()
    duration = round(end_time - start_time, 1)
    end_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    vuln = [f for f in all_findings if f["status"] == "VULNERABLE"]
    secure = [f for f in all_findings if f["status"] == "SECURE"]
    critical = len([f for f in vuln if f["severity"] == "Critical"])
    high = len([f for f in vuln if f["severity"] == "High"])
    medium = len([f for f in vuln if f["severity"] == "Medium"])
    score = int(((len(all_findings) - len(vuln)) / len(all_findings) * 100)) if all_findings else 0
    risk = "CRITICAL" if critical > 0 else "HIGH" if high > 0 else "MEDIUM" if medium > 0 else "LOW"

    print("")
    print(bold("─" * 50))
    print(bold("  SCAN SUMMARY"))
    print(bold("─" * 50))
    print(f"  Target          : {target}")
    print(f"  Duration        : {duration}s")
    print(f"  Total checks    : {len(all_findings)}")
    print(f"  {red('Vulnerabilities')} : {len(vuln)}")
    print(f"    {red('Critical')}      : {critical}")
    print(f"    {yellow('High')}         : {high}")
    print(f"    {cyan('Medium')}       : {medium}")
    print(f"  {green('Secure')}         : {len(secure)}")
    print(f"  Security Score  : {bold(str(score) + '%')}")
    risk_col = red if risk in ["CRITICAL", "HIGH"] else yellow if risk == "MEDIUM" else green
    print(f"  Risk Rating     : {risk_col(bold(risk))}")
    print("")

    # Save JSON report
    os.makedirs("reports", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = f"reports/scan_{timestamp}.json"
    report_data = {
        "target": target,
        "scan_start": start_str,
        "scan_end": end_str,
        "duration_seconds": duration,
        "summary": {
            "total_checks": len(all_findings),
            "vulnerabilities": len(vuln),
            "critical": critical, "high": high, "medium": medium,
            "secure": len(secure),
            "security_score": score,
            "risk_rating": risk
        },
        "findings": all_findings
    }
    with open(json_path, "w") as f:
        json.dump(report_data, f, indent=2)
    print(green(f"  [✓] JSON report saved: {json_path}"))

    # Save HTML report
    html_path = f"reports/scan_{timestamp}.html"
    scan_meta = {"end_time": end_str, "duration": duration}
    html = generate_html_report(target, all_findings, scan_meta)
    with open(html_path, "w") as f:
        f.write(html)
    print(green(f"  [✓] HTML report saved: {html_path}"))
    print(cyan(f"  [*] Open in browser: file://{os.path.abspath(html_path)}"))
    print("")


# ──────────────────────────────────────────────
# ENTRY POINT
# ──────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="API Security Scanner — OWASP API Top 10")
    parser.add_argument("--target", "-t", default="http://localhost:8080",
                        help="Target API base URL (default: http://localhost:8080)")
    args = parser.parse_args()
    run_scanner(args.target)
