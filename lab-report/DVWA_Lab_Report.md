# Self-Directed Web Application Penetration Testing Lab Report

**Title:** DVWA Vulnerability Assessment — Low Security Level  
**Prepared by:** Yuvdeep Bharjana  
**Date:** February 18, 2026  
**Purpose:** Demonstrating foundational web vulnerability assessment skills for client-side security contribution  
**Disclaimer:** All testing conducted on a locally hosted, intentionally vulnerable application (DVWA) in an isolated environment. No real systems were targeted.

---

## 1. Scope & Methodology

### Scope
- **Target:** Damn Vulnerable Web Application (DVWA) — local Docker instance
- **URL:** `http://localhost:8080`
- **Security Level:** Low (intentionally misconfigured to simulate real-world weak deployments)
- **Testing Type:** Manual black-box exploitation, no automated scanners

### Methodology
Testing followed a manual, proof-of-concept approach aligned with OWASP Testing Guide principles:
1. Identify input vectors
2. Craft and inject payloads
3. Observe and document application response
4. Assess real-world impact
5. Recommend targeted remediation

### Tools Used
| Tool             | Purpose                              |
|------------------|--------------------------------------|
| Web Browser      | Manual payload delivery, observation |
| Browser DevTools | Request inspection                   |
| DVWA (Docker)    | Isolated vulnerable target           |

---

## 2. Findings

---

### Finding 1 — SQL Injection

| Field        | Details                          |
|--------------|----------------------------------|
| **OWASP**    | A03:2021 – Injection             |
| **Severity** | High                             |
| **Location** | `http://localhost:8080/vulnerabilities/sqli/` |
| **Parameter**| `id` (GET)                       |

#### Description
The application passes user-supplied input directly into a SQL query without sanitization or parameterization. An attacker can manipulate the query logic to bypass authentication, extract data, or enumerate the entire database.

#### Proof of Concept

**Step 1:** Navigate to `http://localhost:8080/vulnerabilities/sqli/`

**Step 2:** Enter the following payload in the User ID field:

```
' OR '1'='1
```

**Step 3:** Click Submit. The application returns **all user records** from the database instead of a single result — confirming the injection is successful.

**Step 4:** To enumerate database users and password hashes, enter:

```
' UNION SELECT user, password FROM users#
```

**Screenshot — Payload Input:**  
`[INSERT: screenshots/sqli/sqli-payload-input.png]`

**Screenshot — Dumped User Records:**  
`[INSERT: screenshots/sqli/sqli-all-users-dumped.png]`

#### Impact
- Full extraction of all user credentials (usernames + MD5 hashes)
- Potential for authentication bypass
- In a real application: complete database compromise, data breach, privilege escalation

#### Remediation
- **Use parameterized queries / prepared statements** (e.g., PDO in PHP)
- Enforce least-privilege database accounts
- Implement input validation and allowlisting
- Enable a Web Application Firewall (WAF) as a secondary control

---

### Finding 2 — Reflected Cross-Site Scripting (XSS)

| Field        | Details                          |
|--------------|----------------------------------|
| **OWASP**    | A03:2021 – Injection             |
| **Severity** | High                             |
| **Location** | `http://localhost:8080/vulnerabilities/xss_r/` |
| **Parameter**| `name` (GET)                     |

#### Description
The application reflects user-supplied input directly into the HTML response without encoding. An attacker can inject malicious JavaScript that executes in the victim's browser. This enables session hijacking, credential theft, and client-side redirection.

#### Proof of Concept

**Step 1:** Navigate to `http://localhost:8080/vulnerabilities/xss_r/`

**Step 2:** Enter the following payload in the Name field:

```html
<script>alert('XSS by Yuve')</script>
```

**Step 3:** Click Submit. The browser executes the script and displays an alert popup — confirming the payload was reflected and executed without sanitization.

**Screenshot — Payload Input:**  
`[INSERT: screenshots/xss/xss-payload-input.png]`

**Screenshot — Alert Popup Executing:**  
`[INSERT: screenshots/xss/xss-alert-popup.png]`

#### Impact
- Session token theft via `document.cookie` exfiltration
- Phishing attacks through page content manipulation
- Redirection to malicious sites
- In a real application: full account takeover of any user who visits the crafted URL

#### Remediation
- **Encode all user-supplied output** (HTML entity encoding before rendering)
- Implement a strict **Content Security Policy (CSP)** header
- Use framework-level auto-escaping (e.g., React, Angular handle this by default)
- Validate and sanitize all input server-side

---

### Finding 3 — OS Command Injection

| Field        | Details                          |
|--------------|----------------------------------|
| **OWASP**    | A03:2021 – Injection             |
| **Severity** | Critical                         |
| **Location** | `http://localhost:8080/vulnerabilities/exec/` |
| **Parameter**| `ip` (POST)                      |

#### Description
The application passes user input directly to an OS-level command (`ping`) without sanitization. An attacker can append arbitrary shell commands using standard shell operators (`&&`, `;`, `|`), resulting in Remote Code Execution (RCE) on the underlying server.

#### Proof of Concept

**Step 1:** Navigate to `http://localhost:8080/vulnerabilities/exec/`

**Step 2:** Enter a valid IP followed by a command injection payload:

```
127.0.0.1 && whoami
```

**Step 3:** Click Submit. The application returns the output of `ping` **and** the result of `whoami` — revealing the OS user the web server is running as.

**Step 4:** To enumerate the server filesystem:

```
127.0.0.1 && ls /var/www/html
```

**Screenshot — Payload Input:**  
`[INSERT: screenshots/command-injection/cmdi-payload-input.png]`

**Screenshot — whoami Output:**  
`[INSERT: screenshots/command-injection/cmdi-whoami-output.png]`

**Screenshot — Directory Listing:**  
`[INSERT: screenshots/command-injection/cmdi-ls-output.png]`

#### Impact
- Full Remote Code Execution as the web server user
- File system read/write access (config files, credentials, source code)
- Potential for reverse shell and full server compromise
- In a real application: highest possible impact — complete system takeover

#### Remediation
- **Never pass user input to OS commands.** Refactor to use language-native libraries (e.g., PHP's `checkdnsrr()` instead of calling `ping`)
- If OS calls are unavoidable, use `escapeshellarg()` / `escapeshellcmd()`
- Allowlist acceptable input formats (e.g., validate IP format with regex before use)
- Run the web server under a minimal-privilege OS user
- Disable dangerous PHP functions (`exec`, `shell_exec`, `system`) in `php.ini`

---

## 3. Summary & Recommendations

### Overall Risk Assessment

All three vulnerabilities stem from a single root cause: **insufficient input validation and output encoding**. In a real-world application, any one of these findings would represent a critical or high-severity issue requiring immediate remediation.

| Finding              | Severity | Root Cause                        | Quick Fix                        |
|----------------------|----------|-----------------------------------|----------------------------------|
| SQL Injection         | High     | Unsanitized DB queries            | Prepared statements              |
| Reflected XSS         | High     | Unencoded output rendering        | HTML entity encoding + CSP       |
| Command Injection     | Critical | User input passed to OS shell     | Avoid OS calls; escapeshellarg() |

### Key Recommendations
1. **Adopt a Secure Development Lifecycle (SDL):** Input validation and output encoding should be requirements, not afterthoughts.
2. **Use modern frameworks** that handle escaping and parameterization by default.
3. **Conduct regular security reviews** of any feature that processes user input — especially those that interact with databases, the OS, or render HTML.
4. **Implement defense-in-depth:** WAF, CSP headers, and least-privilege principles as secondary controls.

### Conclusion
This lab demonstrated the practical exploitation of three foundational web application vulnerabilities across the OWASP Top 10 (A03:2021 – Injection). The exercise built hands-on skills in identifying attack vectors, crafting proof-of-concept payloads, assessing real-world impact, and recommending actionable remediation — directly applicable to client-side security assessment contributions.

---

## Appendix

### A — Lab Setup Screenshots
- `screenshots/setup/dvwa-login.png` — DVWA login page
- `screenshots/setup/dvwa-security-low.png` — Security level set to Low
- `screenshots/setup/dvwa-dashboard.png` — DVWA main dashboard

### B — References
- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [DVWA GitHub](https://github.com/digininja/DVWA)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

### C — Repository
[github.com/YuvdeepBharjana/DVWA-Penetration-Testing-Project](https://github.com/YuvdeepBharjana/DVWA-Penetration-Testing-Project)
