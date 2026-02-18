# DVWA-Penetration-Testing-Project
# DVWA Penetration Testing Lab

Self-directed hands-on web vulnerability assessment using Damn Vulnerable Web Application (DVWA) running locally via Docker. Built overnight to demonstrate foundational offensive security skills relevant to client-side software penetration testing contributions.

## Environment & Setup
- **DVWA**: Official `digininja/DVWA` Docker image + compose
- **URL**: http://localhost:8080
- **Security Level**: Low (for clear exploit demonstration)
- **Database**: MariaDB (containerized)
- **Tools Used**: Browser (manual testing), screenshot capture

Quick setup recap:
1. `docker compose up -d` from DVWA source folder
2. Browser → http://localhost:8080 → Setup DVWA → Create/Reset Database
3. Login: admin / password
4. DVWA Security → Low

## Vulnerabilities Demonstrated
Three common OWASP Top 10 web vulnerabilities exploited on Low security level:

1. **SQL Injection**  
   - Payloads: `' OR 1=1 -- -` (dump all users), `' UNION SELECT user, password FROM users -- -` (extract MD5 hashes)  
   - Impact: Full database exposure possible in production  
   - OWASP: A03:2021 – Injection  
   - Screenshots: [/screenshots/sqli/](./screenshots/sqli/)

2. **Reflected Cross-Site Scripting (XSS)**  
   - Payload: `<script>alert('XSS by Yuve')</script>`  
   - Impact: Potential session hijacking, phishing, or client-side code execution  
   - OWASP: A07:2021 – Identification and Authentication Failures (wait no – Cross-Site Scripting)  
   - Screenshots: [/screenshots/xss/](./screenshots/xss/)

3. **Command Injection**  
   - Payloads: `127.0.0.1 && whoami`, `127.0.0.1 && ls /var/www/html`  
   - Impact: Remote code execution on server (critical in backend apps)  
   - OWASP: A03:2021 – Injection (OS Command Injection subcategory)  
   - Screenshots: [/screenshots/command-injection/](./screenshots/command-injection/)

## Deliverables
- **Full Report (PDF)**: [Yuve_DVWA_PenTest_Report.pdf](./Yuve_DVWA_PenTest_Report.pdf) – includes PoCs, impacts, remediations  
- **Raw Markdown Report**: [/lab-report/DVWA_Lab_Report.md](./lab-report/DVWA_Lab_Report.md)  
- **Screenshots**: Organized by vulnerability in [/screenshots/](./screenshots/)  
- **Setup Proof**: [/screenshots/setup/](./screenshots/setup/)

## Key Takeaways & Next Steps
This lab shows ability to:
- Set up vulnerable environments ethically
- Perform manual reconnaissance and exploitation
- Document findings clearly with visuals
- Suggest basic remediations

Built Feb 17–18, 2026 as proactive preparation for assisting on real client-side vulnerability assessments.

Feedback welcome – happy to iterate or tackle more complex levels/tools.
