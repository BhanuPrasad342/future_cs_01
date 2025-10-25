. Executive Summary 
This report presents the findings of a comprehensive Web Application Security Assessment 
conducted on the OWASP Juice Shop application. The primary objective was to identify 
vulnerabilities that could be exploited to compromise the confidentiality, integrity, or 
availability of the system. The engagement revealed several critical and high-severity 
findings, including a SQL Injection vulnerability allowing administrative access and 
reflected Cross-Site Scripting (XSS) issues. Immediate remediation is recommended to 
mitigate these risks and improve the application's security posture. 
Overall Security Posture: CRITICAL 
Summary of Findings: - Critical: SQL Injection vulnerability enabling admin authentication bypass - High: Reflected Cross-Site Scripting (XSS) in search functionality - Medium: Broken Access Control leading to sensitive file exposure - Medium: Missing Content Security Policy (CSP) header 
2. Scope and Methodology 
Scope: The assessment focused exclusively on the OWASP Juice Shop instance accessible at 
http://localhost:3000. All other systems, services, or infrastructure assets were explicitly 
out of scope. 
Methodology: Testing was performed following the OWASP Top 10 framework using a 
hybrid approach combining manual penetration testing and automated scanning 
techniques. 
Tools Used: - OWASP ZAP (v2.x) - Burp Suite Community Edition - Kali Linux - Docker - Mozilla Firefox Developer Edition 
3. Detailed Findings 
Finding 1: SQL Injection – Administrator Authentication Bypass 
Risk Level: CRITICAL 
OWASP Mapping: A03:2021 – Injection 
Description: The login form fails to sanitize user input in the email field, allowing an 
attacker to inject SQL commands to manipulate backend queries. 
Proof of Concept (PoC): 
1. Navigate to http://localhost:3000/#/login 
2. Enter `' OR 1=1 --` in the Email field. 
3. Enter any password and click 'Log In'. 
4. The attacker gains access as an administrator. 
Impact: Successful exploitation grants full administrative privileges, allowing complete 
control over user accounts, products, and data. 
Recommended Mitigation: Implement parameterized queries and use ORM frameworks to 
prevent direct SQL query manipulation. Validate and sanitize all user inputs. 
Finding 2: Reflected Cross-Site Scripting (XSS) in Search Bar 
Risk Level: HIGH 
OWASP Mapping: A03:2021 – Injection 
Description: The search functionality reflects unsanitized user input back into the page, 
allowing execution of arbitrary JavaScript in the user's browser. 
PoC: Enter `<script>alert('XSS')</script>` in the search field to trigger a JavaScript alert. 
Impact: Exploitation may lead to session hijacking, credential theft, and defacement. 
Recommended Mitigation: Apply context-aware output encoding and sanitize user input 
before rendering it in the response. Implement a strong Content Security Policy (CSP). 
Finding 3: Broken Access Control – Sensitive File Exposure 
Risk Level: MEDIUM 
OWASP Mapping: A01:2021 – Broken Access Control 
Description: Directory browsing is enabled, exposing sensitive files under /ftp, which 
should not be publicly accessible. 
PoC: Navigate to http://localhost:3000/ftp to view exposed directories. 
Impact: Unauthorized users may download or modify internal files leading to data 
disclosure. 
Recommended Mitigation: Disable directory listing and restrict access to sensitive 
directories using authentication and authorization controls. 
Finding 4: Missing Content Security Policy (CSP) Header 
Risk Level: MEDIUM 
OWASP Mapping: A05:2021 – Security Misconfiguration 
Description: The application does not enforce a Content Security Policy (CSP), increasing 
the risk of XSS and data injection attacks. 
PoC: Detected using OWASP ZAP scan results. 
Impact: Allows untrusted scripts to execute in the user’s browser environment. 
Recommended Mitigation: Implement a strict CSP header defining trusted content sources 
(scripts, styles, frames, etc.). 
4. OWASP Top 10 Mapping 
OWASP Top 10 Category 
Status 
A01: Broken Access Control Vulnerable 
A02: Cryptographic Failures Not Tested 
A03: Injection 
A04: Insecure Design 
A05: Security 
Misconfiguration 
Vulnerable 
Not Tested 
Vulnerable 
Corresponding Findings 
Sensitive File Exposure 
(/ftp) - 
SQL Injection, Reflected XSS - 
CSP Header Not Set 
5. Conclusion and Recommendations 
The OWASP Juice Shop application was found to contain multiple security weaknesses, 
primarily in input validation and access control. The SQL Injection and XSS vulnerabilities 
pose the highest risks, potentially allowing attackers to gain full control over the 
application. It is imperative that the development team implements the mitigations outlined 
for each issue and adopts secure coding practices. 
Recommended Actions: 
1. Patch all critical and high-severity vulnerabilities immediately. 
2. Conduct a follow-up assessment after remediation. 
3. Integrate automated security testing in the CI/CD pipeline. 
4. Enforce security headers and strict validation mechanisms. 
5. Provide regular security awareness training to the development team. 

End of Report.
