# Webshield
# 🛡️ WebShield - Advanced Web Application Firewall CLI Tool

**WebShield** is a powerful command-line-based Web Application Firewall (WAF) and security toolkit that helps detect, monitor, and defend websites against OWASP Top 10 vulnerabilities, including SQL Injection, XSS, brute-force attempts, and more. Built for penetration testers and sysadmins, WebShield provides automation, alerting, and actionable fix tips in a terminal-friendly interface.


## 🔧 Features

1. **WAF Scanner (SQLi + XSS)** - Advanced detection of SQL Injection & XSS attacks using evasion and timing techniques.
2. **SSL Expiry Checker** - Monitors SSL certificate expiration dates.
3. **Uptime Monitor** - Checks real-time website availability.
4. **DDoS Simulation** - Simulates rate-limiting behavior under fake load.
5. **Block IP** - Manually block malicious IPs via CLI.
6. **View Blocked IPs** - Shows list of IPs currently blocked.
7. **Archive Logs** - Archives old logs for retention.
8. **Malware Link Scanner** - Detects malicious or suspicious URLs.
9. **Admin Summary Report** - Generates a detailed summary of security scan results.
10. **View Logs** - Displays activity and scan logs.
11. **Developer Help & Fix Tips** - Shows fixes, OWASP references, and DevFixReport.

**Usage**

Run the command:
**python3 webshield.py**
You will see a menu-driven interface then it will ask for URL and then choose any options given below:

==== WebShield Security CLI Tool ====
1. WAF Scanner (SQLi + XSS)
2. SSL Expiry Checker
3. Uptime Monitor
4. Simulate DDoS Rate Limiting
5. Block IP
6. View Blocked IPs
7. Archive Logs
8. Malware Link Scanner
9. Generate Admin Summary Report
10. View Logs
11. Developer Help & Fix Tips
0. Exit
   
Use the menu to perform scans, generate reports, or manage logs and blocked IPs.
