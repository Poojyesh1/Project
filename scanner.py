import requests
from bs4 import BeautifulSoup
import re
import os
import sys
import json
import html
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from datetime import datetime

def sanitize_url_for_filename(url):
    # Remove protocol
    filename = re.sub(r'^https?://', '', url)
    # Replace invalid filename characters with underscore
    filename = re.sub(r'[\\/:"*?<>|]+', '_', filename)
    # Remove trailing slash or query params
    filename = filename.rstrip('/').split('?')[0]
    return filename

class WebSecurityScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.visited_urls = set()
        self.vulnerabilities = []
        self.payloads = {
            'xss': "<script>alert('XSS')</script>",
            'sqli': "' OR 1=1--"
        }

    def crawl(self, url):
        if url in self.visited_urls:
            return
        print(f"Crawling URL: {url}")
        self.visited_urls.add(url)
        try:
            resp = requests.get(url, timeout=5)
            soup = BeautifulSoup(resp.text, "html.parser")
            for link in soup.find_all("a", href=True):
                abs_url = requests.compat.urljoin(url, link['href'])
                if abs_url.startswith(self.target_url) and abs_url not in self.visited_urls:
                    self.crawl(abs_url)
            self.test_forms(url, soup)
        except Exception as e:
            print(f"Error crawling {url}: {e}")

    def test_forms(self, url, soup):
        forms = soup.find_all("form")
        print(f"Found {len(forms)} forms on {url}")
        for form in forms:
            action = form.get("action")
            form_url = requests.compat.urljoin(url, action)
            method = form.get("method", "get").lower()
            inputs = form.find_all("input")
            for vulntype, payload in self.payloads.items():
                data = {}
                for input_elem in inputs:
                    name = input_elem.get("name")
                    if name:
                        data[name] = payload
                print(f"Testing form at {form_url} with payload ({vulntype}): {payload}")
                try:
                    if method == "post":
                        res = requests.post(form_url, data=data, timeout=5)
                    else:
                        res = requests.get(form_url, params=data, timeout=5)
                    self.analyze_response(form_url, res.text, vulntype, payload)
                except Exception as e:
                    print(f"Error submitting form at {form_url}: {e}")

    def analyze_response(self, url, response, vulntype, payload):
        found = False
        if vulntype == 'xss' and payload in response:
            found = True
        elif vulntype == 'sqli' and re.search(r"sql|syntax|database error", response, re.I):
            found = True
        if found:
            vuln = {
                "url": url,
                "type": vulntype,
                "payload": payload,
                "evidence": response[:200]
            }
            print(f"Vulnerability found: {vuln}")
            self.vulnerabilities.append(vuln)

    def save_reports(self):
        if not os.path.exists("reports"):
            os.makedirs("reports")
        safe_name = sanitize_url_for_filename(self.target_url)
        base_filename = f"reports/{safe_name}_report"
        self.save_json_report(base_filename + ".json")
        self.save_html_report(base_filename + ".html")
        self.save_pdf_report(base_filename + ".pdf")

    def save_json_report(self, filename):
        with open(filename, "w", encoding="utf-8") as f:
            json_data = {
                "target": self.target_url,
                "total_urls_visited": len(self.visited_urls),
                "vulnerabilities_found": len(self.vulnerabilities),
                "vulnerabilities": self.vulnerabilities
            }
            json.dump(json_data, f, indent=4)
        print(f"JSON report saved to {filename}")

    def save_html_report(self, filename):
        with open(filename, "w", encoding="utf-8") as f:
            f.write(f"<html><head><title>Scan Report for {html.escape(self.target_url)}</title></head><body>")
            f.write(f"<h2>Scan Report for {html.escape(self.target_url)}</h2>")
            f.write(f"<p>Total URLs Visited: {len(self.visited_urls)}</p>")
            f.write(f"<p>Vulnerabilities Found: {len(self.vulnerabilities)}</p>")
            f.write("<hr>")
            for vuln in self.vulnerabilities:
                f.write("<div>")
                f.write(f"<b>Type:</b> {html.escape(str(vuln.get('type', 'N/A')))}<br>")
                url = vuln.get('url', 'N/A')
                f.write(f"<b>URL:</b> <a href='{html.escape(url)}' target='_blank'>{html.escape(url)}</a><br>")
                payload = vuln.get('payload', 'N/A')
                evidence = vuln.get('evidence', 'N/A')
                f.write(f"<b>Payload:</b> {html.escape(str(payload))}<br>")
                f.write(f"<b>Evidence:</b> <pre>{html.escape(str(evidence))}</pre>")
                f.write("</div><hr>")
            f.write("</body></html>")
        print(f"HTML report saved to {filename}")

    def save_pdf_report(self, filename):
        c = canvas.Canvas(filename, pagesize=letter)
        width, height = letter
        margin = 50
        line_height = 14
        x = margin
        y = height - margin
        c.setFont("Helvetica-Bold", 16)
        c.drawString(x, y, f"Scan Report for {self.target_url}")
        y -= 30
        c.setFont("Helvetica", 12)
        c.drawString(x, y, f"Total URLs Visited: {len(self.visited_urls)}")
        y -= 20
        c.drawString(x, y, f"Vulnerabilities Found: {len(self.vulnerabilities)}")
        y -= 25
        c.setFont("Helvetica", 10)

        for vuln in self.vulnerabilities:
            if y < margin + 60:
                c.showPage()
                c.setFont("Helvetica", 10)
                y = height - margin
            c.drawString(x, y, f"Type: {vuln.get('type', 'N/A')}")
            y -= line_height
            c.drawString(x, y, f"URL: {vuln.get('url', 'N/A')}")
            y -= line_height
            c.drawString(x, y, f"Payload: {vuln.get('payload', 'N/A')}")
            y -= line_height
            c.drawString(x, y, "Evidence:")
            y -= 12
            evidence_lines = str(vuln.get('evidence', 'N/A')).splitlines()[:5]
            for line in evidence_lines:
                if y < margin + 20:
                    c.showPage()
                    c.setFont("Helvetica", 10)
                    y = height - margin
                c.drawString(x + 20, y, line[:90])
                y -= 12
            y -= 10

        c.save()
        print(f"PDF report saved to {filename}")

    def scan(self):
        print("Starting scan...")
        self.crawl(self.target_url)
        print(f"Scan complete. URLs visited: {len(self.visited_urls)}, Vulnerabilities found: {len(self.vulnerabilities)}")
        self.save_reports()
        return self.vulnerabilities


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python scanner.py <target_url>")
        sys.exit(1)
    target_url = sys.argv[1]
    scanner = WebSecurityScanner(target_url)
    vulns = scanner.scan()
    for vuln in vulns:
        print(vuln)
