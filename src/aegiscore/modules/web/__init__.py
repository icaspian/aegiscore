import asyncio
import re
import urllib.parse
from typing import List, Optional

import aiohttp
import requests
import typer
from bs4 import BeautifulSoup
from rich.table import Table

from aegiscore.core.logger import console, logger

web_app = typer.Typer(help="Web Application Security Tools")


def normalize_url(url: str) -> str:
    if not url.lower().startswith(("http://", "https://")):
        return "http://" + url
    return url


@web_app.command("headers")
def analyze_headers(
    url: str = typer.Argument(..., help="The URL to analyze (include http:// or https://)"),
):
    """
    Analyzes HTTP security headers for a given URL.
    """
    url = normalize_url(url)
    console.print(f"[*] Analyzing security headers for {url}")

    try:
        response = requests.get(url, timeout=5)
        headers = response.headers

        security_headers = {
            "Strict-Transport-Security": "Missing HSTS - site may be vulnerable to downgrade attacks.",
            "Content-Security-Policy": "Missing CSP - site may be vulnerable to XSS.",
            "X-Frame-Options": "Missing X-Frame-Options - site may be vulnerable to clickjacking.",
            "X-Content-Type-Options": "Missing X-Content-Type-Options - vulnerable to MIME-sniffing.",
        }

        table = Table(title=f"Security Headers for {url}")
        table.add_column("Header", style="cyan")
        table.add_column("Status", style="green")

        warnings = 0
        for header, warning in security_headers.items():
            if header in headers:
                table.add_row(header, "[green]Present[/green]")
            else:
                table.add_row(header, "[red]Missing[/red]")
                logger.warning(f"[!] {warning}")
                warnings += 1

        console.print(table)

        if warnings == 0:
            logger.info("[green][+] All standard security headers are present.[/green]")
        else:
            logger.warning(f"[!] Found {warnings} missing security headers.")
    except requests.RequestException as e:
        logger.error(f"[!] Failed to connect to {url}: {e}")


async def fetch(
    session: aiohttp.ClientSession, url: str, sem: asyncio.Semaphore
) -> tuple:
    async with sem:
        try:
            async with session.get(url, allow_redirects=False) as response:
                return url, response.status
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return url, 0


async def run_fuzzer(base_url: str, wordlist: List[str]) -> List[str]:
    found = []
    sem = asyncio.Semaphore(20)
    timeout = aiohttp.ClientTimeout(total=5)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        # Chunk the wordlist so large lists do not create one huge task list.
        for i in range(0, len(wordlist), 200):
            chunk = wordlist[i : i + 200]
            tasks = []
            for word in chunk:
                target = urllib.parse.urljoin(base_url, word)
                tasks.append(fetch(session, target, sem))

            for target, status in await asyncio.gather(*tasks):
                if status in (200, 301, 302, 401, 403):
                    found.append(target)
                    logger.info(f"[green][+] Found: {target} (status {status})[/green]")

    return found


@web_app.command("fuzz")
def directory_fuzz(
    url: str = typer.Argument(..., help="The target URL"),
    wordlist: Optional[str] = typer.Option(None, help="Path to a custom wordlist file"),
):
    """
    Fuzzes directories and endpoints to find hidden paths.
    """
    url = normalize_url(url)
    console.print(f"[*] Fuzzing directories on {url}")

    if not url.endswith("/"):
        url += "/"

    words = ["admin", "login", "dashboard", "api", "v1", "backup", ".git", "config", "test"]

    if wordlist:
        try:
            with open(wordlist, "r", encoding="utf-8", errors="ignore") as f:
                words = [line.strip() for line in f if line.strip()]
        except OSError:
            logger.error(f"[!] Wordlist {wordlist} could not be read. Using default.")

    logger.info(f"[*] Using wordlist with {len(words)} entries.")

    try:
        found = asyncio.run(run_fuzzer(url, words))
        if not found:
            logger.info("[-] No hidden directories found.")
        else:
            logger.info(f"[+] Fuzzing complete. Found {len(found)} endpoints.")
    except KeyboardInterrupt:
        logger.warning("[!] Fuzzing interrupted.")


@web_app.command("vuln-scan")
def vuln_scan(
    url: str = typer.Argument(..., help="The target URL to test for basic XSS/SQLi"),
):
    """
    Scans URL parameters for basic reflected XSS and SQL injection.
    """
    url = normalize_url(url)
    console.print(f"[*] Scanning {url} for basic vulnerabilities")

    if "?" not in url:
        logger.warning(
            "[-] Target URL has no parameters (e.g., ?id=1). Cannot test injections."
        )
        return

    xss_payload = "<script>alert(1)</script>"
    sqli_payload = "'"

    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    try:
        for param in params:
            test_params = params.copy()
            test_params[param] = xss_payload
            test_url = f"{base_url}?{urllib.parse.urlencode(test_params, doseq=True)}"

            response = requests.get(test_url, timeout=5)
            if xss_payload in response.text:
                logger.warning(f"[red][!] Potential reflected XSS in parameter: {param}[/red]")

        for param in params:
            test_params = params.copy()
            test_params[param] = sqli_payload
            test_url = f"{base_url}?{urllib.parse.urlencode(test_params, doseq=True)}"

            response = requests.get(test_url, timeout=5)
            if any(
                error in response.text.lower()
                for error in ("sql syntax", "mysql_fetch", "sqlite3")
            ):
                logger.warning(f"[red][!] Potential SQL injection in parameter: {param}[/red]")

        logger.info("[+] Vulnerability scan complete.")
    except requests.RequestException as e:
        logger.error(f"[!] Request failed: {e}")


@web_app.command("scrape")
def scrape_page(
    url: str = typer.Argument(..., help="The URL to scrape (include http:// or https://)"),
):
    """
    Crawls a web page to extract links and email addresses.
    """
    url = normalize_url(url)
    console.print(f"[*] Scraping {url} for links and emails")

    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, "html.parser")

        links = set()
        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"]
            if href.startswith("http"):
                links.add(href)
            elif href.startswith("/"):
                links.add(urllib.parse.urljoin(url, href))

        email_pattern = r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
        emails = set(re.findall(email_pattern, response.text))

        if links:
            logger.info(f"[green][+] Found {len(links)} links:[/green]")
            for link in sorted(links)[:20]:
                console.print(f"    - {link}")
            if len(links) > 20:
                console.print("    - ... (more links hidden)")

        if emails:
            logger.info(f"[green][+] Found {len(emails)} emails:[/green]")
            for email in sorted(emails):
                console.print(f"    - {email}")
        else:
            logger.info("[-] No emails found.")
    except requests.RequestException as e:
        logger.error(f"[!] Failed to fetch {url}: {e}")
