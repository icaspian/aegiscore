import asyncio
import socket
from typing import List, Optional

import requests
import typer
from rich.progress import Progress

from aegiscore.core.logger import console, logger

recon_app = typer.Typer(help="Network & Reconnaissance Tools")


async def scan_port(ip: str, port: int, timeout: float = 1.0) -> Optional[int]:
    """Attempts to connect to a specific port asynchronously."""
    writer = None
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        return port
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass


async def run_port_scan(ip: str, start_port: int, end_port: int) -> List[int]:
    """Runs the asynchronous port scan."""
    open_ports = []
    total = end_port - start_port + 1

    with Progress() as progress:
        task = progress.add_task(f"[cyan]Scanning {ip}...", total=total)

        # Chunked so we do not open thousands of sockets at once.
        chunk_size = 500
        for i in range(start_port, end_port + 1, chunk_size):
            chunk_end = min(i + chunk_size, end_port + 1)
            tasks = [scan_port(ip, p) for p in range(i, chunk_end)]
            results = await asyncio.gather(*tasks)

            for result in results:
                if result is not None:
                    open_ports.append(result)
                    logger.info(f"[green][+] Port {result} is open[/green]")

            progress.update(task, advance=chunk_end - i)

    return open_ports


@recon_app.command("port-scan")
def port_scan(
    ip: str = typer.Argument(..., help="The IP address or hostname to scan"),
    start: int = typer.Option(1, help="Starting port"),
    end: int = typer.Option(1024, help="Ending port"),
):
    """
    Perform a fast asynchronous port scan on a target host.
    """
    if not 1 <= start <= 65535 or not 1 <= end <= 65535 or start > end:
        logger.error("[!] Port range must be between 1 and 65535, with start <= end.")
        raise typer.Exit(code=1)

    console.print(f"[*] Starting port scan on {ip} ({start}-{end})")
    try:
        open_ports = asyncio.run(run_port_scan(ip, start, end))
        if not open_ports:
            logger.info("[-] No open ports found in the specified range.")
        else:
            logger.info(f"[+] Scan complete. Found {len(open_ports)} open ports.")
    except KeyboardInterrupt:
        logger.warning("[!] Scan interrupted by user.")


@recon_app.command("banner")
def banner_grab(
    ip: str = typer.Argument(..., help="The target IP address or hostname"),
    port: int = typer.Argument(..., help="The target port"),
):
    """
    Connects to an open port and grabs the service banner to identify software.
    """
    console.print(f"[*] Grabbing banner from {ip}:{port}")
    try:
        with socket.create_connection((ip, port), timeout=3.0) as sock:
            # Send a basic request for services that wait for input (like HTTP).
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()

        if banner:
            logger.info(f"[green][+] Banner from {port}:[/green]\n{banner}")
        else:
            logger.info("[-] No banner returned.")
    except OSError as e:
        logger.error(f"[!] Failed to grab banner: {e}")


@recon_app.command("osint")
def osint_gather(
    target: str = typer.Argument(..., help="Domain name or IP address"),
):
    """
    Gathers basic OSINT information about a target.
    """
    console.print(f"[*] Gathering OSINT for {target}")

    try:
        response = requests.get(f"http://ip-api.com/json/{target}", timeout=5)
        response.raise_for_status()
        data = response.json()
        if data.get("status") == "success":
            logger.info("[green][+] OSINT Data:[/green]")
            for key, value in data.items():
                console.print(f"    [bold]{key.capitalize()}[/bold]: {value}")
        else:
            logger.error("[!] Failed to retrieve OSINT data or invalid target.")
    except requests.RequestException as e:
        logger.error(f"[!] Error making OSINT request: {e}")
    except ValueError:
        logger.error("[!] OSINT API returned an invalid response.")


@recon_app.command("subdomains")
def subdomains_enum(
    domain: str = typer.Argument(..., help="The target domain (e.g., example.com)"),
):
    """
    Finds hidden subdomains using Certificate Transparency logs (crt.sh).
    """
    console.print(f"[*] Enumerating subdomains for {domain}")

    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = requests.get(url, timeout=15)
        if response.status_code != 200:
            logger.error(f"[!] Failed to fetch data from crt.sh (status {response.status_code})")
            return

        subdomains = set()
        for entry in response.json():
            name_value = entry.get("name_value", "")
            if "*" not in name_value:
                subdomains.update(name_value.split("\n"))

        subdomains.discard("")
        if subdomains:
            logger.info(f"[green][+] Found {len(subdomains)} subdomains:[/green]")
            for sub in sorted(subdomains):
                console.print(f"    - {sub}")
        else:
            logger.info("[-] No subdomains found.")
    except requests.RequestException as e:
        logger.error(f"[!] Request failed: {e}")
    except ValueError:
        logger.error("[!] crt.sh returned an invalid response.")


@recon_app.command("pcap")
def parse_pcap(
    pcap_file: str = typer.Argument(..., help="Path to the .pcap file to analyze"),
):
    """
    Analyzes a PCAP file for plaintext credentials.
    """
    console.print(f"[*] Analyzing PCAP file: {pcap_file}")

    try:
        from scapy.all import TCP, PcapReader, Raw
    except ImportError:
        logger.error("[!] Scapy is not installed. Run: pip install 'aegiscore[pcap]'")
        raise typer.Exit(code=1)

    found = 0
    count = 0
    try:
        reader = PcapReader(pcap_file)
    except FileNotFoundError:
        logger.error(f"[!] File not found: {pcap_file}")
        raise typer.Exit(code=1)
    except Exception as e:
        logger.error(f"[!] Could not open PCAP: {e}")
        raise typer.Exit(code=1)

    try:
        for pkt in reader:
            count += 1
            if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                payload = pkt[Raw].load.decode("utf-8", errors="ignore")
                if "USER " in payload or "PASS " in payload or "Authorization: Basic" in payload:
                    logger.warning(
                        f"[red][!] Plaintext credentials detected in packet![/red]\n"
                        f"{payload[:100].strip()}..."
                    )
                    found += 1
    except OSError as e:
        logger.error(f"[!] Failed to parse PCAP: {e}")
        raise typer.Exit(code=1)
    finally:
        reader.close()

    logger.info(f"[*] Loaded {count} packets.")
    if found == 0:
        logger.info("[green][+] No obvious plaintext credentials found.[/green]")
    else:
        logger.warning(f"[!] Found {found} packets with potential plaintext credentials.")
