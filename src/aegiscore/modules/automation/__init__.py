import asyncio

import typer

from aegiscore.core.logger import console, logger
from aegiscore.modules.recon import run_port_scan
from aegiscore.modules.web import analyze_headers

automation_app = typer.Typer(help="Automation & Workflow Tools")

@automation_app.command("orchestrate")
def orchestrate_scan(
    target: str = typer.Argument(..., help="The target IP or Domain to run a full orchestrated scan on")
):
    """
    Runs a chained workflow: Port Scan -> Header Analysis (if port 80/443 is open).
    """
    console.print(f"[*] Starting orchestrated workflow against {target}")
    
    # Step 1: Port Scan
    logger.info(f"[*] Step 1: Scanning ports 1-1024 on {target}")
    try:
        open_ports = asyncio.run(run_port_scan(target, 1, 1024))
    except KeyboardInterrupt:
        logger.warning("[!] Workflow interrupted.")
        return

    if not open_ports:
        logger.warning(f"[-] No open ports found on {target}. Workflow halted.")
        return

    # Step 2: Web Analysis
    if 80 in open_ports or 443 in open_ports:
        logger.info("[*] Step 2: Web ports detected (80/443). Running header analyzer.")
        if 443 in open_ports:
            analyze_headers(f"https://{target}")
        else:
            analyze_headers(f"http://{target}")
    else:
        logger.info("[*] Step 2: No web ports found. Skipping web analysis.")

    logger.info("[green][+] Orchestrated workflow complete.[/green]")
