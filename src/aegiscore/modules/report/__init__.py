from datetime import datetime
from pathlib import Path

import typer

from aegiscore.core.logger import console, logger

report_app = typer.Typer(help="Reporting & Export Tools")

@report_app.command("generate")
def generate_report(
    title: str = typer.Option("AegisCore Security Audit", help="Title of the report"),
    output: str = typer.Option("report.md", help="Output filename (e.g., report.md)")
):
    """
    Generates a markdown report template for findings.
    """
    console.print(f"[*] Generating report: {output}")
    
    date_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    markdown_content = f"""# {title}
**Date Generated:** {date_str}
**Tool:** AegisCore Security Framework

## Executive Summary
*Enter your high-level summary here...*

## 1. Reconnaissance Findings
### Open Ports
- 
### Subdomains Discovered
- 

## 2. Web Application Assessment
### Security Headers
- 
### Exposed Endpoints / Fuzzing Results
- 

## 3. Cloud & Infrastructure
### S3 Bucket Audits
- 

## 4. Defensive Auditing
### File Integrity (FIM)
- 
### Static Analysis (Secrets)
- 

## Appendix
- Network PCAP anomalies
- Cryptographic hash checks
"""

    try:
        output_path = Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(markdown_content, encoding="utf-8")
        logger.info(f"[green][+] Report template generated at: {output}[/green]")
    except OSError as e:
        logger.error(f"[!] Failed to write report: {e}")
        raise typer.Exit(code=1)
