import hashlib
import json
import os
import re
from pathlib import Path

import typer
from rich.table import Table

from aegiscore.core.logger import console, logger

audit_app = typer.Typer(help="Defensive & Auditing Tools")

SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", "build", "dist"}
SKIP_SUFFIXES = {
    ".pyc", ".pyo", ".exe", ".dll", ".so", ".dylib", ".whl", ".zip", ".gz",
    ".tar", ".png", ".jpg", ".jpeg", ".gif", ".pdf", ".ico", ".woff", ".woff2",
}


def hash_file(filepath: str) -> str:
    """Returns the SHA-256 hash of a file."""
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()


@audit_app.command("fim-baseline")
def fim_baseline(
    directory: str = typer.Argument(..., help="Directory to baseline"),
    output: str = typer.Option("baseline.json", help="Output file for the baseline hashes"),
):
    """
    Creates a File Integrity Monitor (FIM) baseline by hashing all files in a directory.
    """
    console.print(f"[*] Generating FIM baseline for {directory}")
    path = Path(directory)

    if not path.exists() or not path.is_dir():
        logger.error(f"[!] Directory {directory} does not exist.")
        raise typer.Exit(code=1)

    baseline = {}
    for file_path in path.rglob("*"):
        if file_path.is_file() and not file_path.is_symlink():
            try:
                baseline[str(file_path)] = hash_file(str(file_path))
            except OSError as e:
                logger.warning(f"[-] Could not hash {file_path}: {e}")

    output_path = Path(output)
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8") as f:
            json.dump(baseline, f, indent=4, sort_keys=True)
    except OSError as e:
        logger.error(f"[!] Could not write {output}: {e}")
        raise typer.Exit(code=1)

    logger.info(
        f"[green][+] Baseline generated and saved to {output} "
        f"({len(baseline)} files).[/green]"
    )


@audit_app.command("fim-check")
def fim_check(
    directory: str = typer.Argument(..., help="Directory to check"),
    baseline_file: str = typer.Option("baseline.json", help="Baseline JSON file to compare against"),
):
    """
    Checks a directory against a previously generated FIM baseline.
    """
    console.print(f"[*] Checking {directory} against baseline {baseline_file}")

    if not os.path.exists(baseline_file):
        logger.error(f"[!] Baseline file {baseline_file} not found.")
        raise typer.Exit(code=1)

    path = Path(directory)
    if not path.exists() or not path.is_dir():
        logger.error(f"[!] Directory {directory} does not exist.")
        raise typer.Exit(code=1)

    try:
        with open(baseline_file, "r", encoding="utf-8") as f:
            baseline = json.load(f)
    except OSError as e:
        logger.error(f"[!] Could not read {baseline_file}: {e}")
        raise typer.Exit(code=1)
    except ValueError:
        logger.error(f"[!] Baseline file {baseline_file} is not valid JSON.")
        raise typer.Exit(code=1)

    if not isinstance(baseline, dict):
        logger.error(f"[!] Baseline file {baseline_file} has the wrong format.")
        raise typer.Exit(code=1)

    current_files = set()
    altered_files = []
    new_files = []

    for file_path in path.rglob("*"):
        if file_path.is_file() and not file_path.is_symlink():
            key = str(file_path)
            current_files.add(key)
            if key in baseline:
                try:
                    if hash_file(key) != baseline[key]:
                        altered_files.append(key)
                except OSError as e:
                    logger.warning(f"[-] Could not hash {file_path}: {e}")
            else:
                new_files.append(key)

    deleted_files = sorted(set(baseline) - current_files)

    table = Table(title="File Integrity Monitor Results")
    table.add_column("Status", justify="left")
    table.add_column("File", justify="left")

    for file in sorted(new_files):
        table.add_row("[yellow]NEW[/yellow]", file)
    for file in altered_files:
        table.add_row("[red]ALTERED[/red]", file)
    for file in deleted_files:
        table.add_row("[magenta]DELETED[/magenta]", file)

    if not (new_files or altered_files or deleted_files):
        logger.info("[green][+] No changes detected. Directory matches baseline.[/green]")
    else:
        console.print(table)
        logger.warning(
            f"[!] Integrity check failed: {len(new_files)} new, "
            f"{len(altered_files)} altered, {len(deleted_files)} deleted."
        )
        raise typer.Exit(code=1)


@audit_app.command("static-scan")
def static_scan(
    directory: str = typer.Argument(..., help="Directory of source code to scan"),
):
    """
    Scans source code for hardcoded secrets and API keys.
    """
    path = Path(directory)
    if not path.exists() or not path.is_dir():
        logger.error(f"[!] Directory {directory} does not exist.")
        raise typer.Exit(code=1)

    console.print(f"[*] Running static analysis on {directory} for secrets")

    patterns = {
        "Generic Secret": re.compile(
            r"(?i)\b(password|passwd|secret|api[_-]?key|token)\s*[:=]\s*['\"]([^'\"]{4,})['\"]"
        ),
        "AWS Access Key ID": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "RSA Private Key": re.compile(r"-----BEGIN RSA PRIVATE KEY-----"),
        "Private Key": re.compile(r"-----BEGIN (?:EC |OPENSSH )?PRIVATE KEY-----"),
    }
    placeholders = {"changeme", "password", "secret", "example", "test", "none", "null"}
    max_size = 2 * 1024 * 1024
    own_file = Path(__file__).resolve()

    findings = 0
    for file_path in path.rglob("*"):
        if not file_path.is_file() or file_path.is_symlink():
            continue
        if file_path.resolve() == own_file:
            # Do not flag this module's own rule definitions.
            continue
        if any(part in SKIP_DIRS for part in file_path.relative_to(path).parts):
            continue
        if file_path.suffix.lower() in SKIP_SUFFIXES:
            continue
        try:
            if file_path.stat().st_size > max_size:
                continue
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        for secret_type, pattern in patterns.items():
            for match in pattern.finditer(content):
                if secret_type == "Generic Secret":
                    value = match.group(2).strip()
                    if value.lower() in placeholders or value.startswith(("<", "{{", "your_")):
                        continue
                logger.warning(f"[red][!] {secret_type} found in {file_path}[/red]")
                findings += 1

    if findings == 0:
        logger.info("[green][+] No hardcoded secrets found.[/green]")
    else:
        logger.warning(f"[!] Scan complete. Found {findings} potential secrets.")
        raise typer.Exit(code=1)


@audit_app.command("log-analyze")
def log_analyze(
    logfile: str = typer.Argument(..., help="Path to the log file to analyze"),
):
    """
    Analyzes an Apache/Nginx access log for common injection attempts.
    """
    console.print(f"[*] Analyzing log file {logfile}")

    suspicious_patterns = [
        (r"(%27|')\s*(or|and)\s+", "SQL injection"),
        (r"union\s+(all\s+)?select", "SQL injection"),
        (r"(%3C|<)\s*script", "cross-site scripting"),
        (r"(javascript:|onerror\s*=|onload\s*=)", "cross-site scripting"),
        (r"(\.\./|%2e%2e%2f)", "path traversal"),
    ]

    try:
        with open(logfile, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except OSError as e:
        logger.error(f"[!] Could not read {logfile}: {e}")
        raise typer.Exit(code=1)

    hits = 0
    for i, line in enumerate(lines, start=1):
        for pattern, label in suspicious_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                logger.warning(
                    f"[red][!] Possible {label} on line {i}:[/red] {line.strip()[:100]}..."
                )
                hits += 1
                break

    if hits == 0:
        logger.info("[green][+] Log looks clean. No basic attacks detected.[/green]")
    else:
        logger.warning(f"[!] Found {hits} suspicious log entries.")


@audit_app.command("cloud-audit")
def cloud_audit(
    bucket_name: str = typer.Argument(..., help="The name of the AWS S3 bucket to audit"),
):
    """
    Checks if an AWS S3 bucket allows public unauthenticated listing.
    """
    try:
        import boto3
        from botocore import UNSIGNED
        from botocore.client import Config
        from botocore.exceptions import ClientError
    except ImportError:
        logger.error("[!] boto3 is not installed. Run: pip install 'aegiscore[cloud]'")
        raise typer.Exit(code=1)

    console.print(f"[*] Auditing AWS S3 bucket: {bucket_name}")

    # Unsigned requests are enough to test public access.
    s3 = boto3.client(
        "s3", region_name="us-east-1", config=Config(signature_version=UNSIGNED)
    )

    try:
        response = s3.list_objects_v2(Bucket=bucket_name, MaxKeys=5)
        logger.warning(
            f"[red][!] HIGH RISK: Bucket '{bucket_name}' is publicly readable![/red]"
        )
        for obj in response.get("Contents", []):
            console.print(f"    - {obj['Key']}")
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        if code == "AccessDenied":
            logger.info(
                f"[green][+] Bucket '{bucket_name}' is not publicly listable.[/green]"
            )
        elif code == "NoSuchBucket":
            logger.error(f"[-] Bucket '{bucket_name}' does not exist.")
        else:
            logger.error(f"[!] AWS error: {e}")
    except Exception as e:
        logger.error(f"[!] Failed to audit bucket: {e}")
