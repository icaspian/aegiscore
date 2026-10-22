# AegisCore

[![CI](https://github.com/icaspian/aegiscore/actions/workflows/ci.yml/badge.svg)](https://github.com/icaspian/aegiscore/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A small command-line security toolkit for defensive auditing and authorized
testing. It bundles common checks into one Typer/Rich CLI.

> Use it only on systems you own or have written permission to test. The
> authors are not responsible for misuse or damage.

## Modules

**recon**
- `port-scan` – async TCP port scanner
- `banner` – service banner grab
- `osint` – IP/domain geolocation via ip-api.com
- `subdomains` – subdomain lookup through crt.sh
- `pcap` – look for plaintext credentials in a capture file (needs `scapy`)

**web**
- `headers` – grade common HTTP security headers
- `fuzz` – async directory/endpoint discovery
- `vuln-scan` – basic reflected XSS and SQLi checks on query parameters
- `scrape` – extract links and email addresses from a page

**audit**
- `fim-baseline` / `fim-check` – SHA-256 file integrity monitoring
- `static-scan` – find hardcoded secrets in source trees
- `log-analyze` – scan access logs for common injection patterns
- `cloud-audit` – check if an S3 bucket allows public listing (needs `boto3`)

**crypto**
- `hash`, `encode`, `decode`
- `audit-pwd` – HaveIBeenPwned check using k-Anonymity
- `crack` – offline dictionary attack against a hash
- `stego-hide` / `stego-reveal` – LSB steganography (needs `stegano`)

**automation / report**
- `orchestrate` – port scan, then header analysis if a web port is open
- `generate` – write a Markdown report skeleton

## Install

Python 3.10 or newer.

### Script

Linux / Kali / Termux:

```bash
git clone https://github.com/icaspian/aegiscore.git
cd aegiscore
chmod +x install.sh
./install.sh
source venv/bin/activate
```

Windows:

```cmd
git clone https://github.com/icaspian/aegiscore.git
cd aegiscore
install.bat
```

### Manual

```bash
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -e ".[all]"
```

`.[all]` pulls in the optional `scapy`, `boto3`, and `stegano` modules. To keep
the install small, use `pip install -e .` and add extras only when needed:

```bash
pip install -e ".[pcap]"    # scapy
pip install -e ".[cloud]"   # boto3
pip install -e ".[stego]"   # stegano
```

## Usage

```bash
aegis --help
aegis --version

aegis recon port-scan 192.168.1.10 --start 1 --end 1024
aegis recon subdomains example.com
aegis recon pcap capture.pcap

aegis web headers https://example.com
aegis web fuzz https://example.com
aegis web vuln-scan "https://example.com/item?id=1"

aegis audit fim-baseline ./src --output src-baseline.json
aegis audit fim-check ./src --baseline-file src-baseline.json
aegis audit static-scan ./src
aegis audit cloud-audit my-bucket

aegis crypto hash "hello" --algo sha256
aegis crypto audit-pwd                 # prompts without echoing
aegis crypto crack 5d41402abc4b2a76b9719d911017c592 wordlist.txt

aegis automation orchestrate example.com
aegis report generate --title "Weekly Audit" --output audit.md
```

## Development

```bash
pip install -e ".[dev]"
pytest
```

`fim-check` and `static-scan` exit with status 1 when they find changes or
secrets, so both can be used as CI checks. The test suite covers the CLI entry
point and local-only commands; network tests are intentionally excluded.

## License

MIT. See [LICENSE](LICENSE).
