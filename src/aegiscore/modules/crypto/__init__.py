import base64
import hashlib
import urllib.parse
from typing import Optional

import requests
import typer

from aegiscore.core.logger import console, logger

crypto_app = typer.Typer(help="Cryptography & Password Tools")


def _new_hasher(algo: str):
    try:
        return hashlib.new(algo)
    except ValueError:
        logger.error(f"[!] Unsupported algorithm: {algo}")
        raise typer.Exit(code=1)


@crypto_app.command("hash")
def generate_hash(
    text: str = typer.Argument(..., help="The text to hash"),
    algo: str = typer.Option("sha256", help="Algorithm to use (md5, sha1, sha256, sha512)"),
):
    """
    Generates a cryptographic hash for a given string.
    """
    h = _new_hasher(algo)
    h.update(text.encode("utf-8"))
    console.print(f"[bold cyan]{algo.upper()}:[/bold cyan] {h.hexdigest()}")


@crypto_app.command("encode")
def encode_text(
    text: str = typer.Argument(..., help="Text to encode"),
    fmt: str = typer.Option("base64", "--format", help="Format: base64, hex, or url"),
):
    """
    Encodes text into various formats.
    """
    if fmt == "base64":
        result = base64.b64encode(text.encode("utf-8")).decode("utf-8")
    elif fmt == "hex":
        result = text.encode("utf-8").hex()
    elif fmt == "url":
        result = urllib.parse.quote(text)
    else:
        logger.error(f"[!] Unsupported format: {fmt}")
        raise typer.Exit(code=1)

    console.print(f"[bold cyan]Encoded ({fmt}):[/bold cyan] {result}")


@crypto_app.command("decode")
def decode_text(
    text: str = typer.Argument(..., help="Text to decode"),
    fmt: str = typer.Option("base64", "--format", help="Format: base64, hex, or url"),
):
    """
    Decodes text from various formats.
    """
    try:
        if fmt == "base64":
            result = base64.b64decode(text, validate=True).decode("utf-8")
        elif fmt == "hex":
            result = bytes.fromhex(text).decode("utf-8")
        elif fmt == "url":
            result = urllib.parse.unquote(text)
        else:
            logger.error(f"[!] Unsupported format: {fmt}")
            raise typer.Exit(code=1)

        console.print(f"[bold cyan]Decoded ({fmt}):[/bold cyan] {result}")
    except (ValueError, UnicodeDecodeError) as e:
        logger.error(f"[!] Decoding failed: {e}")
        raise typer.Exit(code=1)


@crypto_app.command("audit-pwd")
def audit_password(
    password: Optional[str] = typer.Argument(
        None, help="Password to check. Omit this to be prompted instead."
    ),
):
    """
    Checks a password against HaveIBeenPwned using k-Anonymity.
    """
    if password is None:
        password = typer.prompt("Password", hide_input=True)

    console.print("[*] Auditing password via HaveIBeenPwned (k-Anonymity)")

    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]

    try:
        response = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}", timeout=10
        )
        response.raise_for_status()
    except requests.RequestException as e:
        logger.error(f"[!] Could not reach the API: {e}")
        raise typer.Exit(code=1)

    for line in response.text.splitlines():
        if ":" not in line:
            continue
        candidate, count = line.split(":", 1)
        if candidate == suffix:
            logger.warning(
                f"[red][!] This password appeared {count} times in known breaches.[/red]"
            )
            return

    logger.info("[green][+] Password was not found in known breaches.[/green]")


@crypto_app.command("crack")
def crack_hash(
    hash_value: str = typer.Argument(..., help="The hash to crack"),
    wordlist: str = typer.Argument(..., help="Path to the dictionary wordlist"),
    algo: str = typer.Option("md5", help="Hashing algorithm used"),
):
    """
    Performs an offline dictionary attack against a hash.
    """
    console.print(f"[*] Attempting to crack {algo} hash: {hash_value}")

    hasher = _new_hasher(algo)
    target = hash_value.lower()
    attempts = 0

    try:
        with open(wordlist, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                word = line.rstrip("\r\n")
                if not word:
                    continue

                attempts += 1
                candidate = hasher.copy()
                candidate.update(word.encode("utf-8"))
                if candidate.hexdigest() == target:
                    logger.info(
                        f"[green][+] Hash cracked after {attempts} attempts![/green] "
                        f"Password: [bold]{word}[/bold]"
                    )
                    return
    except OSError as e:
        logger.error(f"[!] Could not read wordlist: {e}")
        raise typer.Exit(code=1)

    logger.warning(f"[-] Hash not found in the wordlist ({attempts} attempts).")


@crypto_app.command("stego-hide")
def stego_hide(
    image: str = typer.Argument(..., help="Path to the cover image (e.g., cover.png)"),
    secret: str = typer.Argument(..., help="The secret message to hide"),
    output: str = typer.Option("secret_image.png", help="Output file name"),
):
    """
    Hides a secret message inside an image file (LSB steganography).
    """
    console.print(f"[*] Hiding secret inside {image}")
    try:
        from stegano import lsb
    except ImportError:
        logger.error("[!] stegano is not installed. Run: pip install 'aegiscore[stego]'")
        raise typer.Exit(code=1)

    try:
        secret_image = lsb.hide(image, secret)
        secret_image.save(output)
        logger.info(f"[green][+] Secret hidden inside {output}[/green]")
    except Exception as e:
        logger.error(f"[!] Steganography failed: {e}")
        raise typer.Exit(code=1)


@crypto_app.command("stego-reveal")
def stego_reveal(
    image: str = typer.Argument(..., help="Path to the image containing a secret"),
):
    """
    Reveals a hidden secret message from an image file.
    """
    console.print(f"[*] Analyzing {image} for hidden secrets...")
    try:
        from stegano import lsb
    except ImportError:
        logger.error("[!] stegano is not installed. Run: pip install 'aegiscore[stego]'")
        raise typer.Exit(code=1)

    try:
        secret = lsb.reveal(image)
        if secret:
            logger.info(f"[green][+] Secret revealed:[/green]\n[bold]{secret}[/bold]")
        else:
            logger.warning("[-] No secret message found in this image.")
    except IndexError:
        logger.warning("[-] No secret message found or image is not encoded properly.")
    except Exception as e:
        logger.error(f"[!] Failed to analyze image: {e}")
