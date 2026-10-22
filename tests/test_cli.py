import json

from typer.testing import CliRunner

from aegiscore import __version__
from aegiscore.main import app

runner = CliRunner()


def test_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_no_args_shows_help():
    result = runner.invoke(app, [])
    assert result.exit_code == 0
    assert "Usage:" in result.output


def test_hash_sha256():
    result = runner.invoke(app, ["crypto", "hash", "abc", "--algo", "sha256"])
    assert result.exit_code == 0
    assert "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" in result.output


def test_encode_decode_roundtrip():
    encoded = runner.invoke(app, ["crypto", "encode", "hello", "--format", "base64"])
    assert encoded.exit_code == 0
    assert "aGVsbG8=" in encoded.output

    decoded = runner.invoke(app, ["crypto", "decode", "aGVsbG8=", "--format", "base64"])
    assert decoded.exit_code == 0
    assert "hello" in decoded.output


def test_invalid_port_range():
    result = runner.invoke(app, ["recon", "port-scan", "127.0.0.1", "--start", "500", "--end", "100"])
    assert result.exit_code == 1


def test_fim_baseline_and_check(tmp_path):
    target = tmp_path / "watched"
    target.mkdir()
    (target / "file.txt").write_text("one", encoding="utf-8")
    baseline = tmp_path / "baseline.json"

    result = runner.invoke(
        app, ["audit", "fim-baseline", str(target), "--output", str(baseline)]
    )
    assert result.exit_code == 0
    assert json.loads(baseline.read_text(encoding="utf-8"))

    result = runner.invoke(
        app, ["audit", "fim-check", str(target), "--baseline-file", str(baseline)]
    )
    assert result.exit_code == 0

    (target / "file.txt").write_text("two", encoding="utf-8")
    result = runner.invoke(
        app, ["audit", "fim-check", str(target), "--baseline-file", str(baseline)]
    )
    assert result.exit_code == 1


def test_static_scan_finds_secret(tmp_path):
    value = "abcd1234efgh5678"
    # Build the line so this test file does not match the scanner itself.
    content = "api_key" + ' = "' + value + '"'
    (tmp_path / "config.py").write_text(content, encoding="utf-8")
    result = runner.invoke(app, ["audit", "static-scan", str(tmp_path)])
    assert result.exit_code == 1


def test_report_generate(tmp_path):
    output = tmp_path / "reports" / "audit.md"
    result = runner.invoke(
        app, ["report", "generate", "--title", "Test Audit", "--output", str(output)]
    )
    assert result.exit_code == 0
    assert output.exists()
    assert "Test Audit" in output.read_text(encoding="utf-8")
