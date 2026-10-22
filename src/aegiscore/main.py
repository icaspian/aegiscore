import typer

from aegiscore import __version__
from aegiscore.core.logger import logger, print_banner
from aegiscore.modules.audit import audit_app
from aegiscore.modules.automation import automation_app
from aegiscore.modules.crypto import crypto_app
from aegiscore.modules.recon import recon_app
from aegiscore.modules.report import report_app
from aegiscore.modules.web import web_app

app = typer.Typer(
    name="aegis",
    help="AegisCore - command-line security toolkit",
    no_args_is_help=False,
)

# Register sub-modules
app.add_typer(recon_app, name="recon", help="Network & Reconnaissance Tools")
app.add_typer(audit_app, name="audit", help="Defensive & Auditing Tools")
app.add_typer(web_app, name="web", help="Web Application Security Tools")
app.add_typer(crypto_app, name="crypto", help="Cryptography & Password Tools")
app.add_typer(automation_app, name="automation", help="Automation & Workflow Tools")
app.add_typer(report_app, name="report", help="Reporting & Export Tools")


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(
        False, "--version", "-V", help="Show the version and exit.", is_eager=True
    ),
):
    """AegisCore - command-line security toolkit"""
    if version:
        typer.echo(f"aegis {__version__}")
        raise typer.Exit()

    if ctx.invoked_subcommand is None:
        print_banner()
        typer.echo(ctx.get_help())
        logger.info("Run 'aegis <module> --help' for module options.")
