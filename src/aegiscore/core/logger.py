import logging

from rich.align import Align
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.theme import Theme

from aegiscore import __version__

# Shared Rich theme
custom_theme = Theme({
    "info": "dim cyan",
    "warning": "magenta",
    "danger": "bold red",
    "success": "bold green",
    "highlight": "bold yellow"
})

console = Console(theme=custom_theme)

def setup_logger(level: int = logging.INFO) -> logging.Logger:
    """Configure the application logger."""
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True, console=console, show_path=False, markup=True)]
    )
    return logging.getLogger("aegiscore")

logger = setup_logger()

def print_banner():
    """Print the application banner."""
    banner_text = """
    █████╗ ███████╗ ██████╗ ██╗███████╗ ██████╗ ██████╗ ██████╗ ███████╗
   ██╔══██╗██╔════╝██╔════╝ ██║██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
   ███████║█████╗  ██║  ███╗██║███████╗██║     ██║   ██║██████╔╝█████╗  
   ██╔══██║██╔══╝  ██║   ██║██║╚════██║██║     ██║   ██║██╔══██╗██╔══╝  
   ██║  ██║███████╗╚██████╔╝██║███████║╚██████╗╚██████╔╝██║  ██║███████╗
   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝
    """
    
    panel = Panel(
        Align.center(
            f"[bold cyan]{banner_text}[/bold cyan]\n"
            "[bold white]SECURITY TOOLKIT[/bold white]\n"
            f"[dim]v{__version__}[/dim]"
        ),
        border_style="cyan",
        padding=(1, 2)
    )
    console.print(panel)
    console.print()
