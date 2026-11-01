"""
CipherFlux Labs Custom Terminal Color Theme & Rich Styling.
"""
import sys
from rich.theme import Theme
from rich.console import Console

# Ensure UTF-8 output across Windows and Linux
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

CIPHERFLUX_THEME = Theme({
    "success": "bold green",
    "critical": "bold red",
    "warning": "bold yellow",
    "info": "bold cyan",
    "module": "bold blue",
    "text": "white",
    "dim": "dim white",
    "highlight": "bold magenta",
    "banner.title": "bold cyan",
    "banner.sub": "bold white",
    "banner.border": "cyan",
    "banner.meta": "bright_cyan",
    "status.confirmed": "bold red",
    "status.potential": "bold yellow",
    "status.inconclusive": "bold blue",
    "status.not_vulnerable": "bold green",
    "status.not_tested": "dim white",
})

def get_console(no_color: bool = False, force_terminal: bool = None) -> Console:
    """Return a configured Rich Console with CipherFlux theme."""
    return Console(
        theme=CIPHERFLUX_THEME,
        no_color=no_color,
        force_terminal=force_terminal,
        highlight=False,
    )
