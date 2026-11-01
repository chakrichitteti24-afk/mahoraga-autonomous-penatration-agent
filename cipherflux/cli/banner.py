"""
CipherFlux Labs Terminal Splash Screen & ASCII Banner Module.
"""
import os
import sys
import platform
from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich import box

from .theme import get_console

ASCII_LOGO_SLANT = r"""
   ______ _____ ____  __  __ _____ ____  ______ _      _    _ __   __
  / ____//_  _// __ \/ / / // ____// __ \/ ____// /     / /  / /\ \ / /
 / /      / / / /_/ // /_/ // __/  / /_/ // __/  / /     / /  / /  \ V / 
/ /___  _/ / / ____// __  // /___ / _, _// /___ / /___  / /__/ /   /   \ 
\____/ /___//_/    /_/ /_//_____//_/ |_|/_____//_____/  \____/   /_/ \_\
"""

ASCII_LOGO_COMPACT = r"""
   ___ _       _               ___ _            
  / __(_)_ __ | |__   ___ _ __/ __\ |_   ___  __
 / /  | | '_ \| '_ \ / _ \ '__\ \ | | | | \ \/ /
/ /___| | |_) | | | |  __/ | _ \ \| | |_| |>  < 
\____/|_| .__/|_| |_|\___|_| \__/ |_|\__,_/_/\_\
        |_|                                     
"""

VERSION = "1.0.0"
ENGINE_NAME = "CIPHERFLUX SCANNING ENGINE"

def get_platform_name() -> str:
    """Detect platform with Kali Linux priority detection."""
    if os.path.exists("/etc/os-release"):
        try:
            with open("/etc/os-release", "r", encoding="utf-8") as f:
                content = f.read().lower()
                if "kali" in content:
                    return "KALI LINUX"
                elif "debian" in content:
                    return "DEBIAN LINUX"
                elif "ubuntu" in content:
                    return "UBUNTU LINUX"
        except Exception:
            pass
    system = platform.system().upper()
    if system == "LINUX":
        return "KALI LINUX / DEBIAN"
    return f"{system} (DEV COMPAT)"

def render_banner(console: Optional[Console] = None, plain: bool = False) -> None:
    """Render the official CipherFlux splash screen."""
    if console is None:
        console = get_console()

    plat = get_platform_name()

    if plain or console.no_color:
        plain_banner = f"""
================================================================================
                         [+] CIPHERFLUX LABS [+]
                  ADVANCED VULNERABILITY SCANNER
               SECURITY * DETECTION * VERIFICATION
================================================================================
 VERSION       : {VERSION}
 PLATFORM      : {plat}
 ENGINE        : {ENGINE_NAME}
 STATUS        : READY
================================================================================
"""
        console.print(plain_banner)
        return

    # Choose logo based on console width
    width = console.width
    logo_art = ASCII_LOGO_SLANT if width >= 78 else ASCII_LOGO_COMPACT

    grid = Table.grid(expand=True)
    grid.add_column(justify="center")

    logo_text = Text(logo_art, style="bold cyan")
    grid.add_row(logo_text)

    sub_title = Text("◈ CIPHERFLUX LABS ◈", style="bold green")
    tagline = Text("ADVANCED VULNERABILITY ASSESSMENT FRAMEWORK", style="bold white")
    motto = Text("SECURITY • DETECTION • VERIFICATION", style="bold cyan")
    grid.add_row(sub_title)
    grid.add_row(tagline)
    grid.add_row(motto)

    # Metadata table
    meta_table = Table(box=box.SIMPLE, show_header=False, pad_edge=False, style="dim")
    meta_table.add_column("Key", style="bold cyan", width=16)
    meta_table.add_column("Separator", style="dim white", width=3)
    meta_table.add_column("Value", style="bold white")

    meta_table.add_row("VERSION", ":", VERSION)
    meta_table.add_row("PLATFORM", ":", plat)
    meta_table.add_row("ENGINE", ":", ENGINE_NAME)
    meta_table.add_row("STATUS", ":", "[bold green]READY[/bold green]")

    panel_content = Table.grid(expand=True)
    panel_content.add_row(grid)
    panel_content.add_row(Text(""))
    panel_content.add_row(meta_table)

    panel = Panel(
        panel_content,
        border_style="cyan",
        box=box.DOUBLE,
        padding=(1, 2),
    )
    console.print(panel)

def print_banner(console: Optional[Console] = None, no_banner: bool = False, plain: bool = False) -> None:
    """Print banner if not disabled."""
    if no_banner:
        return
    render_banner(console, plain=plain)
