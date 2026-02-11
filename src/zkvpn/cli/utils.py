"""CLI utilities for ZK-VPN.

Formatting, colors, tables, and progress bars.
"""

import time
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import humanize
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.syntax import Syntax
from rich import box
import pyperclip
import qrcode
from io import StringIO

console = Console()


def print_success(message: str):
    """Print success message in green."""
    console.print(f"✅ {message}", style="bold green")


def print_error(message: str):
    """Print error message in red."""
    console.print(f"❌ {message}", style="bold red")


def print_warning(message: str):
    """Print warning message in yellow."""
    console.print(f"⚠️  {message}", style="bold yellow")


def print_info(message: str):
    """Print info message in blue."""
    console.print(f"ℹ️  {message}", style="bold blue")


def print_table(title: str, columns: List[str], rows: List[List[str]]):
    """Print data as a rich table.
    
    Args:
        title: Table title
        columns: Column headers
        rows: Table rows
    """
    table = Table(title=title, box=box.ROUNDED, title_style="bold cyan")
    
    for col in columns:
        table.add_column(col, style="cyan")
    
    for row in rows:
        table.add_row(*[str(cell) for cell in row])
    
    console.print(table)


def print_json(data: Dict[str, Any]):
    """Print JSON data with syntax highlighting."""
    import json
    syntax = Syntax(
        json.dumps(data, indent=2, default=str),
        "json",
        theme="monokai",
        line_numbers=True
    )
    console.print(syntax)


def format_bytes(bytes_val: int) -> str:
    """Format bytes to human readable string."""
    return humanize.naturalsize(bytes_val, binary=True)


def format_duration(seconds: float) -> str:
    """Format duration in seconds to human readable."""
    return humanize.naturaldelta(timedelta(seconds=seconds))


def format_timestamp(timestamp: float) -> str:
    """Format timestamp to human readable."""
    dt = datetime.fromtimestamp(timestamp)
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def create_progress_spinner(message: str):
    """Create a progress spinner."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True
    )


async def run_with_spinner(coro, description: str) -> Any:
    """Run an async function with a spinner."""
    with create_progress_spinner(description) as progress:
        progress.add_task(description=description, total=None)
        return await coro


def generate_qr_code(data: str) -> str:
    """Generate QR code as ASCII art.
    
    Args:
        data: Data to encode
        
    Returns:
        str: ASCII representation of QR code
    """
    qr = qrcode.QRCode(
        version=1,
        box_size=1,
        border=1
    )
    qr.add_data(data)
    qr.make(fit=True)
    
    f = StringIO()
    qr.print_ascii(out=f)
    f.seek(0)
    return f.read()


def copy_to_clipboard(text: str) -> bool:
    """Copy text to clipboard.
    
    Returns:
        bool: True if successful
    """
    try:
        pyperclip.copy(text)
        return True
    except:
        return False


class StatusColors:
    """ANSI color codes for status display."""
    
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'
    
    @classmethod
    def colorize(cls, text: str, color: str) -> str:
        """Colorize text with ANSI color."""
        return f"{color}{text}{cls.END}"
    
    @classmethod
    def status_symbol(cls, status: bool) -> str:
        """Return colored status symbol."""
        if status:
            return f"{cls.GREEN}●{cls.END}"
        return f"{cls.RED}○{cls.END}"
    
    @classmethod
    def health_color(cls, age_seconds: float) -> str:
        """Color based on proof age."""
        if age_seconds < 60:
            return cls.GREEN
        elif age_seconds < 300:
            return cls.YELLOW
        else:
            return cls.RED


__all__ = [
    "console",
    "print_success",
    "print_error",
    "print_warning",
    "print_info",
    "print_table",
    "print_json",
    "format_bytes",
    "format_duration",
    "format_timestamp",
    "create_progress_spinner",
    "run_with_spinner",
    "generate_qr_code",
    "copy_to_clipboard",
    "StatusColors"
]
