"""
This module contains the logic for the interactive mode of the port scanner.
"""
from rich.panel import Panel
from rich.prompt import Prompt, FloatPrompt, IntPrompt, Confirm
from rich.text import Text

from utils import console, parse_port_range
from core import run_scan

def interactive_mode():
    """
    Runs the port scanner in an interactive mode, prompting the user for input.
    """
    
    # Display a banner
    banner_text = Text("Advanced Network Port Scanner", justify="center", style="bold magenta")
    console.print(Panel(banner_text, title="Port Scanner", border_style="blue"))

    # Prompt user for input
    target_input = Prompt.ask("[cyan]Enter target(s) (IP, CIDR, or comma-separated)[/cyan]")
    targets = [t.strip() for t in target_input.split(',')]
    
    port_input = Prompt.ask("[cyan]Enter ports (e.g., 80,443 or 1-1000 or 'common' or 'all')[/cyan]", default="common")
    ports = parse_port_range(port_input)
    
    timeout = FloatPrompt.ask("[cyan]Timeout per port[/cyan]", default=0.3)
    workers = IntPrompt.ask("[cyan]Max concurrent workers[/cyan]", default=100)
    banner_grab = Confirm.ask("[cyan]Enable banner grabbing?[/cyan]", default=False)
    verbose = Confirm.ask("[cyan]Enable verbose output?[/cyan]", default=False)
    
    # Ask to save results and get filename
    output_file = None
    if Confirm.ask("\n[cyan]Save results to a file?[/cyan]"):
        fmt = Prompt.ask("[cyan]Format (txt/json/csv)[/cyan]", choices=['txt', 'json', 'csv'], default='txt')
        default_filename = f"open_ports.{fmt}"
        output_file = Prompt.ask(f"[cyan]Filename[/cyan]", default=default_filename)

    # Run the scan with the provided inputs
    run_scan(
        targets=targets,
        ports=ports,
        timeout=timeout,
        workers=workers,
        banner=banner_grab,
        verbose=verbose,
        no_progress=False,
        output=output_file
    )
