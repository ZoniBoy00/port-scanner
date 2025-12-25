#!/usr/bin/env python3
"""
A feature-rich and modern port scanner with a rich CLI.
"""
import argparse

from rich.panel import Panel
from rich.text import Text

from utils import console, parse_port_range
from interactive import interactive_mode
from core import run_scan

def main():
    """
    Main function to handle argument parsing and initiate the scan.
    """
    parser = argparse.ArgumentParser(
        description='A feature-rich and modern port scanner with a rich CLI.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t 192.168.1.1 -p 80,443,8080
  %(prog)s -t 192.168.1.0/24 -p 1-1000 -o results.json
  %(prog)s -t 10.0.0.1,10.0.0.2 -p common --banner
  %(prog)s (for interactive mode)
        """
    )
    
    # Arguments for CLI mode
    parser.add_argument('-t', '--target', help='Target IP(s) or CIDR (comma-separated)')
    parser.add_argument('-p', '--ports', help='Ports to scan (e.g., 80,443, 1-1000, common, all)')
    parser.add_argument('-o', '--output', help='Output file (format based on extension: .txt, .json, .csv)')
    parser.add_argument('--timeout', type=float, default=0.3, help='Timeout per port in seconds (default: 0.3)')
    parser.add_argument('-w', '--workers', type=int, default=100, help='Number of concurrent threads (default: 100)')
    parser.add_argument('-b', '--banner', action='store_true', help='Enable banner grabbing to identify services')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output (shows open ports as they are found)')
    parser.add_argument('--no-progress', action='store_true', help='Disable the progress bar')
    
    args = parser.parse_args()
    
    # If no target or ports are specified, enter interactive mode
    if not args.target or not args.ports:
        interactive_mode()
        return

    # Display banner for CLI mode
    banner_text = Text("Advanced Network Port Scanner", justify="center", style="bold magenta")
    console.print(Panel(banner_text, title="Port Scanner", border_style="blue"))
    
    # Parse targets and ports
    targets = [t.strip() for t in args.target.split(',')]
    ports = parse_port_range(args.ports)
    
    # Run the scan with CLI arguments
    run_scan(
        targets=targets,
        ports=ports,
        timeout=args.timeout,
        workers=args.workers,
        banner=args.banner,
        verbose=args.verbose,
        no_progress=args.no_progress,
        output=args.output
    )

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n\n[[yellow]Scan interrupted by user.[/yellow]]")
    except Exception as e:
        console.print(f"\n[[red]Fatal error[/red]]: {e}")
        console.print_exception(show_locals=True)
