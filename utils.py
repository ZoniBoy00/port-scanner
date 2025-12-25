"""
This module contains utility functions and shared objects for the port scanner.
"""
import json
import csv
from typing import List, Set

from rich.console import Console
from rich.table import Table

from scanner import ScanResult

# A list of common ports to scan if the user selects 'common'.
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 5900, 8080, 8443]

# Create a global console object for rich output
console = Console()

def parse_port_range(port_input: str) -> List[int]:
    """
    Parses a port range string into a list of integers.

    The string can be in the format of:
    - A single port: '80'
    - Comma-separated ports: '80,443,8080'
    - A range of ports: '1-1024'
    - A combination of the above: '80,443,1000-2000'
    - Special keywords: 'all' (1-65535) or 'common'.

    Args:
        port_input (str): The string to parse.

    Returns:
        List[int]: A sorted list of unique port numbers.
    """
    ports: Set[int] = set()
    
    port_input = port_input.lower()

    if port_input == 'all':
        return list(range(1, 65536))
    elif port_input == 'common':
        return COMMON_PORTS
    
    for part in port_input.split(','):
        part = part.strip()
        if '-' in part:
            try:
                start, end = map(int, part.split('-'))
                if 1 <= start <= 65535 and 1 <= end <= 65535 and start <= end:
                    ports.update(range(start, end + 1))
                else:
                    console.print(f"[[yellow]Warning[/yellow]] Invalid port range: {part}. Ports must be between 1 and 65535.")
            except ValueError:
                console.print(f"[[yellow]Warning[/yellow]] Invalid port range format: {part}")
        else:
            try:
                port = int(part)
                if 1 <= port <= 65535:
                    ports.add(port)
                else:
                    console.print(f"[[yellow]Warning[/yellow]] Invalid port: {part}. Port must be between 1 and 65535.")
            except ValueError:
                console.print(f"[[yellow]Warning[/yellow]] Invalid port number: {part}")
    
    return sorted(list(ports))

def print_results(results: List[ScanResult], show_banner: bool = False):
    """
    Prints the scan results in a nicely formatted table using rich.

    Args:
        results (List[ScanResult]): A list of ScanResult objects.
        show_banner (bool): Whether to display the banner column.
    """
    if not results:
        console.print("\n[yellow]No open ports found.[/yellow]")
        return
    
    # Create a table to display the results
    table = Table(title="Scan Results", show_header=True, header_style="bold magenta")
    table.add_column("IP Address", style="cyan", width=15)
    table.add_column("Port", style="green", width=8)
    table.add_column("Service", style="yellow", width=15)
    if show_banner:
        table.add_column("Banner", style="white", no_wrap=False, width=40)

    # Sort results by IP and port before printing
    for result in sorted(results, key=lambda x: (x.ip, x.port)):
        row = [result.ip, str(result.port), result.service]
        if show_banner:
            # Sanitize banner for printing to avoid breaking table layout
            sanitized_banner = result.banner.replace('[', r'\[')
            row.append(sanitized_banner)
        table.add_row(*row)
    
    console.print(table)

def save_results(results: List[ScanResult], output_format: str, filename: str):
    """
    Saves the scan results to a file in the specified format.

    Supported formats are 'txt', 'json', and 'csv'.

    Args:
        results (List[ScanResult]): A list of ScanResult objects.
        output_format (str): The format to save the results in.
        filename (str): The name of the file to save to.
    """
    try:
        if output_format == 'txt':
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(f"{'IP Address':<15} {'Port':<8} {'Service':<15} {'Banner':<40}\n")
                f.write("=" * 80 + "\n")
                for result in sorted(results, key=lambda x: (x.ip, x.port)):
                    f.write(f"{result.ip:<15} {result.port:<8} {result.service:<15} {result.banner[:40]:<40}\n")
        
        elif output_format == 'json':
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump([r.to_dict() for r in results], f, indent=2)
        
        elif output_format == 'csv':
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=['ip', 'port', 'service', 'banner'])
                writer.writeheader()
                writer.writerows([r.to_dict() for r in results])
        
        console.print(f"\n[[bold green]Success[/bold green]] Results saved to '{filename}'")
    except IOError as e:
        console.print(f"\n[[red]Error[/red]] Could not save results to '{filename}': {e}")
