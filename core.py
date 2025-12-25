"""
This module contains the core function to run the scan.
"""
import time
from typing import List, Optional

from scanner import PortScanner
from utils import console, print_results, save_results

def run_scan(targets: List[str], ports: List[int], timeout: float, workers: int, banner: bool, verbose: bool, no_progress: bool, output: Optional[str]):
    """
    Executes the scan with the given parameters.

    Args:
        targets (List[str]): The targets to scan.
        ports (List[int]): The ports to scan.
        timeout (float): The timeout for each connection.
        workers (int): The number of concurrent workers.
        banner (bool): Whether to grab banners.
        verbose (bool): Whether to show verbose output.
        no_progress (bool): Whether to disable the progress bar.
        output (Optional[str]): The output file path.
    """
    if not ports:
        console.print("[[red]Error[/red]] No valid ports specified.")
        return

    # Initialize the scanner
    scanner = PortScanner(timeout=timeout, max_workers=workers, banner_grab=banner)
    
    console.print(f"[*] Scanning {len(targets)} target(s) on {len(ports)} port(s) ...")
    start_time = time.time()
    
    # Run the scan
    results = scanner.scan_target(targets, ports, verbose=verbose, show_progress=not no_progress)
    
    elapsed = time.time() - start_time
    
    console.print(f"\n[*] Scan completed in {elapsed:.2f} seconds.")
    console.print(f"[*] Found [bold green]{len(results)}[/bold green] open port(s).")
    
    # Process results
    if results:
        print_results(results, show_banner=banner)
        if output:
            # Determine output format from file extension
            ext = output.split('.')[-1].lower()
            if ext not in ['txt', 'json', 'csv']:
                console.print(f"[[yellow]Warning[/yellow]] Invalid output format '{ext}', defaulting to 'txt'.")
                ext = 'txt'
            save_results(results, ext, output)
