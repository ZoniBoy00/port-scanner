"""
This module contains the core port scanning logic.
"""
import socket
import ipaddress
import concurrent.futures
from typing import List, Tuple, Optional, Set
from dataclasses import dataclass, asdict

from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeRemainingColumn, TimeElapsedColumn
from rich.console import Console

console = Console()

@dataclass
class ScanResult:
    """
    Data class to store the result of a port scan.
    
    Attributes:
        ip (str): The IP address of the scanned host.
        port (int): The port number.
        service (str): The name of the service running on the port.
        banner (str): The banner grabbed from the port, if any.
    """
    ip: str
    port: int
    service: str
    banner: str = ""
    
    def to_dict(self):
        """Converts the ScanResult to a dictionary."""
        return asdict(self)

class PortScanner:
    """
    An advanced port scanner with configurable options.

    Attributes:
        timeout (float): The timeout for each port scan.
        max_workers (int): The maximum number of concurrent threads to use.
        banner_grab (bool): Whether to perform banner grabbing.
    """
    
    def __init__(self, timeout: float = 0.3, max_workers: int = 100, banner_grab: bool = False):
        """
        Initializes the PortScanner.

        Args:
            timeout (float): The timeout for each port scan.
            max_workers (int): The maximum number of concurrent threads.
            banner_grab (bool): Whether to enable banner grabbing.
        """
        self.timeout = timeout
        self.max_workers = max_workers
        self.banner_grab = banner_grab
        self.service_cache = {}
    
    def get_service_name(self, port: int) -> str:
        """
        Gets the service name for a given port, with caching.

        Args:
            port (int): The port number.

        Returns:
            str: The service name, or 'unknown'.
        """
        if port not in self.service_cache:
            try:
                self.service_cache[port] = socket.getservbyport(port)
            except (OSError, socket.error):
                self.service_cache[port] = "unknown"
        return self.service_cache[port]
    
    def grab_banner(self, ip: str, port: int) -> str:
        """
        Attempts to grab the service banner from an open port.

        Args:
            ip (str): The IP address of the target.
            port (int): The port number.

        Returns:
            str: The banner, or an empty string if it fails.
        """
        if not self.banner_grab:
            return ""
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1.0)
                sock.connect((ip, port))
                # Send a generic HTTP HEAD request, which works for many services
                sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                return banner[:100]  # Limit banner length
        except:
            # Ignore all errors during banner grabbing
            return ""
    
    def scan_port(self, ip_port: Tuple[str, int], verbose: bool = False) -> Optional[ScanResult]:
        """
        Scans a single port on a single IP address.

        Args:
            ip_port (Tuple[str, int]): A tuple containing the IP address and port number.
            verbose (bool): Whether to print verbose output.

        Returns:
            Optional[ScanResult]: A ScanResult object if the port is open, otherwise None.
        """
        ip, port = ip_port
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((str(ip), port))
                
                if result == 0:
                    service = self.get_service_name(port)
                    banner = self.grab_banner(str(ip), port)
                    return ScanResult(str(ip), port, service, banner)
        except socket.gaierror:
            # Handle invalid hostname errors
            pass
        except socket.error:
            # Handle connection errors
            pass
        except Exception as e:
            if verbose:
                console.print(f"[[red]Error[/red]] Error scanning {ip}:{port}: {str(e)}")
        
        return None
    
    def scan_target(self, targets: List[str], ports: List[int], verbose: bool = False, show_progress: bool = True) -> List[ScanResult]:
        """
        Scans a list of targets for a list of open ports.

        Args:
            targets (List[str]): A list of target IPs or CIDR networks.
            ports (List[int]): A list of ports to scan.
            verbose (bool): Whether to print verbose output.
            show_progress (bool): Whether to display a progress bar.

        Returns:
            List[ScanResult]: A list of ScanResult objects for open ports.
        """
        ip_port_pairs = []
        for target in targets:
            try:
                # Handle CIDR notation
                if '/' in target:
                    network = ipaddress.IPv4Network(target, strict=False)
                    for ip in network.hosts():
                        ip_port_pairs.extend([(str(ip), port) for port in ports])
                else:
                    # Handle single IP
                    ip = ipaddress.IPv4Address(target)
                    ip_port_pairs.extend([(str(ip), port) for port in ports])
            except ValueError as e:
                console.print(f"[[red]Error[/red]] Invalid target: {target} - {e}")
                continue
        
        if not ip_port_pairs:
            return []
        
        results = []
        
        # Configure rich progress bar
        progress_columns = [
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
            TimeElapsedColumn(),
        ]

        with Progress(*progress_columns, console=console, disable=not show_progress) as progress:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                scan_task = progress.add_task("Scanning...", total=len(ip_port_pairs))
                
                # Submit all scan jobs to the thread pool
                futures = {executor.submit(self.scan_port, pair, verbose): pair for pair in ip_port_pairs}

                # Process results as they complete
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result:
                        results.append(result)
                        if verbose:
                            console.print(f"[[bold green]OPEN[/bold green]] {result.ip}:{result.port} ({result.service})")
                    progress.update(scan_task, advance=1)
        
        return results
