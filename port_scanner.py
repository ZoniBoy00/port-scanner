import socket
import ipaddress
import concurrent.futures
import time
from colorama import Fore, init
from tqdm import tqdm
import random

# Initialize colorama for cross-platform colored terminal text
init(autoreset=True)

# ASCII art banner for the Port Scanner
BANNER = """
 ____            _     ____                                  
|  _ \ ___  _ __| |_  / ___|  ___ __ _ _ __  _ __   ___ _ __ 
| |_) / _ \| '__| __| \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
|  __/ (_) | |  | |_   ___) | (_| (_| | | | | | | |  __/ |   
|_|   \___/|_|   \__| |____/ \___\__,_|_| |_|_| |_|\___|_|   
"""

# Constants for scan configuration
MAX_WORKERS = 50  # Reduced number of workers to prevent buffer overflow
SCAN_DELAY = 0.1  # Increased delay between port scans
MAX_PORT = 65535  # Maximum port number

def get_service_name(port):
    """Get the service name for a given port number."""
    try:
        return socket.getservbyport(port)
    except:
        return "Unknown"

def scan_port(ip_port):
    """Scan a single IP:port combination."""
    ip, port = ip_port
    try:
        with socket.create_connection((str(ip), port), timeout=0.5) as sock:
            time.sleep(SCAN_DELAY)
            return (ip, port, get_service_name(port))
    except (socket.timeout, ConnectionRefusedError):
        return None
    except Exception as e:
        print(Fore.RED + f"[-] Error scanning {ip}:{port}: {str(e)}")
        return None

def scan_network(network, ports):
    """Scan a network for open ports."""
    ip_port_pairs = [(ip, port) for ip in network.hosts() for port in ports]
    random.shuffle(ip_port_pairs)
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        results = list(tqdm(executor.map(scan_port, ip_port_pairs), total=len(ip_port_pairs), desc="Scanning", unit="port"))
    return [result for result in results if result]

def print_results(all_open_ports):
    """Print the scan results in a formatted table."""
    print("\n" + "=" * 60)
    print(f"{'IP Address':<15} {'Port':<10} {'Service':<20}")
    print("=" * 60)
    for ip, port, service in all_open_ports:
        print(f"{str(ip):<15} {port:<10} {service:<20}")
    print("=" * 60)

def get_valid_input(prompt, validation_func, error_message):
    """Get valid input from the user with error handling."""
    while True:
        try:
            user_input = input(Fore.CYAN + prompt)
            return validation_func(user_input)
        except ValueError:
            print(Fore.RED + error_message)

def parse_port_range(port_range):
    """Parse the port range string into a list of ports to scan."""
    if '-' in port_range:
        start_port, end_port = map(int, port_range.split('-'))
        return range(start_port, min(end_port + 1, MAX_PORT + 1))
    elif ',' in port_range:
        return [int(port) for port in port_range.split(',') if 0 <= int(port) <= MAX_PORT]
    elif port_range.lower() == 'all':
        return range(1, MAX_PORT + 1)
    else:
        return [int(port_range)] if 0 <= int(port_range) <= MAX_PORT else []

def main():
    """Main function to run the port scanner."""
    print(Fore.MAGENTA + BANNER)

    # Get the starting IP address
    start_ip = get_valid_input(
        "Enter starting IP address (e.g., 192.168.0.0): ",
        ipaddress.IPv4Address,
        "Invalid IP address. Please try again."
    )

    # Get the number of /24 networks to scan
    num_networks = get_valid_input(
        "Enter number of /24 networks to scan: ",
        lambda x: int(x) if int(x) > 0 else ValueError(),
        "Please enter a valid positive integer."
    )

    # Get the port range to scan
    port_range = input(Fore.CYAN + f"Enter port range to scan (e.g., 1-65535, 80,443,8080, or 'all' for all ports): ")
    ports = parse_port_range(port_range)

    if not ports:
        print(Fore.RED + "Invalid port range. Exiting.")
        return

    start_time = time.time()
    all_open_ports = []

    # Scan each network
    for i in range(num_networks):
        current_network = ipaddress.IPv4Network(f"{start_ip}/{24}", strict=False)
        print(Fore.CYAN + f"\nScanning network: {current_network}")
        open_ports = scan_network(current_network, ports)
        all_open_ports.extend(open_ports)
        start_ip = str(current_network.broadcast_address + 1)

    # Print scan summary
    elapsed_time = time.time() - start_time
    print(Fore.CYAN + f"\nTotal scan completed in {elapsed_time:.2f} seconds")
    print(Fore.CYAN + f"Total open ports found: {len(all_open_ports)}")

    # Print and save results
    if all_open_ports:
        print_results(all_open_ports)
        with open("open_ports.txt", "w") as f:
            f.write(f"{'IP Address':<15} {'Port':<10} {'Service':<20}\n")
            f.write("=" * 60 + "\n")
            for ip, port, service in all_open_ports:
                f.write(f"{str(ip):<15} {port:<10} {service:<20}\n")
        print(Fore.GREEN + "Open ports saved to 'open_ports.txt'")
    else:
        print(Fore.YELLOW + "No open ports found")

if __name__ == "__main__":
    main()