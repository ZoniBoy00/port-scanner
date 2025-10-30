# Port Scanner

A high-performance Python-based tool for scanning networks and identifying open ports with advanced features including banner grabbing, multiple output formats, and CLI support.

## Features

- **Fast Concurrent Scanning**: Optimized multi-threaded scanning with configurable workers
- **Flexible Network Targeting**: Scan /24 networks or specific IP addresses with CIDR notation support
- **Customizable Port Ranges**: Scan specific ports, ranges, or use common port presets
- **Banner Grabbing**: Identify service versions and details (optional)
- **Multiple Output Formats**: Export results as TXT, JSON, or CSV
- **CLI Support**: Full command-line argument support for automation
- **Colorized Output**: Enhanced readability with color-coded results
- **Progress Tracking**: Real-time progress bar with scan statistics
- **Service Detection**: Automatic service name resolution for known ports

## Prerequisites

- Python 3.7 or higher
- pip (Python package installer)

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/ZoniBoy00/port-scanner.git
   ```

2. Navigate to the project directory:
   ```bash
   cd port-scanner
   ```

3. Install the required packages:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Interactive Mode

Run the script without arguments for interactive prompts:

```bash
python port_scanner.py
```

Follow the prompts to configure your scan.

### CLI Mode

Use command-line arguments for automated scanning:

```bash
# Basic scan
python port_scanner.py --start-ip 192.168.1.0 --networks 1 --ports 1-1000

# Scan common ports only
python port_scanner.py --start-ip 192.168.1.0 --networks 2 --ports common

# Scan with banner grabbing and JSON output
python port_scanner.py --start-ip 10.0.0.0 --networks 1 --ports 1-1000 --banner --output results.json --format json

# Verbose mode with CSV export
python port_scanner.py --start-ip 192.168.0.0 --networks 1 --ports 80,443,8080 --verbose --output scan.csv --format csv

# Fast scan with more workers
python port_scanner.py --start-ip 192.168.1.0 --networks 1 --ports common --workers 200 --timeout 0.2
```

### CLI Arguments

| Argument | Description | Example |
|----------|-------------|---------|
| `--start-ip` | Starting IP address | `192.168.1.0` |
| `--networks` | Number of /24 networks to scan | `1` |
| `--ports` | Port range (e.g., 1-1000, 80,443, common, all) | `1-1000` |
| `--output` | Output file path | `results.json` |
| `--format` | Output format (txt, json, csv) | `json` |
| `--workers` | Number of concurrent threads | `100` |
| `--timeout` | Socket timeout in seconds | `0.3` |
| `--banner` | Enable banner grabbing | (flag) |
| `--verbose` | Enable verbose output | (flag) |

## Examples

### Example 1: Quick Common Ports Scan

```bash
$ python port_scanner.py --start-ip 192.168.1.0 --networks 1 --ports common

 ____            _     ____                                  
|  _ \ ___  _ __| |_  / ___|  ___ __ _ _ __  _ __   ___ _ __ 
| |_) / _ \| '__| __| \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
|  __/ (_) | |  | |_   ___) | (_| (_| | | | | | | |  __/ |   
|_|   \___/|_|   \__| |____/ \___\__,_|_| |_|_| |_|\___|_|   

Scanning network: 192.168.1.0/24
Scanning common ports: 21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 5432, 8080, 8443
Scanning: 100%|████████████████████████| 3556/3556 [00:15<00:00, 235.73port/s]

Total scan completed in 15.08 seconds
Total open ports found: 5

============================================================
IP Address      Port       Service           
============================================================
192.168.1.1     80         http              
192.168.1.1     443        https             
192.168.1.100   22         ssh               
192.168.1.100   3306       mysql             
192.168.1.200   8080       http-proxy        
============================================================
Open ports saved to 'open_ports.txt'
```

### Example 2: Banner Grabbing with JSON Output

```bash
$ python port_scanner.py --start-ip 192.168.1.0 --networks 1 --ports 1-1000 --banner --output results.json --format json --verbose

Scanning network: 192.168.1.0/24
Banner grabbing enabled
Scanning: 100%|████████████████████████| 254000/254000 [01:45<00:00, 2410.52port/s]

[VERBOSE] 192.168.1.1:80 - http - Banner: HTTP/1.1 200 OK
[VERBOSE] 192.168.1.1:443 - https - Banner: (SSL/TLS connection)
[VERBOSE] 192.168.1.100:22 - ssh - Banner: SSH-2.0-OpenSSH_8.2p1

Total scan completed in 105.32 seconds
Total open ports found: 3

Results exported to 'results.json' in JSON format
```

### Example 3: CSV Export for Analysis

```bash
$ python port_scanner.py --start-ip 10.0.0.0 --networks 1 --ports 80,443,8080,8443 --output scan.csv --format csv

Scanning network: 10.0.0.0/24
Scanning: 100%|████████████████████████| 1016/1016 [00:03<00:00, 305.12port/s]

Total scan completed in 3.33 seconds
Total open ports found: 8

Results exported to 'scan.csv' in CSV format
```

## Configuration

You can adjust scanning behavior using CLI arguments or by modifying these defaults in the script:

- `MAX_WORKERS`: Number of concurrent threads (default: 100)
- `TIMEOUT`: Socket timeout in seconds (default: 0.3)
- `MAX_PORT`: Maximum port number (default: 65535)
- `COMMON_PORTS`: Preset list of commonly used ports

## Output Formats

### Text Format (Default)
Human-readable table format with color-coded output, saved to `open_ports.txt` by default.

### JSON Format
Structured JSON with detailed information:
```json
{
  "scan_info": {
    "start_time": "2025-01-15 10:30:00",
    "end_time": "2025-01-15 10:32:15",
    "duration": 135.42,
    "networks_scanned": ["192.168.1.0/24"],
    "total_open_ports": 3
  },
  "results": [
    {
      "ip": "192.168.1.1",
      "port": 80,
      "service": "http",
      "banner": "HTTP/1.1 200 OK"
    }
  ]
}
```

### CSV Format
Spreadsheet-compatible format for data analysis:
```csv
IP Address,Port,Service,Banner
192.168.1.1,80,http,HTTP/1.1 200 OK
192.168.1.1,443,https,(SSL/TLS connection)
```

## Performance Tips

- **Increase workers** for faster scans on powerful machines: `--workers 200`
- **Reduce timeout** for faster scans on local networks: `--timeout 0.2`
- **Use common ports** for quick reconnaissance: `--ports common`
- **Disable banner grabbing** for maximum speed (enabled with `--banner` flag)

## Troubleshooting

### Too Many Open Files Error
Reduce the number of workers:
```bash
python port_scanner.py --start-ip 192.168.1.0 --networks 1 --ports 1-1000 --workers 50
```

### Slow Scanning
Increase workers and reduce timeout for local networks:
```bash
python port_scanner.py --start-ip 192.168.1.0 --networks 1 --ports 1-1000 --workers 200 --timeout 0.2
```

### Permission Denied
Some systems require elevated privileges for network scanning:
```bash
sudo python port_scanner.py --start-ip 192.168.1.0 --networks 1 --ports 1-1000
```

## Legal Notice

This tool is intended for authorized security testing and network administration only. Unauthorized port scanning may be illegal in your jurisdiction. Always obtain proper authorization before scanning networks you do not own or have explicit permission to test.

## Contributing

Contributions are welcome! Feel free to submit issues or pull requests for:
- Bug fixes
- Performance improvements
- New features
- Documentation updates

## License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/ZoniBoy00/port-scanner/blob/main/LICENSE) file for details.
