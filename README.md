
# Port Scanner

A Python-based tool for scanning networks and identifying open ports with a user-friendly interface and concurrent scanning capabilities.

## Features

- Scan multiple /24 networks
- Customizable port ranges
- Concurrent scanning for faster results
- Colorized output for better readability
- Progress bar to track scanning progress
- Results saved to a text file

## Prerequisites

- Python 3.6 or higher
- pip (Python package installer)

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/ZoniBoy00/port-scanner.git
   ```

2. Navigate to the project directory:
   ```
   cd port-scanner
   ```

3. Install the required packages:
   ```
   pip install -r requirements.txt
   ```

## Usage

1. Open a terminal or command prompt.
2. Navigate to the project directory.
3. Run the script:
   ```
   python port_scanner.py
   ```
4. Follow the prompts:
   - Enter the starting IP address (e.g., 192.168.0.0)
   - Enter the number of /24 networks to scan
   - Enter the port range to scan (e.g., 1-1000, 80,443,8080, or 'all' for all ports)
5. The script will display a progress bar during the scan.
6. After the scan completes, results will be displayed in the terminal and saved to `open_ports.txt` in the current directory.

## Example

```
$ python port_scanner.py

 ____            _     ____                                  
|  _ \ ___  _ __| |_  / ___|  ___ __ _ _ __  _ __   ___ _ __ 
| |_) / _ \| '__| __| \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
|  __/ (_) | |  | |_   ___) | (_| (_| | | | | | | |  __/ |   
|_|   \___/|_|   \__| |____/ \___\__,_|_| |_|_| |_|\___|_|   

Enter starting IP address (e.g., 192.168.0.0): 192.168.1.0
Enter number of /24 networks to scan: 1
Enter port range to scan (e.g., 1-65535, 80,443,8080, or 'all' for all ports): 1-1000

Scanning network: 192.168.1.0/24
Scanning: 100%|██████████████████████████████| 254000/254000 [02:06<00:00, 2010.32port/s]

Total scan completed in 126.35 seconds
Total open ports found: 3

============================================================
IP Address      Port       Service           
============================================================
192.168.1.1     80         http              
192.168.1.1     443        https             
192.168.1.100   22         ssh               
============================================================
Open ports saved to 'open_ports.txt'
```

## Configuration

You can modify the following constants in the script to adjust the scanning behavior:

- `MAX_WORKERS`: Number of concurrent threads (default: 50)
- `SCAN_DELAY`: Delay between port scans in seconds (default: 0.1)
- `MAX_PORT`: Maximum port number to scan (default: 65535)

## Troubleshooting

If you encounter buffer overflow errors on Windows, try reducing `MAX_WORKERS` or increasing `SCAN_DELAY` in the script.

## Contributing

Feel free to submit issues or pull requests if you have any improvements or bug fixes to suggest.

## License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/ZoniBoy00/port-scanner/blob/main/LICENSE) file for details.
