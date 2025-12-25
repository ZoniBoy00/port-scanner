# Modern Port Scanner

A feature-rich and modern port scanner with a beautiful and user-friendly command-line interface powered by the [Rich](https://github.com/Textualize/rich) library. This tool allows for fast and efficient network scanning to identify open ports, with advanced features like banner grabbing and multiple output formats.


## Features

- **Rich & Modern CLI**: A visually appealing and easy-to-use interface built with `rich`.
- **Fast Concurrent Scanning**: Utilizes multi-threading for high-performance scanning.
- **Flexible Targeting**: Scan single IPs, hostnames, or entire CIDR networks.
- **Customizable Port Selection**: Scan specific ports, ranges (e.g., `1-1000`), or predefined lists (`common`, `all`).
- **Banner Grabbing**: Identify service versions running on open ports.
- **Multiple Output Formats**: Save scan results as TXT, JSON, or CSV.
- **Interactive & CLI Modes**: Run with interactive prompts for guided scanning or use command-line arguments for automation.
- **Progress Tracking**: A real-time progress bar shows scan statistics and estimated time remaining.

## Prerequisites

- Python 3.7 or higher
- pip (Python package installer)

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/ZoniBoy00/port-scanner.git
    cd port-scanner
    ```

2.  **Install the required packages:**
    ```bash
    pip install -r requirements.txt
    ```

## Usage

The scanner can be run in two modes: interactive or command-line.

### Interactive Mode

For a user-friendly, guided experience, run the script without any arguments:

```bash
python main.py
```

The application will prompt you for the targets, ports, and other scanning options.


### Command-Line Mode

For automation and scripting, you can provide all options as command-line arguments.

#### Basic Examples:

-   **Scan common ports on a single IP:**
    ```bash
    python main.py -t 192.168.1.1 -p common
    ```

-   **Scan a range of ports on a CIDR network:**
    ```bash
    python main.py -t 192.168.1.0/24 -p 1-1024
    ```

-   **Scan multiple targets with banner grabbing and save to a JSON file:**
    ```bash
    python main.py -t 192.168.1.1,example.com -p 80,443,8080 -b -o scan_results.json
    ```

### CLI Arguments

| Short | Long | Description | Default |
| :--- | :--- | :--- | :--- |
| `-t` | `--target` | Target IP(s), hostname(s), or CIDR network(s) (comma-separated). | (none) |
| `-p` | `--ports` | Ports to scan (e.g., `80,443`, `1-1000`, `common`, `all`). | (none) |
| `-o` | `--output` | Save results to an output file. Format is inferred from the extension (`.txt`, `.json`, `.csv`). | (none) |
| `-w` | `--workers` | Number of concurrent scanning threads. | `100` |
| `-b` | `--banner` | Enable banner grabbing to identify service versions. | `False` |
| `-v` | `--verbose` | Enable verbose output (shows open ports as they are found). | `False` |
| | `--timeout` | Timeout for each port connection in seconds. | `0.3` |
| | `--no-progress`| Disable the live progress bar. | `False` |


## Performance Tips

-   For faster scans on a reliable network, you can use more workers and a lower timeout:
    ```bash
    python main.py -t 192.168.1.0/24 -p 1-1000 -w 200 --timeout 0.2
    ```
-   For quick reconnaissance, scan only the common ports:
    ```bash
    python main.py -t 192.168.1.0/24 -p common
    ```
-   Banner grabbing (`-b`) adds a small delay for each open port. Disable it if you only need to know which ports are open.

## Legal Notice

This tool is intended for educational purposes and authorized security testing only. Unauthorized scanning of networks is illegal. Always obtain permission from the network owner before scanning.

## Contributing

Contributions are welcome! If you have ideas for improvements or find a bug, please open an issue or submit a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.