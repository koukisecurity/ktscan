# KTScan

A multi-threaded Python CLI tool for scanning SSL/TLS certificates across multiple IPs and ports for a given URL.

> **⚠️ Development Status Notice**
> KTScan is currently under active development. APIs, command-line interfaces, and configuration formats may change between versions. While the tool is functional and tested, please expect potential breaking changes in future releases. We recommend pinning to specific versions in production environments and reviewing release notes before upgrading.

## Features

- **Multi-threaded scanning** using ThreadPoolExecutor
- **DNS resolution** to enumerate all target IPs 
- **Port connectivity checking** before certificate scanning
- **Advanced certificate security validation** with 100+ security checks
- **NIST SP 800-57 compliance** validation for cryptographic standards  
- **Configurable validation profiles** (SERVER_DEFAULT, CABF_ONLY, NIST_ONLY, MINIMAL)
- **Security scoring** with 0-100 point scale for certificate assessment
- **Multiple output formats** (brief, table, JSON, CSV, NDJSON) with detailed findings
- **Flexible configuration** via CLI arguments or YAML files
- **Rich terminal output** with security findings and remediation guidance

## Installation

### Local Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Or install in development mode
pip install -e .
```

### Docker Installation

#### Option 1: Build from Source

```bash
# Clone the repository
git clone https://github.com/koukisecurity/ktscan.git
cd ktscan

# Build the Docker image
docker build -t ktscan .

# Run the scanner
docker run --rm ktscan scan --url https://example.com
```

#### Option 2: Pre-built Image (when available)

```bash
# Pull and run the pre-built image
docker pull koukisecurity/ktscan
docker run --rm koukisecurity/ktscan scan --url https://example.com
```

## Quick Start

### Local Execution

```bash
# Basic scan
python -m ktscan.cli scan --url https://example.com

# Scan multiple ports with custom thread count
python -m ktscan.cli scan --url example.com --ports 443,8443,9443 --threads 20

# Output as JSON
python -m ktscan.cli scan --url https://example.com --output-format json

# Brief output format (focused findings)
python -m ktscan.cli scan --url https://example.com --output-format brief

# Use configuration file
python -m ktscan.cli scan --config config/default.yaml

# Generate sample config
python -m ktscan.cli init-config my-config.yaml
```

### Docker Execution

```bash
# Basic scan with Docker
docker run --rm ktscan scan --url https://example.com

# Scan multiple ports
docker run --rm ktscan scan --url example.com --ports 443,8443,9443 --threads 20

# Output as JSON
docker run --rm ktscan scan --url https://example.com --output-format json

# Brief output format
docker run --rm ktscan scan --url https://example.com --output-format brief

# Save output to file (mount current directory)
docker run --rm -v $(pwd):/output ktscan scan --url https://example.com --output-format json > /output/results.json

# Use custom configuration (mount config directory)
docker run --rm -v $(pwd)/config:/config ktscan --config /config/my-config.yaml

# Scan with verbose output
docker run --rm ktscan scan --url https://example.com --verbose
```

## Usage

### Command Line Options

```
--url, -u          Target URL to scan (can be used multiple times)
--config, -c       Path to YAML config file
--threads, -t      Number of threads (default: system default)
--ports, -p        Comma-separated ports (default: 443)
--timeout          Connection timeout in seconds (default: 10)
--output-format, -o Output format: brief, table, json, csv, ndjson (default: brief)
--verbose, -v      Enable verbose logging
--profile, -P      Validation profile (e.g., SERVER_DEFAULT, CABF_ONLY, NIST_ONLY)
--standard, -s     Specific standards to include (can be used multiple times)
--severity         Minimum severity to show: CRITICAL, HIGH, MEDIUM, LOW, INFO (default: MEDIUM)
--no-color         Disable color in output text
--version          Show version information
--help, -h         Show help message
```

### Configuration File

Create a YAML configuration file:

```yaml
# Basic configuration
urls:
  - "https://example.com"
  - "https://google.com"

ports: 
  - 443
  - 8443

# Optional settings
timeout: 10
output_format: "brief"  # brief, table, json, csv, ndjson
verbose: false

# Advanced validation settings
validation:
  profile: "SERVER_DEFAULT"  # SERVER_DEFAULT, CABF_ONLY, NIST_ONLY, MINIMAL
  severity_filter: "MEDIUM"  # CRITICAL, HIGH, MEDIUM, LOW, INFO
```

For a complete example with all available options, see [config/default.yaml](config/default.yaml).

## Architecture

The tool is organized into modular components:

- **`cli.py`** - Click-based command line interface
- **`config.py`** - Configuration management (CLI + YAML)
- **`network.py`** - DNS resolution and port connectivity
- **`cert_analyzer.py`** - SSL certificate retrieval and analysis
- **`threading_manager.py`** - Thread pool management with progress tracking
- **`scanner.py`** - Main orchestration logic
- **`output.py`** - Result formatting (table, JSON, CSV, NDJSON)

## Certificate Analysis

The tool analyzes certificates and provides:

- **Basic Information**: Subject, Issuer, Serial Number, Signature Algorithm
- **Validity**: Not Before/After dates, expiration warnings
- **Key Details**: Public key size and algorithm
- **Extensions**: Subject Alternative Names (SAN)
- **Validation**: Hostname matching, certificate chain validation
- **Security Checks**: Key strength, expiration status

## Output Formats

### Brief Format (Default)
Focused output showing only findings with minimal extraneous information. Features:
- Human-readable scan completion time
- Shows profiles/standards used during scan  
- Groups findings by target with ports and endpoint counts
- Clean table format using Rich library
- Respects severity filtering

### Table Format
Rich terminal table with color-coded status indicators and summary statistics.

### JSON Format
Machine-readable structured data with all certificate details.

### CSV Format  
Spreadsheet-compatible format for data analysis.

### NDJSON Format
Newline-delimited JSON with one certificate per line, ideal for streaming processing and log analysis. Each line contains the complete certificate data and all findings without metadata wrapper.


## Error Handling

The tool gracefully handles:
- DNS resolution failures
- Closed ports and connection timeouts
- SSL/TLS handshake errors
- Invalid certificates
- Network connectivity issues

## Security Notes

This tool is designed for **defensive security purposes only**:
- Certificate monitoring and compliance checking
- SSL/TLS configuration validation
- Security assessment of owned infrastructure
- Certificate expiration monitoring

## Docker Notes

The Docker image includes:
- **Multi-stage build** for optimized image size
- **Non-root user** for security
- **Health checks** for container monitoring
- **CA certificates** for SSL/TLS validation
- **Python 3.12** runtime environment

### Docker Compose (Optional)

Create a `docker-compose.yml` for easier management:

```yaml
version: '3.8'
services:
  ktscan:
    build: .
    # or use: image: koukisecurity/ktscan
    volumes:
      - ./config:/config
      - ./output:/output
    command: --url https://example.com --output-format json
```

Run with: `docker-compose run ktscan`

## Requirements

- Python 3.8+
- Docker (for containerized deployment)
- See `requirements.txt` for all dependencies

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Contributing

We welcome contributions! Please read our [Contributing Guidelines](CONTRIBUTING.md) and sign our Contributor License Agreement (CLA) before submitting pull requests.

[![CLA assistant](https://cla-assistant.io/readme/badge/koukisecurity/CertScanner)](https://cla-assistant.io/koukisecurity/CertScanner)
