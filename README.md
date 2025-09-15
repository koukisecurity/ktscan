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

KTScan uses a command-based CLI structure. All commands require you to specify the command first:

```bash
ktscan <command> [options]
```

### Available Commands

#### Scan SSL/TLS certificates
```bash
ktscan scan --url <URL> [options]
ktscan scan --config <config-file> [options]
```

**Options:**
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
--help, -h         Show help message
```

#### Generate sample configuration file
```bash
ktscan init-config <config-file>
```
Creates a sample YAML configuration file with all available options and comments.

#### Retrieve information about available checks and standards
```bash
ktscan get categories         # List all check categories
ktscan get standards          # List all available standards
ktscan get profiles           # List all validation profiles
ktscan get checks             # List all available checks
ktscan get checks --category <category>   # List checks for specific category
ktscan get checks --standard <standard>   # List checks for specific standard
ktscan get checks --profile <profile>     # List checks for specific profile
```

#### Get detailed information about checks
```bash
ktscan describe category <category-id>        # Describe a check category
ktscan describe check <category>:<check-id>   # Describe a specific check
```

**Examples:**
```bash
# Describe the cryptography category
ktscan describe category crypto

# Describe a specific check
ktscan describe check crypto:weak_signature_algorithm
```

### Global Options
```
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

## Examples

### Output Formats
```bash
# Brief output (default) - focused security findings
ktscan scan --url https://example.com --output-format brief

# Table output - detailed tabular view
ktscan scan --url https://example.com --output-format table

# JSON output - machine readable
ktscan scan --url https://example.com --output-format json

# CSV output - spreadsheet compatible
ktscan scan --url https://example.com --output-format csv
```

### Advanced Options
```bash
# Use specific validation profile
ktscan scan --url https://example.com --profile NIST_ONLY

# Filter by severity level
ktscan scan --url https://example.com --severity HIGH

# Use specific standards only
ktscan scan --url https://example.com --standard NIST_800-52r2 --standard RFC5280

# Verbose output with detailed information
ktscan scan --url https://example.com --verbose
```

### Docker Examples
```bash
# Basic Docker scan
docker run --rm ktscan scan --url https://example.com

# Save output to file
docker run --rm -v $(pwd):/output ktscan scan --url https://example.com --output-format json > results.json

# Use custom configuration
docker run --rm -v $(pwd)/config:/config ktscan scan --config /config/my-config.yaml

# Generate config file in Docker
docker run --rm -v $(pwd):/output ktscan init-config /output/my-config.yaml
```

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
Focused human-readable output format showing only findings with minimal extraneous information.

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
    command: scan --url https://example.com --output-format json
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
