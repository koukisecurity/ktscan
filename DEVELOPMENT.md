# KTScan Development Guide

## Development Setup

### Prerequisites
- Python 3.10 or higher
- pip package manager

### Installation Options

#### Production Installation
For end users who just want to use KTScan:
```bash
pip install ktscan
```

#### Development Installation
For contributors and developers:
```bash
# Clone the repository
git clone https://github.com/koukisecurity/ktscan.git
cd ktscan

# Install in development mode with test dependencies
pip install -e ".[test]"

# Or install development dependencies manually
pip install -r requirements-dev.txt
```

#### Alternative Development Setup
Using the included Makefile:
```bash
make install-dev    # Install development dependencies
make dev-setup     # Install dev deps + pre-commit hooks
```

## Testing

### Running Tests
```bash
# Run all tests
make test
# or
pytest tests/

# Run check tests only (our comprehensive test suite)
make test-validators
# or  
pytest tests/unit/checks/

# Run tests with coverage
make test-cov
# or
pytest tests/ --cov=ktscan --cov-report=html --cov-report=term-missing

# Quick test run (minimal output)
make test-quick
```

### Test Structure
```
tests/
├── conftest.py              # Pytest fixtures and configuration
├── certificates/
│   └── factory.py          # Test certificate generation
└── unit/
    └── validators/         # Validator test suites (214 tests)
        ├── test_base.py        # BaseValidator tests
        ├── test_chain.py       # ChainValidator tests  
        ├── test_compliance.py  # ComplianceValidator tests
        ├── test_cryptography.py # CryptographyValidator tests
        ├── test_hostname.py    # HostnameValidator tests
        ├── test_lifecycle.py   # LifecycleValidator tests
        └── test_usage.py       # UsageValidator tests
```

## Code Quality

### Formatting and Linting
```bash
# Format code
make format
# or
black ktscan/ tests/

# Lint code
make lint
# or
flake8 ktscan/
mypy ktscan/
```

### Pre-commit Hooks
Install pre-commit hooks to automatically format and check code:
```bash
pre-commit install
```

## Build and Distribution

### Building Packages
```bash
make build
# or
python setup.py sdist bdist_wheel
```

### Clean Build Artifacts
```bash
make clean
```

## Project Structure

### Key Components
- `ktscan/validators/`: Certificate validation modules
- `ktscan/scanners/`: Certificate discovery and scanning
- `ktscan/collectors/`: Certificate collection from various sources
- `ktscan/utils/`: Utility functions and helpers
- `tests/`: Comprehensive test suite

### Configuration
- `pytest.ini`: Pytest configuration with coverage settings
- `setup.py`: Package configuration with proper dependency separation
- `requirements*.txt`: Dependency management
- `Makefile`: Development task automation
- `MANIFEST.in`: Package distribution file inclusion

## Contributing

1. Fork the repository
2. Install development dependencies: `make install-dev`
3. Create a feature branch
4. Write tests for new functionality
5. Ensure all tests pass: `make test`
6. Format code: `make format` 
7. Submit a pull request

## Testing Philosophy

The KTScan project follows a comprehensive testing approach:

- **Unit Testing**: Each validator has extensive unit tests covering all functionality
- **Mock Testing**: Sophisticated mocking strategies for immutable cryptography objects
- **Edge Case Coverage**: Tests for invalid certificates, network errors, and edge cases
- **Standards Compliance**: Tests for NIST, CA/Browser Forum, and RFC 5280 compliance
- **Time-Based Testing**: Certificate validity period testing with time mocking
- **Network Simulation**: OCSP/CRL endpoint testing with HTTP mocking

This ensures high confidence in the reliability and correctness of certificate validation logic.