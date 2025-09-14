"""
Pytest configuration and shared fixtures for KTScan tests.
"""

from datetime import datetime

import pytest
from freezegun import freeze_time

from ktscan.config import ScanConfig
from tests.certificates.factory import TestCertificateFactory


@pytest.fixture
def mock_time():
    """Freeze time for consistent testing at 2024-01-15 12:00:00 UTC"""
    with freeze_time("2024-01-15 12:00:00"):
        yield datetime(2024, 1, 15, 12, 0, 0)


@pytest.fixture
def cert_factory():
    """Certificate factory for generating test certificates"""
    return TestCertificateFactory()


@pytest.fixture
def basic_config():
    """Basic scan configuration for testing"""
    return ScanConfig(urls=["https://example.com"], validation={"profile": "balanced"})


@pytest.fixture
def strict_config():
    """Strict validation configuration"""
    return ScanConfig(urls=["https://example.com"], validation={"profile": "strict"})


@pytest.fixture
def minimal_config():
    """Minimal validation configuration"""
    return ScanConfig(urls=["https://example.com"], validation={"profile": "MINIMAL"})


@pytest.fixture
def validation_context():
    """Standard validation context for testing"""
    return {"hostname": "example.com", "ip": "192.0.2.1", "port": 443}


# Test data fixtures
@pytest.fixture
def sample_hostnames():
    """Sample hostnames for testing"""
    return [
        "example.com",
        "www.example.com",
        "api.example.com",
        "mail.example.org",
        "*.example.com",
        "xn--fsq.example.com",  # IDN domain
    ]


@pytest.fixture
def sample_ips():
    """Sample IP addresses for testing"""
    return ["192.0.2.1", "198.51.100.1", "203.0.113.1", "2001:db8::1", "::1"]
