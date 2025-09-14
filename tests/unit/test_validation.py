"""Test basic input validation"""
import pytest
from ktscan.validation import validate_url_basic, validate_port_list, validate_basic_params, ValidationError


class TestURLValidation:
    def test_valid_urls(self):
        """Test that valid URLs work"""
        cases = [
            ("https://example.com", "https://example.com", "example.com", 443),
            ("http://test.org:8080", "http://test.org:8080", "test.org", 8080),
            ("google.com", "https://google.com", "google.com", 443),  # Auto-add https
            ("192.168.1.1:443", "https://192.168.1.1:443", "192.168.1.1", 443),
            ("localhost:8443", "https://localhost:8443", "localhost", 8443),
        ]
        
        for input_url, expected_url, expected_host, expected_port in cases:
            url, host, port = validate_url_basic(input_url)
            assert url == expected_url
            assert host == expected_host
            assert port == expected_port

    def test_invalid_urls(self):
        """Test that invalid URLs give helpful errors"""
        cases = [
            ("", "URL cannot be empty"),
            ("   ", "URL cannot be empty"), 
            ("ftp://example.com", "Only http and https URLs supported"),
            ("https://", "URL missing hostname"),
            ("https://example.com:99999", "Port out of valid range"),
            ("https://example.com:0", "Port 0 out of valid range"),
            ("https://192.168.1.4000", "Invalid hostname or IP address"),  # Octet > 255
            ("https://192.168.1", "Invalid hostname or IP address"),       # Incomplete IP
            ("https://256.1.1.1", "Invalid hostname or IP address"),       # Invalid octet
            ("https://192.168.1.1.1", "Invalid hostname or IP address"),   # Too many octets
        ]
        
        for invalid_url, expected_error in cases:
            with pytest.raises(ValidationError) as exc_info:
                validate_url_basic(invalid_url)
            assert expected_error in str(exc_info.value)

    def test_url_cleaning(self):
        """Test that URLs get cleaned/normalized"""
        # Test whitespace removal
        url, host, port = validate_url_basic("  example.com  ")
        assert url == "https://example.com"
        assert host == "example.com"
        assert port == 443

    def test_default_ports(self):
        """Test default port assignment"""
        # HTTPS default
        url, host, port = validate_url_basic("https://example.com")
        assert port == 443
        
        # HTTP default
        url, host, port = validate_url_basic("http://example.com")
        assert port == 80


class TestPortValidation:
    def test_valid_ports(self):
        """Test valid port lists"""
        validate_port_list([443])  # Should not raise
        validate_port_list([80, 443, 8080])  # Should not raise
        validate_port_list([1, 65535])  # Edge cases

    def test_invalid_ports(self):
        """Test invalid port lists"""
        with pytest.raises(ValidationError, match="At least one port required"):
            validate_port_list([])
        
        with pytest.raises(ValidationError, match="Invalid port"):
            validate_port_list([0])
        
        with pytest.raises(ValidationError, match="Invalid port"):
            validate_port_list([65536])
        
        with pytest.raises(ValidationError, match="Invalid port"):
            validate_port_list(["443"])  # String instead of int


class TestBasicParams:
    def test_valid_params(self):
        """Test valid thread/timeout combinations"""
        validate_basic_params(1, 1)  # Should not raise
        validate_basic_params(10, 30)  # Should not raise
        validate_basic_params(100, 300)  # Edge cases

    def test_invalid_threads(self):
        """Test invalid thread counts"""
        with pytest.raises(ValidationError, match="Thread count must be positive"):
            validate_basic_params(0, 10)
        
        with pytest.raises(ValidationError, match="Thread count must be positive"):
            validate_basic_params(-1, 10)
        
        with pytest.raises(ValidationError, match="Thread count too high"):
            validate_basic_params(101, 10)

    def test_invalid_timeouts(self):
        """Test invalid timeout values"""
        with pytest.raises(ValidationError, match="Timeout must be positive"):
            validate_basic_params(10, 0)
        
        with pytest.raises(ValidationError, match="Timeout must be positive"):
            validate_basic_params(10, -1)
        
        with pytest.raises(ValidationError, match="Timeout too high"):
            validate_basic_params(10, 301)