"""
Tests for ktscan.scan_target module
"""

import pytest
from ktscan.scan_target import ScanTarget, resolve_scan_targets


class TestScanTarget:
    """Test the ScanTarget class"""

    def test_init_basic(self):
        """Test basic ScanTarget initialization"""
        target = ScanTarget(
            original_url="https://example.com",
            hostname="example.com", 
            ports=[443, 8443]
        )
        
        assert target.original_url == "https://example.com"
        assert target.hostname == "example.com"
        assert target.ports == [443, 8443]

    def test_str_representation(self):
        """Test string representation"""
        target = ScanTarget(
            original_url="https://example.com",
            hostname="example.com",
            ports=[443, 8443]
        )
        
        assert str(target) == "example.com:443,8443"

    def test_str_single_port(self):
        """Test string representation with single port"""
        target = ScanTarget(
            original_url="https://example.com",
            hostname="example.com",
            ports=[443]
        )
        
        assert str(target) == "example.com:443"

    def test_str_no_ports(self):
        """Test string representation with no ports"""
        target = ScanTarget(
            original_url="https://example.com",
            hostname="example.com", 
            ports=[]
        )
        
        assert str(target) == "example.com:"

    def test_from_url_spec_basic_https(self):
        """Test parsing basic HTTPS URL with global ports"""
        target = ScanTarget.from_url_spec("https://example.com", [443, 8443])
        
        assert target.original_url == "https://example.com"
        assert target.hostname == "example.com"
        assert target.ports == [443, 8443]

    def test_from_url_spec_basic_http(self):
        """Test parsing basic HTTP URL with global ports"""
        target = ScanTarget.from_url_spec("http://example.com", [80, 8080])
        
        assert target.original_url == "http://example.com"
        assert target.hostname == "example.com"
        assert target.ports == [80, 8080]

    def test_from_url_spec_no_schema(self):
        """Test parsing URL without schema"""
        target = ScanTarget.from_url_spec("example.com", [443])
        
        assert target.original_url == "example.com"
        assert target.hostname == "example.com" 
        assert target.ports == [443]

    def test_from_url_spec_with_single_port(self):
        """Test parsing URL with single port specification"""
        target = ScanTarget.from_url_spec("https://example.com:8080", [443])
        
        assert target.original_url == "https://example.com:8080"
        assert target.hostname == "example.com"
        assert target.ports == [8080]  # Should override global ports

    def test_from_url_spec_with_multiple_ports(self):
        """Test parsing URL with multiple port specification"""
        target = ScanTarget.from_url_spec("https://example.com:443,8443,9000")
        
        assert target.original_url == "https://example.com:443,8443,9000"
        assert target.hostname == "example.com"
        assert target.ports == [443, 8443, 9000]

    def test_from_url_spec_ports_with_spaces(self):
        """Test parsing URL with ports containing spaces"""
        target = ScanTarget.from_url_spec("https://example.com:443, 8443 , 9000")
        
        assert target.original_url == "https://example.com:443, 8443 , 9000"
        assert target.hostname == "example.com"
        assert target.ports == [443, 8443, 9000]

    def test_from_url_spec_no_global_ports(self):
        """Test parsing URL without global ports (should result in empty ports)"""
        target = ScanTarget.from_url_spec("https://example.com")
        
        assert target.original_url == "https://example.com"
        assert target.hostname == "example.com"
        assert target.ports == []

    def test_from_url_spec_subdomain(self):
        """Test parsing URL with subdomain"""
        target = ScanTarget.from_url_spec("https://api.example.com", [443])
        
        assert target.original_url == "https://api.example.com"
        assert target.hostname == "api.example.com"
        assert target.ports == [443]

    def test_from_url_spec_with_path(self):
        """Test parsing URL with path (path should be ignored for hostname extraction)"""
        target = ScanTarget.from_url_spec("https://example.com/path/to/resource", [443])
        
        assert target.original_url == "https://example.com/path/to/resource"
        assert target.hostname == "example.com"
        assert target.ports == [443]

    def test_from_url_spec_with_query_params(self):
        """Test parsing URL with query parameters"""
        target = ScanTarget.from_url_spec("https://example.com?param=value", [443])
        
        assert target.original_url == "https://example.com?param=value"
        assert target.hostname == "example.com"
        assert target.ports == [443]

    def test_from_url_spec_ip_address(self):
        """Test parsing URL with IP address"""
        target = ScanTarget.from_url_spec("https://192.168.1.1:8080", [443])
        
        assert target.original_url == "https://192.168.1.1:8080"
        assert target.hostname == "192.168.1.1"
        assert target.ports == [8080]

    def test_from_url_spec_ipv6_address(self):
        """Test parsing URL with IPv6 address"""
        target = ScanTarget.from_url_spec("https://[2001:db8::1]:8080", [443])
        
        assert target.original_url == "https://[2001:db8::1]:8080"
        assert target.hostname == "2001:db8::1"
        assert target.ports == [8080]

    def test_extract_hostname_https(self):
        """Test hostname extraction from HTTPS URL"""
        hostname = ScanTarget._extract_hostname("https://example.com")
        assert hostname == "example.com"

    def test_extract_hostname_http(self):
        """Test hostname extraction from HTTP URL"""
        hostname = ScanTarget._extract_hostname("http://example.com")
        assert hostname == "example.com"

    def test_extract_hostname_no_schema(self):
        """Test hostname extraction from URL without schema"""
        hostname = ScanTarget._extract_hostname("example.com")
        assert hostname == "example.com"

    def test_extract_hostname_with_port(self):
        """Test hostname extraction from URL with port"""
        hostname = ScanTarget._extract_hostname("https://example.com:8080")
        assert hostname == "example.com"

    def test_extract_hostname_with_path(self):
        """Test hostname extraction from URL with path"""
        hostname = ScanTarget._extract_hostname("https://example.com/path")
        assert hostname == "example.com"

    def test_extract_hostname_ip_address(self):
        """Test hostname extraction from IP address URL"""
        hostname = ScanTarget._extract_hostname("https://192.168.1.1")
        assert hostname == "192.168.1.1"

    def test_extract_hostname_ipv6_address(self):
        """Test hostname extraction from IPv6 address URL"""
        hostname = ScanTarget._extract_hostname("https://[2001:db8::1]")
        assert hostname == "2001:db8::1"

    def test_extract_hostname_invalid_empty(self):
        """Test hostname extraction from empty URL"""
        with pytest.raises(ValueError, match="Cannot extract hostname"):
            ScanTarget._extract_hostname("")

    def test_extract_hostname_invalid_schema_only(self):
        """Test hostname extraction from schema-only URL"""
        with pytest.raises(ValueError, match="Cannot extract hostname"):
            ScanTarget._extract_hostname("https://")

    def test_from_url_spec_port_parsing_errors(self):
        """Test error handling in port parsing"""
        # Invalid port numbers should be caught at the int() conversion
        with pytest.raises(ValueError):
            ScanTarget.from_url_spec("https://example.com:invalid")
            
        with pytest.raises(ValueError):
            ScanTarget.from_url_spec("https://example.com:443,invalid,8443")

    def test_from_url_spec_hostname_extraction_error(self):
        """Test error handling when hostname extraction fails"""
        # This should trigger the hostname extraction error
        with pytest.raises(ValueError, match="Cannot extract hostname"):
            ScanTarget.from_url_spec("https://")

    def test_from_url_spec_complex_cases(self):
        """Test complex URL parsing cases"""
        # URL with authentication info
        target = ScanTarget.from_url_spec("https://user:pass@example.com", [443])
        assert target.hostname == "example.com"
        
        # URL with port in standard position but with path
        target = ScanTarget.from_url_spec("https://example.com:8080/api/v1", [443])
        assert target.hostname == "example.com"
        assert target.ports == [8080]

    def test_port_pattern_matching(self):
        """Test various port pattern matching scenarios"""
        # Test port at end of URL
        target = ScanTarget.from_url_spec("example.com:443")
        assert target.ports == [443]
        
        # Test multiple ports at end
        target = ScanTarget.from_url_spec("example.com:443,8443")
        assert target.ports == [443, 8443]
        
        # Test that ports in middle of URL (with path) don't match the pattern
        target = ScanTarget.from_url_spec("https://example.com:8080/path", [443])
        assert target.ports == [8080]  # Port in URL should still be extracted


class TestResolveScanTargets:
    """Test the resolve_scan_targets function"""

    def test_resolve_single_target(self):
        """Test resolving single target"""
        targets = resolve_scan_targets(["https://example.com"], [443])
        
        assert len(targets) == 1
        assert targets[0].hostname == "example.com"
        assert targets[0].ports == [443]
        assert targets[0].original_url == "https://example.com"

    def test_resolve_multiple_targets(self):
        """Test resolving multiple targets"""
        urls = ["https://example.com", "https://google.com", "api.test.com:8080"]
        targets = resolve_scan_targets(urls, [443, 8443])
        
        assert len(targets) == 3
        
        # First target uses global ports
        assert targets[0].hostname == "example.com"
        assert targets[0].ports == [443, 8443]
        
        # Second target uses global ports  
        assert targets[1].hostname == "google.com"
        assert targets[1].ports == [443, 8443]
        
        # Third target has specific port
        assert targets[2].hostname == "api.test.com"
        assert targets[2].ports == [8080]

    def test_resolve_mixed_port_specifications(self):
        """Test resolving targets with mixed port specifications"""
        urls = [
            "https://example.com",  # Uses global ports
            "https://api.example.com:8080",  # Specific single port
            "test.example.com:443,8443,9000",  # Multiple specific ports
            "http://old.example.com"  # Uses global ports
        ]
        
        targets = resolve_scan_targets(urls, [443])
        
        assert len(targets) == 4
        assert targets[0].ports == [443]  # Global
        assert targets[1].ports == [8080]  # Specific
        assert targets[2].ports == [443, 8443, 9000]  # Multiple
        assert targets[3].ports == [443]  # Global

    def test_resolve_no_global_ports_with_port_specs(self):
        """Test resolving when no global ports but URLs have port specifications"""
        urls = ["https://example.com:8080", "api.test.com:443,8443"]
        targets = resolve_scan_targets(urls)  # No global ports
        
        assert len(targets) == 2
        assert targets[0].ports == [8080]
        assert targets[1].ports == [443, 8443]

    def test_resolve_no_ports_available_error(self):
        """Test error when no ports available for a target"""
        urls = ["https://example.com"]  # No port specification
        
        # No global ports provided
        with pytest.raises(ValueError, match="No ports specified.*no global ports available"):
            resolve_scan_targets(urls)

    def test_resolve_empty_global_ports_error(self):
        """Test error when global ports is empty list"""
        urls = ["https://example.com"]
        
        with pytest.raises(ValueError, match="No ports specified.*no global ports available"):
            resolve_scan_targets(urls, [])  # Empty global ports

    def test_resolve_invalid_url_error(self):
        """Test error handling for invalid URLs"""
        urls = ["https://"]  # Invalid URL
        
        with pytest.raises(ValueError, match="Failed to parse URL specification"):
            resolve_scan_targets(urls, [443])

    def test_resolve_invalid_port_error(self):
        """Test error handling for invalid port specifications"""
        urls = ["https://example.com:invalid_port"]
        
        with pytest.raises(ValueError, match="Failed to parse URL specification"):
            resolve_scan_targets(urls, [443])

    def test_resolve_empty_url_list(self):
        """Test resolving empty URL list"""
        targets = resolve_scan_targets([], [443])
        
        assert targets == []

    def test_resolve_preserves_original_urls(self):
        """Test that original URL specifications are preserved"""
        original_urls = [
            "https://example.com/path?param=value",
            "api.example.com:8080",  
            "https://user:pass@secure.example.com:9000"
        ]
        
        targets = resolve_scan_targets(original_urls, [443])
        
        for i, target in enumerate(targets):
            assert target.original_url == original_urls[i]

    def test_resolve_complex_scenarios(self):
        """Test complex real-world scenarios"""
        urls = [
            "https://www.example.com",
            "https://api.example.com:8080", 
            "admin.example.com:443,8443,9443",
            "192.168.1.1:22,80,443",
            "https://[2001:db8::1]:8080"
        ]
        
        targets = resolve_scan_targets(urls, [443, 80])
        
        assert len(targets) == 5
        
        # Check each target has correct configuration
        assert targets[0].hostname == "www.example.com"
        assert targets[0].ports == [443, 80]  # Global ports
        
        assert targets[1].hostname == "api.example.com" 
        assert targets[1].ports == [8080]  # Specific port
        
        assert targets[2].hostname == "admin.example.com"
        assert targets[2].ports == [443, 8443, 9443]  # Multiple ports
        
        assert targets[3].hostname == "192.168.1.1"
        assert targets[3].ports == [22, 80, 443]  # IP with multiple ports
        
        assert targets[4].hostname == "2001:db8::1"
        assert targets[4].ports == [8080]  # IPv6 with port

    def test_resolve_duplicate_hostnames_different_ports(self):
        """Test resolving duplicate hostnames with different port specifications"""
        urls = [
            "https://example.com:443",
            "https://example.com:8080",
            "example.com:9000"
        ]
        
        targets = resolve_scan_targets(urls, [80])
        
        assert len(targets) == 3
        # All should have same hostname but different ports
        for target in targets:
            assert target.hostname == "example.com"
            
        assert targets[0].ports == [443]
        assert targets[1].ports == [8080] 
        assert targets[2].ports == [9000]

    def test_resolve_error_context(self):
        """Test that error messages include context about which URL failed"""
        urls = ["https://valid.example.com", "https://", "https://also-valid.com"]
        
        with pytest.raises(ValueError) as excinfo:
            resolve_scan_targets(urls, [443])
            
        # Error should mention the specific URL that failed
        assert "https://" in str(excinfo.value)
        assert "Failed to parse URL specification" in str(excinfo.value)