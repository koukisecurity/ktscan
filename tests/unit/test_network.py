"""
Tests for ktscan.network module
"""

import socket
from unittest.mock import Mock, patch, MagicMock
from urllib.parse import urlparse

import pytest
import dns.resolver

from ktscan.network import NetworkResolver


class TestNetworkResolver:
    """Test the NetworkResolver class"""

    def test_init_default_config(self):
        """Test NetworkResolver initialization with default configuration"""
        resolver = NetworkResolver()
        
        assert resolver.timeout == 5
        assert resolver.thread_manager is None
        assert resolver.logger is not None

    def test_init_with_config(self):
        """Test NetworkResolver initialization with custom configuration"""
        thread_manager = Mock()
        resolver = NetworkResolver(timeout=30, thread_manager=thread_manager)
        
        assert resolver.timeout == 30
        assert resolver.thread_manager == thread_manager

    @patch('ktscan.network.socket.socket')
    def test_test_ipv6_support_available(self, mock_socket):
        """Test IPv6 support detection when available"""
        mock_sock = Mock()
        mock_socket.return_value = mock_sock
        
        resolver = NetworkResolver()
        
        mock_socket.assert_called_with(socket.AF_INET6, socket.SOCK_STREAM)
        mock_sock.close.assert_called_once()

    @patch('ktscan.network.socket.socket')
    def test_test_ipv6_support_unavailable(self, mock_socket):
        """Test IPv6 support detection when unavailable"""
        mock_socket.side_effect = socket.error("IPv6 not supported")
        
        resolver = NetworkResolver()
        
        assert resolver.ipv6_supported is False

    def test_is_ip_address_valid_ipv4(self):
        """Test IP address validation for valid IPv4"""
        resolver = NetworkResolver()
        
        assert resolver._is_ip_address("192.168.1.1") is True
        assert resolver._is_ip_address("10.0.0.1") is True
        assert resolver._is_ip_address("127.0.0.1") is True

    def test_is_ip_address_valid_ipv6(self):
        """Test IP address validation for valid IPv6"""
        resolver = NetworkResolver()
        
        assert resolver._is_ip_address("2001:db8::1") is True
        assert resolver._is_ip_address("::1") is True
        assert resolver._is_ip_address("fe80::1") is True

    def test_is_ip_address_invalid(self):
        """Test IP address validation for invalid addresses"""
        resolver = NetworkResolver()
        
        assert resolver._is_ip_address("example.com") is False
        assert resolver._is_ip_address("not.an.ip") is False
        assert resolver._is_ip_address("999.999.999.999") is False
        assert resolver._is_ip_address("") is False

    def test_is_ipv6_address_valid(self):
        """Test IPv6 address detection"""
        resolver = NetworkResolver()
        
        assert resolver._is_ipv6_address("2001:db8::1") is True
        assert resolver._is_ipv6_address("::1") is True
        assert resolver._is_ipv6_address("fe80::1") is True

    def test_is_ipv6_address_ipv4(self):
        """Test IPv6 address detection with IPv4 addresses"""
        resolver = NetworkResolver()
        
        assert resolver._is_ipv6_address("192.168.1.1") is False
        assert resolver._is_ipv6_address("10.0.0.1") is False

    def test_is_ipv6_address_invalid(self):
        """Test IPv6 address detection with invalid addresses"""
        resolver = NetworkResolver()
        
        assert resolver._is_ipv6_address("example.com") is False
        assert resolver._is_ipv6_address("not.an.ip") is False

    def test_resolve_url_to_targets_with_ip(self):
        """Test URL to targets resolution when URL contains IP"""
        resolver = NetworkResolver()
        
        targets = resolver.resolve_url_to_targets("https://192.168.1.1", [443, 8443])
        
        expected = [("192.168.1.1", 443), ("192.168.1.1", 8443)]
        assert targets == expected

    def test_resolve_url_to_targets_invalid_url(self):
        """Test URL to targets resolution with invalid URL"""
        resolver = NetworkResolver()
        
        with pytest.raises(ValueError, match="Cannot extract hostname from URL"):
            resolver.resolve_url_to_targets("", [443])

    @patch('ktscan.network.dns.resolver.resolve')
    def test_resolve_hostname_to_ips_dns_success(self, mock_resolve):
        """Test hostname to IPs resolution via DNS"""
        # Mock DNS responses
        mock_a_record = Mock()
        mock_a_record.__str__ = Mock(return_value="192.168.1.1")
        mock_aaaa_record = Mock()
        mock_aaaa_record.__str__ = Mock(return_value="2001:db8::1")
        
        def mock_resolve_func(hostname, record_type):
            if record_type == "A":
                return [mock_a_record]
            elif record_type == "AAAA":
                return [mock_aaaa_record]
            
        mock_resolve.side_effect = mock_resolve_func
        
        resolver = NetworkResolver()
        ips = resolver._resolve_hostname_to_ips("example.com")
        
        assert "192.168.1.1" in ips
        assert "2001:db8::1" in ips
        assert len(ips) >= 2

    @patch('ktscan.network.dns.resolver.resolve')
    def test_resolve_hostname_to_ips_ip_input(self, mock_resolve):
        """Test hostname to IPs resolution when input is already an IP"""
        resolver = NetworkResolver()
        ips = resolver._resolve_hostname_to_ips("192.168.1.1")
        
        assert ips == {"192.168.1.1"}
        mock_resolve.assert_not_called()

    @patch('ktscan.network.dns.resolver.resolve')
    @patch('ktscan.network.socket.getaddrinfo')
    def test_resolve_hostname_to_ips_dns_failure_fallback(self, mock_getaddrinfo, mock_resolve):
        """Test hostname resolution fallback to getaddrinfo when DNS fails"""
        # Mock DNS to fail
        mock_resolve.side_effect = dns.resolver.NXDOMAIN()
        
        # Mock getaddrinfo to succeed
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.168.1.1', 443))
        ]
        
        resolver = NetworkResolver()
        ips = resolver._resolve_hostname_to_ips("example.com")
        
        assert "192.168.1.1" in ips

    @patch('ktscan.network.dns.resolver.resolve')
    @patch('ktscan.network.socket.getaddrinfo')
    def test_resolve_hostname_to_ips_all_fail(self, mock_getaddrinfo, mock_resolve):
        """Test hostname resolution when all methods fail"""
        # Mock DNS to fail
        mock_resolve.side_effect = dns.resolver.NXDOMAIN()
        
        # Mock getaddrinfo to fail
        mock_getaddrinfo.side_effect = socket.gaierror("Name resolution failed")
        
        resolver = NetworkResolver()
        
        with pytest.raises(ValueError, match="Could not resolve hostname"):
            resolver._resolve_hostname_to_ips("nonexistent.example")

    @patch('ktscan.network.socket.getaddrinfo')
    @patch('ktscan.network.socket.socket')
    def test_is_port_open_success(self, mock_socket_class, mock_getaddrinfo):
        """Test port connectivity check when port is open"""
        # Mock getaddrinfo
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.168.1.1', 443))
        ]
        
        # Mock socket
        mock_socket = Mock()
        mock_socket.connect_ex.return_value = 0  # Success
        mock_socket_class.return_value = mock_socket
        
        resolver = NetworkResolver()
        is_open, reason = resolver.is_port_open("192.168.1.1", 443)
        
        assert is_open is True
        assert reason == "Connected"
        mock_socket.settimeout.assert_called_with(5)
        mock_socket.connect_ex.assert_called_once()
        assert mock_socket.close.call_count >= 1  # May be called multiple times

    @patch('ktscan.network.socket.getaddrinfo')
    @patch('ktscan.network.socket.socket')
    def test_is_port_open_failure(self, mock_socket_class, mock_getaddrinfo):
        """Test port connectivity check when port is closed"""
        # Mock getaddrinfo
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.168.1.1', 443))
        ]
        
        # Mock socket
        mock_socket = Mock()
        mock_socket.connect_ex.return_value = 111  # Connection refused
        mock_socket_class.return_value = mock_socket
        
        resolver = NetworkResolver()
        is_open, reason = resolver.is_port_open("192.168.1.1", 443)
        
        assert is_open is False
        assert "Connection failed" in reason

    @patch('ktscan.network.socket.getaddrinfo')
    def test_is_port_open_no_address_info(self, mock_getaddrinfo):
        """Test port connectivity check when no address info available"""
        mock_getaddrinfo.return_value = []
        
        resolver = NetworkResolver()
        is_open, reason = resolver.is_port_open("192.168.1.1", 443)
        
        assert is_open is False
        assert reason == "No address info available"

    @patch('ktscan.network.socket.getaddrinfo')
    def test_is_port_open_socket_error(self, mock_getaddrinfo):
        """Test port connectivity check when socket error occurs"""
        mock_getaddrinfo.side_effect = socket.error("Network error")
        
        resolver = NetworkResolver()
        is_open, reason = resolver.is_port_open("192.168.1.1", 443)
        
        assert is_open is False
        assert "Network error" in reason

    def test_is_port_open_ipv6_not_supported(self):
        """Test port connectivity check for IPv6 when not supported"""
        resolver = NetworkResolver()
        resolver.ipv6_supported = False
        
        is_open, reason = resolver.is_port_open("2001:db8::1", 443)
        
        assert is_open is False
        assert reason == "IPv6 not supported"

    @patch('ktscan.network.socket.getaddrinfo')
    @patch('ktscan.network.socket.socket')
    def test_is_port_open_ipv6_connectivity_issue(self, mock_socket_class, mock_getaddrinfo):
        """Test port connectivity check for IPv6 with connectivity issues"""
        # Mock getaddrinfo
        mock_getaddrinfo.return_value = [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('2001:db8::1', 443))
        ]
        
        # Mock socket
        mock_socket = Mock()
        mock_socket.connect_ex.return_value = 101  # Network unreachable
        mock_socket_class.return_value = mock_socket
        
        resolver = NetworkResolver()
        resolver.ipv6_supported = True
        is_open, reason = resolver.is_port_open("2001:db8::1", 443)
        
        assert is_open is False
        assert reason == "IPv6 connectivity issue"

    def test_filter_open_ports_mixed_results(self):
        """Test filtering open ports with mixed results"""
        resolver = NetworkResolver()
        
        def mock_is_port_open(ip, port):
            if ip == "192.168.1.1":
                return True, "Connected"
            elif ip == "192.168.1.2":
                return False, "Connection refused"
            elif ip == "2001:db8::1":
                return False, "IPv6 not supported"
            else:
                return False, "Connection failed"
        
        resolver.is_port_open = mock_is_port_open
        resolver.ipv6_supported = False
        
        targets = [
            ("192.168.1.1", 443),
            ("192.168.1.2", 443),
            ("2001:db8::1", 443),
            ("10.0.0.1", 443)
        ]
        
        open_targets = resolver.filter_open_ports(targets)
        
        assert open_targets == [("192.168.1.1", 443)]

    def test_resolve_multiple_hostnames_parallel_no_thread_manager(self):
        """Test parallel hostname resolution without thread manager (falls back to sequential)"""
        resolver = NetworkResolver()
        resolver.thread_manager = None
        
        def mock_resolve(hostname):
            return {f"192.168.1.{ord(hostname[0]) % 10}"}
        
        resolver._resolve_hostname_to_ips = mock_resolve
        
        hostnames = ["example.com", "test.com"]
        result = resolver.resolve_multiple_hostnames_parallel(hostnames)
        
        assert len(result) == 2
        assert "example.com" in result
        assert "test.com" in result

    def test_resolve_multiple_hostnames_parallel_with_thread_manager(self):
        """Test parallel hostname resolution with thread manager"""
        mock_thread_manager = Mock()
        mock_thread_manager.map_parallel.return_value = [
            ("example.com", {"192.168.1.1"}),
            ("test.com", {"192.168.1.2"})
        ]
        
        resolver = NetworkResolver(thread_manager=mock_thread_manager)
        hostnames = ["example.com", "test.com"]
        
        result = resolver.resolve_multiple_hostnames_parallel(hostnames)
        
        assert result == {"example.com": {"192.168.1.1"}, "test.com": {"192.168.1.2"}}
        mock_thread_manager.map_parallel.assert_called_once()

    def test_filter_open_ports_parallel_no_thread_manager(self):
        """Test parallel port filtering without thread manager (falls back to sequential)"""
        resolver = NetworkResolver()
        resolver.thread_manager = None
        
        def mock_filter_open_ports(targets):
            return [t for t in targets if t[1] == 443]  # Only port 443 "open"
        
        resolver.filter_open_ports = mock_filter_open_ports
        
        targets = [("192.168.1.1", 443), ("192.168.1.1", 80)]
        result = resolver.filter_open_ports_parallel(targets)
        
        assert result == [("192.168.1.1", 443)]

    def test_filter_open_ports_parallel_with_thread_manager(self):
        """Test parallel port filtering with thread manager"""
        mock_thread_manager = Mock()
        mock_thread_manager.max_workers = 4
        mock_thread_manager.map_parallel.return_value = [
            ("192.168.1.1", 443, True, "Connected"),
            ("192.168.1.1", 80, False, "Connection refused")
        ]
        
        resolver = NetworkResolver(thread_manager=mock_thread_manager)
        targets = [("192.168.1.1", 443), ("192.168.1.1", 80)]
        
        result = resolver.filter_open_ports_parallel(targets)
        
        assert result == [("192.168.1.1", 443)]
        mock_thread_manager.map_parallel.assert_called_once()

    def test_resolve_url_to_targets_with_hostname(self):
        """Test URL to targets resolution with hostname (integration-like test)"""
        resolver = NetworkResolver()
        
        def mock_resolve(hostname):
            if hostname == "example.com":
                return {"192.168.1.1", "192.168.1.2"}
            return set()
        
        resolver._resolve_hostname_to_ips = mock_resolve
        
        targets = resolver.resolve_url_to_targets("https://example.com", [443, 8443])
        
        expected = [
            ("192.168.1.1", 443), ("192.168.1.1", 8443),
            ("192.168.1.2", 443), ("192.168.1.2", 8443)
        ]
        assert len(targets) == 4
        for target in expected:
            assert target in targets

    @patch('ktscan.network.dns.resolver.resolve')
    def test_resolve_hostname_to_ips_partial_dns_success(self, mock_resolve):
        """Test hostname resolution when only A record succeeds"""
        def mock_resolve_func(hostname, record_type):
            if record_type == "A":
                mock_record = Mock()
                mock_record.__str__ = Mock(return_value="192.168.1.1")
                return [mock_record]
            elif record_type == "AAAA":
                raise dns.resolver.NXDOMAIN()
        
        mock_resolve.side_effect = mock_resolve_func
        
        resolver = NetworkResolver()
        ips = resolver._resolve_hostname_to_ips("example.com")
        
        assert "192.168.1.1" in ips
        assert len(ips) == 1

    def test_filter_open_ports_with_ipv6_logging(self):
        """Test that IPv6 targets are properly logged when skipped"""
        resolver = NetworkResolver()
        resolver.ipv6_supported = False
        
        def mock_is_port_open(ip, port):
            if resolver._is_ipv6_address(ip):
                return False, "IPv6 not supported"
            return True, "Connected"
        
        resolver.is_port_open = mock_is_port_open
        
        targets = [
            ("192.168.1.1", 443),
            ("2001:db8::1", 443),
            ("2001:db8::2", 443)
        ]
        
        result = resolver.filter_open_ports(targets)
        
        # Should only include IPv4 target
        assert result == [("192.168.1.1", 443)]