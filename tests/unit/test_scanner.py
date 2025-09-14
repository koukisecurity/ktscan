"""
Tests for ktscan.scanner module
"""

import logging
import pytest
from unittest.mock import Mock, patch, MagicMock
from ktscan.scanner import KTScan
from ktscan.config import ScanConfig
from ktscan.scan_target import ScanTarget
from ktscan.models import ScanResult, ScanStatus
from cryptography import x509
from cryptography.x509.oid import NameOID


class TestKTScan:
    """Test the KTScan class"""

    def setup_method(self):
        """Set up test fixtures"""
        self.config = ScanConfig(
            urls=["https://example.com"],
            ports=[443],
            threads=2,
            timeout=10,
            verbose=False,
            output_format="table"
        )
        # Resolve targets after config creation
        self.config._resolve_targets()
        
        self.mock_console = Mock()
        self.mock_thread_manager = Mock()
        
        # Create scanner instance with mocks
        with patch('ktscan.scanner.NetworkResolver') as mock_network, \
             patch('ktscan.scanner.CertAnalyzer') as mock_analyzer:
            
            self.scanner = KTScan(
                config=self.config,
                console=self.mock_console,
                thread_manager=self.mock_thread_manager
            )
            self.mock_network = mock_network.return_value
            self.mock_analyzer = mock_analyzer.return_value

    def test_init_basic(self):
        """Test basic scanner initialization"""
        assert self.scanner.config == self.config
        assert self.scanner.console == self.mock_console
        assert self.scanner.thread_manager == self.mock_thread_manager
        assert self.scanner.network is not None
        assert self.scanner.analyzer is not None

    def test_init_logging_setup_verbose(self):
        """Test logging setup in verbose mode"""
        config = ScanConfig(
            urls=[],
            verbose=True
        )
        
        with patch('ktscan.scanner.logging.basicConfig') as mock_basic_config, \
             patch('ktscan.scanner.NetworkResolver'), \
             patch('ktscan.scanner.CertAnalyzer'):
            
            mock_thread_manager = Mock()
            KTScan(config=config, thread_manager=mock_thread_manager)
            mock_basic_config.assert_called_once()
            args, kwargs = mock_basic_config.call_args
            assert kwargs['level'] == logging.DEBUG

    def test_init_logging_setup_json_format(self):
        """Test logging setup for JSON output format"""
        config = ScanConfig(
            urls=[],
            output_format="json"
        )
        
        with patch('ktscan.scanner.logging.basicConfig') as mock_basic_config, \
             patch('ktscan.scanner.NetworkResolver'), \
             patch('ktscan.scanner.CertAnalyzer'):
            
            mock_thread_manager = Mock()
            KTScan(config=config, thread_manager=mock_thread_manager)
            mock_basic_config.assert_called_once()
            args, kwargs = mock_basic_config.call_args
            assert kwargs['level'] == logging.ERROR

    def test_scan_empty_targets(self):
        """Test scanning with no targets"""
        self.config._targets = []
        
        with patch('ktscan.scanner.ThreeStageProgress') as mock_progress:
            mock_progress_instance = Mock()
            mock_progress.return_value.__enter__.return_value = mock_progress_instance
            
            results = self.scanner.scan()
            
            assert results == []

    def test_scan_with_targets(self):
        """Test successful scan with targets"""
        mock_cert_result = ScanResult(
            target="example.com",
            endpoints=[("192.168.1.1", 443)]
        )
        
        with patch('ktscan.scanner.ThreeStageProgress') as mock_progress, \
             patch.object(self.scanner, '_scan_with_progress', return_value=[mock_cert_result]):
            
            mock_progress_instance = Mock()
            mock_progress.return_value.__enter__.return_value = mock_progress_instance
            
            results = self.scanner.scan()
            
            assert len(results) == 1
            assert results[0] == mock_cert_result

    def test_scan_with_exception(self):
        """Test scan error handling"""
        with patch('ktscan.scanner.ThreeStageProgress') as mock_progress, \
             patch.object(self.scanner, '_scan_with_progress', side_effect=Exception("Scan failed")):
            
            mock_progress_instance = Mock()
            mock_progress.return_value.__enter__.return_value = mock_progress_instance
            
            with pytest.raises(Exception, match="Scan failed"):
                self.scanner.scan()

    def test_resolve_network_targets(self):
        """Test network target resolution"""
        scan_target = ScanTarget(
            original_url="https://example.com",
            hostname="example.com",
            ports=[443, 8443]
        )
        
        # Mock network resolver responses
        self.mock_network.resolve_url_to_targets.return_value = [
            ("192.168.1.1", 443),
            ("192.168.1.1", 8443)
        ]
        self.mock_network.filter_open_ports.return_value = [
            ("192.168.1.1", 443)
        ]
        
        results = self.scanner._resolve_network_targets(scan_target)
        
        assert len(results) == 1
        assert results[0] == ("192.168.1.1", 443)
        
        self.mock_network.resolve_url_to_targets.assert_called_once_with(
            "https://example.com", [443, 8443]
        )
        self.mock_network.filter_open_ports.assert_called_once()

    def test_resolve_network_targets_no_ips(self):
        """Test network target resolution with no IPs found"""
        scan_target = ScanTarget(
            original_url="https://example.com",
            hostname="example.com",
            ports=[443]
        )
        
        self.mock_network.resolve_url_to_targets.return_value = []
        
        results = self.scanner._resolve_network_targets(scan_target)
        
        assert results == []

    def test_resolve_network_targets_no_open_ports(self):
        """Test network target resolution with no open ports"""
        scan_target = ScanTarget(
            original_url="https://example.com",
            hostname="example.com",
            ports=[443]
        )
        
        self.mock_network.resolve_url_to_targets.return_value = [("192.168.1.1", 443)]
        self.mock_network.filter_open_ports.return_value = []
        
        results = self.scanner._resolve_network_targets(scan_target)
        
        assert results == []

    def test_resolve_network_targets_exception(self):
        """Test network target resolution error handling"""
        scan_target = ScanTarget(
            original_url="https://example.com",
            hostname="example.com",
            ports=[443]
        )
        
        self.mock_network.resolve_url_to_targets.side_effect = Exception("DNS failed")
        
        with pytest.raises(Exception, match="DNS failed"):
            self.scanner._resolve_network_targets(scan_target)


    def test_deduplicate_certificates_same_url(self):
        """Test certificate deduplication with same fingerprint and same URL"""
        # Create mock certificates with fingerprints
        cert1 = Mock()
        cert1.certificate_fingerprint = "abc123"
        cert2 = Mock()
        cert2.certificate_fingerprint = "abc123"
        
        # Create test results with same fingerprint and same original_url
        result1 = ScanResult(
            target="example.com",
            endpoints=[("192.168.1.1", 443)]
        )
        result1.certificate = cert1
        result1.original_url = "https://example.com"
        
        result2 = ScanResult(
            target="example.com", 
            endpoints=[("192.168.1.2", 443)]
        )
        result2.certificate = cert2
        result2.original_url = "https://example.com"  # Same URL as result1
        
        results = [result1, result2]
        
        with patch.object(result1, 'add_endpoint') as mock_add:
            deduplicated = self.scanner._deduplicate_certificates(results)
            
            # Should deduplicate because same fingerprint AND same URL
            assert len(deduplicated) == 1
            mock_add.assert_called_once_with("192.168.1.2", 443)

    def test_deduplicate_certificates_different_urls(self):
        """Test certificate deduplication with same fingerprint but different URLs"""
        # Create mock certificates with same fingerprints
        cert1 = Mock()
        cert1.certificate_fingerprint = "abc123"
        cert2 = Mock()
        cert2.certificate_fingerprint = "abc123"  # Same fingerprint
        
        # Create test results with same fingerprint but different original_urls
        result1 = ScanResult(
            target="example.com",
            endpoints=[("192.168.1.1", 443)]
        )
        result1.certificate = cert1
        result1.original_url = "https://example.com"
        
        result2 = ScanResult(
            target="www.example.com", 
            endpoints=[("192.168.1.2", 443)]
        )
        result2.certificate = cert2
        result2.original_url = "https://www.example.com"  # Different URL
        
        results = [result1, result2]
        
        deduplicated = self.scanner._deduplicate_certificates(results)
        
        # Should NOT deduplicate because different URLs, even with same fingerprint
        assert len(deduplicated) == 2
        assert result1 in deduplicated
        assert result2 in deduplicated

    def test_deduplicate_certificates_no_fingerprint(self):
        """Test certificate deduplication with missing fingerprints"""
        # Create mock certificates without fingerprints
        cert1 = Mock()
        cert1.certificate_fingerprint = None
        cert2 = Mock()
        cert2.certificate_fingerprint = None
        
        result1 = ScanResult(
            target="example.com",
            endpoints=[("192.168.1.1", 443)]
        )
        result1.certificate = cert1
        
        result2 = ScanResult(
            target="example.com",
            endpoints=[("192.168.1.2", 443)]
        )
        result2.certificate = cert2
        
        results = [result1, result2]
        
        # Should handle missing certificates gracefully by keeping both results
        deduplicated = self.scanner._deduplicate_certificates(results)
        assert len(deduplicated) == 2

    def test_deduplicate_certificates_empty_list(self):
        """Test certificate deduplication with empty input"""
        results = []
        deduplicated = self.scanner._deduplicate_certificates(results)
        assert deduplicated == []



    def test_scan_progress_determination(self):
        """Test progress bar show/hide logic"""
        # Test verbose mode - should not show progress
        self.config.verbose = True
        
        with patch('ktscan.scanner.ThreeStageProgress') as mock_progress, \
             patch.object(self.scanner, '_scan_with_progress', return_value=[]):
            
            mock_progress_instance = Mock()
            mock_progress.return_value.__enter__.return_value = mock_progress_instance
            
            self.scanner.scan()
            
            # Progress should be created with show_progress=False for verbose mode
            mock_progress.assert_called_once_with(self.mock_console, False)

    def test_scan_progress_json_format(self):
        """Test progress bar is disabled for JSON output"""
        self.config.output_format = "json"
        
        with patch('ktscan.scanner.ThreeStageProgress') as mock_progress, \
             patch.object(self.scanner, '_scan_with_progress', return_value=[]):
            
            mock_progress_instance = Mock()
            mock_progress.return_value.__enter__.return_value = mock_progress_instance
            
            self.scanner.scan()
            
            # Progress should be created with show_progress=False for JSON format
            mock_progress.assert_called_once_with(self.mock_console, False)


    def test_scan_returns_all_results_including_failures(self):
        """Test that scanner returns all scan attempts including failures"""
        
        # Create a successful result
        mock_cert_result = ScanResult(
            target="example.com",
            endpoints=[("192.168.1.1", 443)]
        )
        mock_cert_result.certificate = Mock()  # Valid certificate
        mock_cert_result.status = ScanStatus.SUCCESS
        
        # Create a failed result  
        failed_result = ScanResult(
            target="example.com",
            endpoints=[("192.168.1.2", 443)]
        )
        failed_result.certificate = None  # No certificate
        failed_result.status = ScanStatus.FAILED
        
        with patch('ktscan.scanner.ThreeStageProgress'), \
             patch.object(self.scanner, '_stage1_parallel_dns_and_ports', return_value=[]), \
             patch.object(self.scanner, '_stage2_parallel_certificate_download', return_value=[mock_cert_result, failed_result]), \
             patch.object(self.scanner, '_deduplicate_certificates', return_value=[mock_cert_result, failed_result]), \
             patch.object(self.scanner, '_validate_certificates_with_progress', return_value=[mock_cert_result, failed_result]):
            
            # Mock progress
            mock_progress = Mock()
            results = self.scanner._scan_with_progress(mock_progress)
            
            # Should return both results (success and failure)
            assert len(results) == 2
            assert any(r.status == ScanStatus.SUCCESS for r in results)
            assert any(r.status == ScanStatus.FAILED for r in results)

