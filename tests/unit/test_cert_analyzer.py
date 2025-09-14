"""
Tests for ktscan.cert_analyzer module
"""

import socket
import ssl
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch, MagicMock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from ktscan.cert_analyzer import CertAnalyzer
from ktscan.models import ScanResult
from ktscan.models import ValidationFinding, ValidationSeverity, ConfidenceLevel




class TestCertAnalyzer:
    """Test the CertAnalyzer class"""

    def test_init_default_config(self):
        """Test CertAnalyzer initialization with default configuration"""
        analyzer = CertAnalyzer()
        
        assert analyzer.timeout == 10
        assert analyzer.thread_manager is None
        assert analyzer.validation_config == {}
        
        # Check that check registry is available
        from ktscan.check_registry import check_registry
        check_categories = check_registry.get_all_check_categories()
        assert len(check_categories) >= 6  # At least 6 check categories available

    def test_init_with_config(self):
        """Test CertAnalyzer initialization with custom configuration"""
        config = {
            "cryptography": {"min_key_size": 2048},
            "lifecycle": {"warn_days": 30},
            "chain": {"disabled_checks": ["chain_validation"]}
        }
        thread_manager = Mock()
        
        analyzer = CertAnalyzer(
            timeout=30,
            validation_config=config,
            thread_manager=thread_manager
        )
        
        assert analyzer.timeout == 30
        assert analyzer.thread_manager == thread_manager
        assert analyzer.validation_config == config

    @patch('ktscan.cert_analyzer.socket.getaddrinfo')
    @patch('ktscan.cert_analyzer.socket.socket')
    @patch('ktscan.cert_analyzer.ssl.create_default_context')
    def test_get_certificate_success(self, mock_ssl_context, mock_socket_class, mock_getaddrinfo, cert_factory):
        """Test successful certificate retrieval"""
        # Create a test certificate
        cert, _ = cert_factory.create_self_signed_cert(subject_name="example.com")
        cert_der = cert.public_bytes(serialization.Encoding.DER)
        
        # Mock getaddrinfo
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.168.1.1', 443))
        ]
        
        # Mock socket
        mock_socket = Mock()
        mock_socket_class.return_value = mock_socket
        
        # Mock SSL context and connection
        mock_ssl_socket = Mock()
        # The actual code calls getpeercert(binary_form=True)
        mock_ssl_socket.getpeercert.return_value = cert_der
        
        mock_context_manager = Mock()
        mock_context_manager.__enter__ = Mock(return_value=mock_ssl_socket)
        mock_context_manager.__exit__ = Mock(return_value=None)
        
        mock_ssl_context.return_value.wrap_socket.return_value = mock_context_manager
        
        analyzer = CertAnalyzer()
        result = analyzer._get_certificate("192.168.1.1", 443, "example.com")
        
        assert result == cert_der
        # Verify socket was created and used
        mock_socket_class.assert_called_once()
        mock_socket.settimeout.assert_called_once_with(10)
        mock_socket.connect.assert_called_once()
        mock_ssl_context.assert_called_once()

    @patch('ktscan.cert_analyzer.socket.getaddrinfo')
    @patch('ktscan.cert_analyzer.socket.socket')
    def test_get_certificate_connection_error(self, mock_socket_class, mock_getaddrinfo):
        """Test certificate retrieval with connection error"""
        # Mock getaddrinfo
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.168.1.1', 443))
        ]
        
        # Mock socket to fail on connect
        mock_socket = Mock()
        mock_socket.connect.side_effect = socket.error("Connection failed")
        mock_socket_class.return_value = mock_socket
        
        analyzer = CertAnalyzer()
        result = analyzer._get_certificate("192.168.1.1", 443)
        
        assert result is None

    @patch('ktscan.cert_analyzer.socket.create_connection')
    @patch('ktscan.cert_analyzer.ssl.create_default_context')
    def test_get_certificate_ssl_error(self, mock_ssl_context, mock_socket):
        """Test certificate retrieval with SSL error"""
        mock_ssl_context.return_value.wrap_socket.side_effect = ssl.SSLError("SSL handshake failed")
        
        analyzer = CertAnalyzer()
        result = analyzer._get_certificate("192.168.1.1", 443)
        
        assert result is None


    def test_determine_trust_status_chain_disabled(self):
        """Test trust status determination when chain validation is disabled"""
        config = {"chain": {"disabled_checks": ["chain_validation"]}}
        analyzer = CertAnalyzer(validation_config=config)
        
        result = analyzer._determine_trust_status([])
        
        assert result is None

    def test_determine_trust_status_no_failures(self):
        """Test trust status determination with no failures"""
        analyzer = CertAnalyzer()
        findings = [
            ValidationFinding(
                check_id="some_other_check",
                confidence=ConfidenceLevel.HIGH,
                title="Info",
                description="Info finding"
            )
        ]
        
        result = analyzer._determine_trust_status(findings)
        
        assert result is True

    def test_determine_trust_status_chain_path_failure(self):
        """Test trust status determination with chain path validation failure"""
        analyzer = CertAnalyzer()
        findings = [
            ValidationFinding(
                check_id="CHAIN.PATH_VALIDATION_FAILED",
                confidence=ConfidenceLevel.HIGH,
                title="Chain Path Validation Failed",
                description="Chain validation failed"
            )
        ]
        
        result = analyzer._determine_trust_status(findings)
        
        assert result is False

    def test_determine_trust_status_self_signed(self):
        """Test trust status determination with self-signed certificate"""
        analyzer = CertAnalyzer()
        findings = [
            ValidationFinding(
                check_id="CHAIN.SELF_SIGNED",
                confidence=ConfidenceLevel.HIGH,
                title="Self-Signed Certificate",
                description="Certificate is self-signed"
            )
        ]
        
        result = analyzer._determine_trust_status(findings)
        
        assert result is False

    def test_get_public_key_algorithm_rsa(self, cert_factory):
        """Test public key algorithm detection for RSA"""
        cert, _ = cert_factory.create_certificate(
            subject_name="example.com",
            key_size=2048,
            key_type="rsa"
        )
        
        analyzer = CertAnalyzer()
        algorithm = analyzer._get_public_key_algorithm(cert.public_key())
        
        assert algorithm == "RSA"

    def test_get_public_key_algorithm_unknown(self):
        """Test public key algorithm detection for unknown type"""
        analyzer = CertAnalyzer()
        mock_key = Mock()
        type(mock_key).__name__ = "UnknownKey"
        
        algorithm = analyzer._get_public_key_algorithm(mock_key)
        
        # The actual implementation returns the class name for unknown types  
        assert algorithm == "UnknownKey" or "Mock" in algorithm

    def test_calculate_certificate_fingerprint(self, cert_factory):
        """Test certificate fingerprint calculation"""
        cert, _ = cert_factory.create_certificate(subject_name="example.com")
        
        analyzer = CertAnalyzer()
        fingerprint = analyzer._calculate_certificate_fingerprint(cert)
        
        assert len(fingerprint) == 64  # SHA256 hex string
        assert all(c in '0123456789abcdef' for c in fingerprint.lower())

    def test_extract_name_attribute(self, cert_factory):
        """Test name attribute extraction"""
        cert, _ = cert_factory.create_certificate(
            subject_name="example.com",
            issuer_name="Test CA"
        )
        
        analyzer = CertAnalyzer()
        
        subject_cn = analyzer._extract_name_attribute(cert.subject, x509.NameOID.COMMON_NAME)
        issuer_cn = analyzer._extract_name_attribute(cert.issuer, x509.NameOID.COMMON_NAME)
        
        assert "example.com" in subject_cn
        assert "Test CA" in issuer_cn

    def test_extract_name_attribute_not_found(self, cert_factory):
        """Test name attribute extraction when attribute not found"""
        cert, _ = cert_factory.create_certificate(subject_name="example.com")
        
        analyzer = CertAnalyzer()
        result = analyzer._extract_name_attribute(cert.subject, x509.NameOID.ORGANIZATIONAL_UNIT_NAME)
        
        assert result is None

    def test_extract_san_domains(self, cert_factory):
        """Test SAN domain extraction"""
        cert, _ = cert_factory.create_certificate(
            subject_name="example.com",
            san_domains=["example.com", "www.example.com", "api.example.com"]
        )
        
        analyzer = CertAnalyzer()
        san_domains = analyzer._extract_san_domains(cert)
        
        assert len(san_domains) == 3
        assert "example.com" in san_domains
        assert "www.example.com" in san_domains
        assert "api.example.com" in san_domains

    def test_extract_san_domains_no_san(self, cert_factory):
        """Test SAN domain extraction when no SAN extension"""
        cert, _ = cert_factory.create_certificate(subject_name="example.com")
        
        analyzer = CertAnalyzer()
        san_domains = analyzer._extract_san_domains(cert)
        
        assert san_domains == []

    @patch.object(CertAnalyzer, '_get_certificate')
    def test_scan_certificate_no_certificate(self, mock_get_cert):
        """Test certificate scanning when no certificate is retrieved"""
        mock_get_cert.return_value = None
        
        analyzer = CertAnalyzer()
        result = analyzer.scan_certificate("192.168.1.1", 443, "example.com")
        
        assert result.primary_ip == "192.168.1.1"
        assert result.primary_port == 443
        assert result.target == "example.com"
        assert result.certificate is None
        assert result.valid is False
        assert len(result.errors) == 1
        assert "Failed to retrieve certificate" in result.errors[0]

    @patch.object(CertAnalyzer, '_get_certificate')
    def test_scan_certificate_invalid_der(self, mock_get_cert):
        """Test certificate scanning with invalid DER data"""
        mock_get_cert.return_value = b"invalid certificate data"
        
        analyzer = CertAnalyzer()
        result = analyzer.scan_certificate("192.168.1.1", 443)
        
        assert result.certificate is None
        assert result.valid is False
        assert len(result.errors) == 1
        assert "Invalid certificate:" in result.errors[0]

    @patch.object(CertAnalyzer, '_get_certificate')
    def test_scan_certificate_success(self, mock_get_cert, cert_factory):
        """Test successful certificate scanning"""
        # Create a test certificate
        cert, _ = cert_factory.create_certificate(
            subject_name="example.com",
            san_domains=["example.com", "www.example.com"]
        )
        cert_der = cert.public_bytes(serialization.Encoding.DER)
        mock_get_cert.return_value = cert_der
        
        analyzer = CertAnalyzer()
        result = analyzer.scan_certificate("192.168.1.1", 443, "example.com")
        
        assert result.primary_ip == "192.168.1.1"
        assert result.primary_port == 443
        assert result.target == "example.com"
        assert result.certificate is not None
        # Certificate parsing should succeed
        assert result.certificate.certificate_fingerprint != ""
        assert result.certificate.trusted is None  # Not validated yet
        assert len(result.findings) == 0  # No validation findings yet (only scanned)
        assert result.status.value == "SCANNED"  # Should be scanned, not validated

    def test_apply_severity_filtering_default(self):
        """Test severity filtering with default threshold (MEDIUM)"""
        analyzer = CertAnalyzer()
        findings = [
            ValidationFinding("test1", ValidationSeverity.INFO, ConfidenceLevel.HIGH, "Info", "Info finding"),
            ValidationFinding("test2", ValidationSeverity.MEDIUM, ConfidenceLevel.HIGH, "Medium", "Medium finding"),
            ValidationFinding("test3", ValidationSeverity.HIGH, ConfidenceLevel.HIGH, "High", "High finding"),
        ]
        
        result = analyzer._apply_severity_filtering(findings)
        
        assert len(result) == 2  # Only MEDIUM and HIGH should pass

    def test_apply_severity_filtering_with_filter(self):
        """Test severity filtering with minimum severity configured"""
        config = {"severity_filter": "HIGH"}
        analyzer = CertAnalyzer(validation_config=config)
        findings = [
            ValidationFinding("test1", ValidationSeverity.INFO, ConfidenceLevel.HIGH, "Info", "Info finding"),
            ValidationFinding("test2", ValidationSeverity.MEDIUM, ConfidenceLevel.HIGH, "Medium", "Medium finding"),
            ValidationFinding("test3", ValidationSeverity.HIGH, ConfidenceLevel.HIGH, "High", "High finding"),
            ValidationFinding("test4", ValidationSeverity.CRITICAL, ConfidenceLevel.HIGH, "Critical", "Critical finding"),
        ]
        
        result = analyzer._apply_severity_filtering(findings)
        
        assert len(result) == 2
        # Check that only HIGH and CRITICAL findings are included
        severity_values = [f.severity for f in result]
        assert ValidationSeverity.HIGH in severity_values
        assert ValidationSeverity.CRITICAL in severity_values
        assert len(result) == 2


