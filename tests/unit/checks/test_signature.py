"""
Unit tests for signature algorithm validation.
"""

import pytest

from ktscan.models import ValidationSeverity
from ktscan.checks.CRYPTO import CryptoCheck


class TestCryptoCheck:
    """Test CryptoCheck functionality"""

    def test_validator_initialization(self):
        """Test validator initialization with and without config"""
        # Test default initialization
        validator = CryptoCheck()
        assert validator.config == {}

        # Test with config
        config = {"disabled_checks": ["weak_signature_algorithm"]}
        validator = CryptoCheck(config)
        assert validator.config == config
        assert "weak_signature_algorithm" in validator.disabled_checks

    def test_constants(self):
        """Test validator constants are properly defined"""
        validator = CryptoCheck()

        # Check weak signature algorithms
        assert "sha1WithRSAEncryption" in validator.WEAK_SIGNATURE_ALGORITHMS
        assert "md5WithRSAEncryption" in validator.WEAK_SIGNATURE_ALGORITHMS

        # Check deprecated signature algorithms
        assert "dsaWithSHA1" in validator.DEPRECATED_SIGNATURE_ALGORITHMS

        # Check that constants are properly defined
        assert len(validator.DEPRECATED_SIGNATURE_ALGORITHMS) > 0

        # Check that validator has required functionality
        assert hasattr(validator, 'logger')


class TestSignatureAlgorithmValidation:
    """Test signature algorithm validation"""

    def test_strong_signature_algorithms(self, cert_factory):
        """Test that strong signature algorithms pass validation"""
        validator = CryptoCheck()

        # Test SHA-256
        cert, _ = cert_factory.create_certificate(signature_algorithm="sha256")
        findings = validator._validate_signature_algorithm(cert)
        critical_high_findings = [f for f in findings if f.severity in [ValidationSeverity.CRITICAL, ValidationSeverity.HIGH]]
        assert len(critical_high_findings) == 0

        # Test SHA-384
        cert, _ = cert_factory.create_certificate(signature_algorithm="sha384")
        findings = validator._validate_signature_algorithm(cert)
        critical_high_findings = [f for f in findings if f.severity in [ValidationSeverity.CRITICAL, ValidationSeverity.HIGH]]
        assert len(critical_high_findings) == 0

        # Test SHA-512
        cert, _ = cert_factory.create_certificate(signature_algorithm="sha512")
        findings = validator._validate_signature_algorithm(cert)
        critical_high_findings = [f for f in findings if f.severity in [ValidationSeverity.CRITICAL, ValidationSeverity.HIGH]]
        assert len(critical_high_findings) == 0

    def test_weak_signature_algorithms(self, cert_factory, mocker):
        """Test detection of weak signature algorithms"""
        validator = CryptoCheck()

        # Create a mock certificate with weak signature algorithm
        mock_cert = mocker.Mock()
        mock_oid = mocker.Mock()
        mock_oid._name = "sha1WithRSAEncryption"
        mock_cert.signature_algorithm_oid = mock_oid

        findings = validator._validate_signature_algorithm(mock_cert)

        # Should detect weak signature algorithm
        weak_findings = [
            f for f in findings if f.check_id == "CRYPTO.WEAK_ALGORITHM"
        ]
        assert len(weak_findings) >= 1

        finding = weak_findings[0]
        assert finding.severity == ValidationSeverity.CRITICAL
        assert "weak" in finding.description.lower() and "signature algorithm" in finding.description.lower()
        assert finding.evidence.get("algorithm") == "sha1WithRSAEncryption"

    def test_deprecated_signature_algorithms(self, cert_factory, mocker):
        """Test detection of deprecated signature algorithms"""
        validator = CryptoCheck()

        # Create a mock certificate with deprecated signature algorithm
        mock_cert = mocker.Mock()
        mock_oid = mocker.Mock()
        mock_oid._name = "dsaWithSHA1"
        mock_cert.signature_algorithm_oid = mock_oid

        findings = validator._validate_signature_algorithm(mock_cert)

        # DSA should be detected as deprecated
        dep_findings = [
            f for f in findings if f.check_id == "CRYPTO.DEPRECATED_ALGORITHM"
        ]
        assert len(dep_findings) >= 1

        finding = dep_findings[0]
        assert finding.severity == ValidationSeverity.HIGH
        assert "deprecated" in finding.description.lower()


class TestValidatorErrorHandling:
    """Test error handling in validator"""

    def test_signature_algorithm_edge_cases(self, cert_factory, mocker):
        """Test edge cases in signature algorithm validation"""
        validator = CryptoCheck()

        # Create a mock certificate with unknown signature algorithm
        mock_cert = mocker.Mock()
        mock_oid = mocker.Mock()
        mock_oid._name = "unknownSignatureAlgorithm"
        mock_cert.signature_algorithm_oid = mock_oid

        findings = validator._validate_signature_algorithm(mock_cert)
        # Should not crash, unknown algorithms should be handled gracefully
        assert isinstance(findings, list)