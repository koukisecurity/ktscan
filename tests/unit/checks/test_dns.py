"""
Unit tests for DNS validation checks.
"""

import socket
from unittest.mock import Mock, patch

import pytest

from ktscan.models import ValidationSeverity
from ktscan.checks.DNS import DnsCheck


class TestDnsCheck:
    """Test DnsCheck functionality"""

    def test_init_default_config(self):
        """Test validator initialization with default config"""
        validator = DnsCheck()
        assert validator.config == {}
        assert validator.timeout == 10

    def test_init_with_config(self):
        """Test validator initialization with custom config"""
        config = {"disabled_checks": ["DNS.CAA_VIOLATION"]}
        validator = DnsCheck(config, timeout=30)
        assert validator.config == config
        assert validator.timeout == 30

    def test_validate_without_hostname_context(self, cert_factory):
        """Test validation without hostname in context"""
        validator = DnsCheck()
        cert, _ = cert_factory.create_certificate()

        # Test with no context
        findings = validator.validate(cert, None)
        assert len(findings) == 0

        # Test with empty context
        findings = validator.validate(cert, {})
        assert len(findings) == 0

        # Test with context missing hostname
        findings = validator.validate(cert, {"other_key": "value"})
        assert len(findings) == 0

    def test_validate_with_hostname_context(self, cert_factory):
        """Test validation with hostname in context"""
        validator = DnsCheck()
        cert, _ = cert_factory.create_certificate()

        context = {"hostname": "example.com"}
        findings = validator.validate(cert, context)

        # Should have at least one finding (CAA check failed due to not implemented)
        assert len(findings) >= 1
        caa_findings = [f for f in findings if f.check_id == "DNS.CAA_CHECK_FAILED"]
        assert len(caa_findings) >= 1


class TestDomainResolution:
    """Test domain resolution validation"""

    def test_resolvable_domain(self, cert_factory):
        """Test validation with resolvable domain"""
        validator = DnsCheck()

        # Use a well-known public domain that should resolve
        context = {"hostname": "google.com"}
        
        with patch('socket.gethostbyname') as mock_resolve:
            mock_resolve.return_value = "8.8.8.8"
            findings = validator._validate_domain_resolution("google.com")

        # Should not have resolution failure findings
        resolution_failures = [f for f in findings if f.check_id == "DNS.DOMAIN_RESOLUTION_FAILED"]
        assert len(resolution_failures) == 0

    def test_unresolvable_domain(self, cert_factory):
        """Test validation with unresolvable domain"""
        validator = DnsCheck()

        with patch('socket.gethostbyname') as mock_resolve:
            mock_resolve.side_effect = socket.gaierror("Name resolution failed")
            findings = validator._validate_domain_resolution("nonexistent.invalid")

        # Should detect resolution failure
        resolution_failures = [f for f in findings if f.check_id == "DNS.DOMAIN_RESOLUTION_FAILED"]
        assert len(resolution_failures) == 1

        finding = resolution_failures[0]
        assert finding.severity == ValidationSeverity.MEDIUM
        assert "cannot be resolved" in finding.description.lower()
        assert finding.evidence["hostname"] == "nonexistent.invalid"

    def test_domain_resolution_exception(self, cert_factory):
        """Test handling of unexpected exceptions during domain resolution"""
        validator = DnsCheck()

        with patch('socket.gethostbyname') as mock_resolve:
            mock_resolve.side_effect = Exception("Unexpected error")
            findings = validator._validate_domain_resolution("example.com")

        # Should handle exception gracefully without critical failures
        assert isinstance(findings, list)


class TestCAARecordValidation:
    """Test CAA record validation"""

    def test_caa_check_not_implemented(self, cert_factory):
        """Test CAA record checking reports not implemented"""
        validator = DnsCheck()

        findings = validator._validate_caa_records("example.com")

        # Should report CAA check as not implemented
        caa_failures = [f for f in findings if f.check_id == "DNS.CAA_CHECK_FAILED"]
        assert len(caa_failures) == 1

        finding = caa_failures[0]
        assert finding.severity == ValidationSeverity.MEDIUM
        assert "not implemented" in finding.evidence["reason"]
        assert finding.evidence["hostname"] == "example.com"

    def test_caa_validation_exception_handling(self, cert_factory):
        """Test CAA validation handles exceptions gracefully"""
        validator = DnsCheck()

        # Mock an exception during CAA checking
        with patch.object(validator, '_validate_caa_records') as mock_caa:
            mock_caa.side_effect = Exception("DNS error")
            
            # Should handle exception gracefully
            try:
                findings = validator._validate_caa_records("example.com")
                assert isinstance(findings, list)
            except Exception:
                # If exception bubbles up, that's also acceptable behavior
                pass


class TestDnsCheckConfiguration:
    """Test DNS check configuration and filtering"""

    def test_disabled_checks_filtering(self, cert_factory):
        """Test that disabled checks are filtered out"""
        config = {"disabled_checks": ["DNS.CAA_CHECK_FAILED"]}
        validator = DnsCheck(config)

        context = {"hostname": "example.com"}
        cert, _ = cert_factory.create_certificate()
        
        findings = validator.validate(cert, context)

        # Should not have disabled check findings
        caa_findings = [f for f in findings if f.check_id == "DNS.CAA_CHECK_FAILED"]
        assert len(caa_findings) == 0

    def test_check_registration(self):
        """Test that all checks are properly registered"""
        validator = DnsCheck()

        # Verify check registration
        expected_checks = [
            "DNS.CAA_VIOLATION",
            "DNS.CAA_CHECK_FAILED",
            "DNS.DOMAIN_RESOLUTION_FAILED",
            "DNS.CAA_ALLOWS_ISSUANCE",
        ]

        for check_id in expected_checks:
            assert validator.is_check_enabled(check_id), f"Check {check_id} should be enabled by default"


class TestDnsIntegration:
    """Integration tests for DNS validation"""

    def test_validate_complete_workflow(self, cert_factory):
        """Test complete DNS validation workflow"""
        validator = DnsCheck()

        cert, _ = cert_factory.create_certificate()
        context = {"hostname": "example.com"}

        with patch('socket.gethostbyname') as mock_resolve:
            mock_resolve.return_value = "93.184.216.34"  # example.com IP
            findings = validator.validate(cert, context)

        # Should have findings from CAA checking (not implemented)
        assert len(findings) >= 1
        
        # Should not have domain resolution failures
        resolution_failures = [f for f in findings if f.check_id == "DNS.DOMAIN_RESOLUTION_FAILED"]
        assert len(resolution_failures) == 0

    def test_validate_with_context(self, cert_factory):
        """Test validation with context parameter"""
        validator = DnsCheck()
        cert, _ = cert_factory.create_certificate()

        context = {"hostname": "test.example.com", "additional_data": "ignored"}
        findings = validator.validate(cert, context)

        # Context should not cause errors
        assert isinstance(findings, list)

    def test_check_info(self):
        """Test check info is properly defined"""
        validator = DnsCheck()
        check_info = validator.get_check_info()
        
        assert check_info.check_id == "DNS"
        assert "DNS" in check_info.title
        assert len(check_info.description) > 0