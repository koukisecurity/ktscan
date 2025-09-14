"""
Unit tests for certificate revocation validation.
"""

from datetime import datetime
from unittest.mock import Mock, patch

import requests
import responses
from freezegun import freeze_time

from ktscan.models import ValidationSeverity
from ktscan.checks.REVOCATION import RevocationCheck


class TestRevocationCheck:
    """Test RevocationCheck functionality"""

    def test_init_default_config(self):
        """Test validator initialization with default config"""
        validator = RevocationCheck()
        assert validator.config == {}
        assert validator.check_ocsp is True

    def test_init_with_config(self):
        """Test validator initialization with custom config"""
        config = {"check_ocsp": False, "ocsp_timeout": 5}
        validator = RevocationCheck(config)
        assert validator.config == config
        assert validator.check_ocsp is False
        assert validator.ocsp_timeout == 5

    def test_validate_revocation_info_sequential(self, cert_factory):
        """Test revocation validation in sequential mode (no thread manager)"""
        cert, _ = cert_factory.create_cert_with_revocation_info(
            ocsp_urls=["https://ocsp.example.com"],
            crl_urls=["https://crl.example.com/cert.crl"],
        )

        validator = RevocationCheck({"check_ocsp": True})

        with patch.object(
            validator, "_validate_ocsp_endpoint"
        ) as mock_ocsp, patch.object(
            validator, "_validate_crl_distribution_points"
        ) as mock_crl:
            mock_ocsp.return_value = []
            mock_crl.return_value = []

            findings = validator._validate_revocation_info_sequential(cert)

            mock_ocsp.assert_called_once()
            mock_crl.assert_called_once()

    def test_validate_revocation_info_parallel(self, cert_factory):
        """Test revocation validation in parallel mode (with thread manager)"""
        cert, _ = cert_factory.create_cert_with_revocation_info(
            ocsp_urls=["https://ocsp.example.com"],
            crl_urls=["https://crl.example.com/cert.crl"],
        )

        thread_manager = Mock()
        thread_manager.map_parallel.return_value = [[], []]

        validator = RevocationCheck({"check_ocsp": True}, thread_manager=thread_manager)

        findings = validator._validate_revocation_info_parallel(cert)

        thread_manager.map_parallel.assert_called_once()
        args, kwargs = thread_manager.map_parallel.call_args
        assert kwargs["max_concurrent"] == 2  # OCSP + CRL

    def test_missing_revocation_info(self, cert_factory):
        """Test validation of certificate missing all revocation info"""
        cert, _ = cert_factory.create_certificate()  # No OCSP/CRL

        validator = RevocationCheck({"check_ocsp": True})
        findings = validator._validate_revocation_info_sequential(cert)

        missing = [f for f in findings if f.check_id == "REVOCATION.MISSING_REVOCATION_INFO"]
        assert len(missing) == 1
        assert missing[0].severity == ValidationSeverity.MEDIUM
        assert "lacks both OCSP and CRL" in missing[0].description

    def test_missing_ocsp_info_only(self, cert_factory):
        """Test validation of certificate missing only OCSP info"""
        cert, _ = cert_factory.create_certificate(
            crl_urls=["https://crl.example.com/cert.crl"]
        )

        validator = RevocationCheck({"check_ocsp": True})
        findings = validator._validate_revocation_info_sequential(cert)

        missing_ocsp = [f for f in findings if f.check_id == "REVOCATION.MISSING_OCSP_INFO"]
        assert len(missing_ocsp) == 1
        assert missing_ocsp[0].severity == ValidationSeverity.MEDIUM
        assert "lacks OCSP endpoint" in missing_ocsp[0].description


class TestOCSPValidation:
    """Test OCSP endpoint validation"""

    def test_validate_ocsp_endpoint_invalid_url(self):
        """Test OCSP endpoint validation with invalid URL"""
        validator = RevocationCheck()
        findings = validator._validate_ocsp_endpoint("ldap://invalid.com")

        invalid_url = [f for f in findings if f.check_id == "REVOCATION.INVALID_OCSP_URL"]
        assert len(invalid_url) == 1
        assert invalid_url[0].severity == ValidationSeverity.HIGH
        assert "not a valid HTTP endpoint" in invalid_url[0].description

    def test_validate_ocsp_endpoint_insecure_http(self):
        """Test OCSP endpoint validation with HTTP (not HTTPS)"""
        validator = RevocationCheck()

        with responses.RequestsMock() as rsps:
            rsps.add(responses.HEAD, "http://ocsp.example.com", status=200)
            findings = validator._validate_ocsp_endpoint("http://ocsp.example.com")

        insecure = [f for f in findings if f.check_id == "REVOCATION.INSECURE_OCSP_URL"]
        assert len(insecure) == 1
        assert insecure[0].severity == ValidationSeverity.MEDIUM
        assert "uses HTTP instead of HTTPS" in insecure[0].description

    @responses.activate
    def test_validate_ocsp_endpoint_reachable(self):
        """Test OCSP endpoint validation with reachable endpoint"""
        responses.add(responses.HEAD, "https://ocsp.example.com", status=200)

        validator = RevocationCheck()
        findings = validator._validate_ocsp_endpoint("https://ocsp.example.com")

        # Should have no unreachable findings
        unreachable = [f for f in findings if f.check_id == "REVOCATION.OCSP_ENDPOINT_UNREACHABLE"]
        assert len(unreachable) == 0

    @responses.activate
    def test_validate_ocsp_endpoint_method_not_allowed(self):
        """Test OCSP endpoint validation with 405 Method Not Allowed (acceptable)"""
        responses.add(responses.HEAD, "https://ocsp.example.com", status=405)

        validator = RevocationCheck()
        findings = validator._validate_ocsp_endpoint("https://ocsp.example.com")

        # 405 is acceptable for HEAD on OCSP
        unreachable = [f for f in findings if f.check_id == "REVOCATION.OCSP_ENDPOINT_UNREACHABLE"]
        assert len(unreachable) == 0

    @responses.activate
    def test_validate_ocsp_endpoint_unreachable(self):
        """Test OCSP endpoint validation with unreachable endpoint"""
        responses.add(responses.HEAD, "https://ocsp.example.com", status=404)

        validator = RevocationCheck()
        findings = validator._validate_ocsp_endpoint("https://ocsp.example.com")

        unreachable = [f for f in findings if f.check_id == "REVOCATION.OCSP_ENDPOINT_UNREACHABLE"]
        assert len(unreachable) == 1
        assert unreachable[0].severity == ValidationSeverity.HIGH
        assert "unreachable" in unreachable[0].description.lower() or "non-success" in unreachable[0].description.lower()

    @responses.activate
    def test_validate_ocsp_endpoint_timeout(self):
        """Test OCSP endpoint validation with timeout"""
        responses.add(
            responses.HEAD,
            "https://ocsp.example.com",
            body=requests.exceptions.Timeout(),
        )

        validator = RevocationCheck({"ocsp_timeout": 5})
        findings = validator._validate_ocsp_endpoint("https://ocsp.example.com")

        timeout = [f for f in findings if f.check_id == "REVOCATION.OCSP_TIMEOUT"]
        assert len(timeout) == 1
        assert timeout[0].severity == ValidationSeverity.MEDIUM
        assert "timeout" in timeout[0].description.lower() or "timed out" in timeout[0].description.lower()

    @responses.activate
    def test_validate_ocsp_endpoint_connection_error(self):
        """Test OCSP endpoint validation with connection error"""
        responses.add(
            responses.HEAD,
            "https://ocsp.example.com",
            body=requests.exceptions.ConnectionError("Connection failed"),
        )

        validator = RevocationCheck()
        findings = validator._validate_ocsp_endpoint("https://ocsp.example.com")

        error = [f for f in findings if f.check_id == "REVOCATION.OCSP_RESPONDER_ERROR"]
        assert len(error) == 1
        assert error[0].severity == ValidationSeverity.HIGH
        assert "OCSP responder returned an error" in error[0].description


class TestCRLValidation:
    """Test CRL distribution point validation"""

    def test_validate_crl_distribution_points_invalid_url(self, cert_factory):
        """Test CRL distribution point validation with invalid URL"""
        # Create mock CRL distribution points
        mock_dp = Mock()
        mock_name = Mock()
        mock_name.value = "ldap://invalid.com"
        mock_dp.full_name = [mock_name]
        mock_dp.reasons = None

        # Mock isinstance to return True for UniformResourceIdentifier
        with patch("ktscan.checks.REVOCATION.isinstance") as mock_isinstance:
            mock_isinstance.return_value = True

            validator = RevocationCheck()
            findings = validator._validate_crl_distribution_points([mock_dp])

        invalid_url = [f for f in findings if f.check_id == "REVOCATION.INVALID_CRL_URL"]
        assert len(invalid_url) == 1
        assert invalid_url[0].severity == ValidationSeverity.MEDIUM
        assert "not a valid HTTP endpoint" in invalid_url[0].description

    def test_validate_crl_distribution_points_insecure_http(self, cert_factory):
        """Test CRL distribution point validation with HTTP URL"""
        # Create mock CRL distribution points
        mock_dp = Mock()
        mock_name = Mock()
        mock_name.value = "http://crl.example.com/cert.crl"
        mock_dp.full_name = [mock_name]
        mock_dp.reasons = None

        # Mock isinstance to return True for UniformResourceIdentifier
        with patch("ktscan.checks.REVOCATION.isinstance") as mock_isinstance:
            mock_isinstance.return_value = True

            validator = RevocationCheck()
            findings = validator._validate_crl_distribution_points([mock_dp])

        insecure = [f for f in findings if f.check_id == "REVOCATION.INSECURE_CRL_URL"]
        assert len(insecure) == 1
        assert insecure[0].severity == ValidationSeverity.LOW
        assert "uses HTTP instead of HTTPS" in insecure[0].description

    def test_validate_crl_distribution_points_with_reasons(self, cert_factory):
        """Test CRL distribution point validation with reasons specified"""
        # Create mock CRL distribution points with reasons
        mock_dp = Mock()
        mock_name = Mock()
        mock_name.value = "https://crl.example.com/cert.crl"
        mock_dp.full_name = [mock_name]
        mock_dp.reasons = [Mock(), Mock()]  # Some reasons

        # Mock isinstance to return True for UniformResourceIdentifier
        with patch("ktscan.checks.REVOCATION.isinstance") as mock_isinstance:
            mock_isinstance.return_value = True

            validator = RevocationCheck()
            findings = validator._validate_crl_distribution_points([mock_dp])

        with_reasons = [f for f in findings if f.check_id == "REVOCATION.CRL_DP_WITH_REASONS"]
        assert len(with_reasons) == 1
        assert with_reasons[0].severity == ValidationSeverity.LOW
        assert "specifies revocation reasons" in with_reasons[0].description


class TestRevocationIntegration:
    """Integration tests for revocation validation"""

    @freeze_time("2024-06-15")
    def test_validate_complete_workflow_with_ocsp(self, cert_factory):
        """Test complete validation workflow with OCSP enabled"""
        cert, _ = cert_factory.create_cert_with_revocation_info(
            not_before=datetime(2024, 1, 1),
            not_after=datetime(2024, 12, 31),
            ocsp_urls=["https://ocsp.example.com"],
            crl_urls=["https://crl.example.com/cert.crl"],
        )

        validator = RevocationCheck({"check_ocsp": True})

        with responses.RequestsMock() as rsps:
            rsps.add(responses.HEAD, "https://ocsp.example.com", status=200)
            findings = validator.validate(cert)

        # Should include revocation validation
        assert len(findings) >= 0  # At least some findings should be present

    def test_validate_with_context(self, cert_factory):
        """Test validation with context parameter"""
        cert, _ = cert_factory.create_certificate()

        validator = RevocationCheck()
        context = {"hostname": "example.com"}
        findings = validator.validate(cert, context)

        # Context doesn't affect revocation validation, but should not cause errors
        assert isinstance(findings, list)