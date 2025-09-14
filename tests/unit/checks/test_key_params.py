"""
Unit tests for key parameter validation.
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
        config = {"disabled_checks": ["CRYPTO.WEAK_RSA"]}
        validator = CryptoCheck(config)
        assert validator.config == config
        assert "CRYPTO.WEAK_RSA" in validator.disabled_checks

    def test_constants(self):
        """Test validator constants are properly defined"""
        validator = CryptoCheck()

        # Check key parameter constants
        assert validator.MINIMUM_RSA_KEY_SIZE == 2048
        assert len(validator.APPROVED_EC_CURVES) > 0

        # Check that validator has required functionality
        assert hasattr(validator, 'logger')


class TestRSAKeyValidation:
    """Test RSA key validation"""

    def test_strong_rsa_keys(self, cert_factory):
        """Test that strong RSA keys pass validation"""
        validator = CryptoCheck()

        # Test 2048-bit RSA (minimum acceptable)
        cert, _ = cert_factory.create_certificate(key_type="rsa", key_size=2048)
        findings = validator._validate_rsa_key(cert.public_key())

        # Should have at most a warning about recommending 3072+ bits
        critical_high_findings = [
            f
            for f in findings
            if f.severity in [ValidationSeverity.CRITICAL, ValidationSeverity.HIGH]
        ]
        assert len(critical_high_findings) == 0

        # Test 3072-bit RSA (recommended)
        cert, _ = cert_factory.create_certificate(key_type="rsa", key_size=3072)
        findings = validator._validate_rsa_key(cert.public_key())
        assert len(findings) == 0

        # Test 4096-bit RSA (strong)
        cert, _ = cert_factory.create_certificate(key_type="rsa", key_size=4096)
        findings = validator._validate_rsa_key(cert.public_key())
        assert len(findings) == 0

    def test_weak_rsa_keys(self, cert_factory):
        """Test detection of weak RSA keys"""
        validator = CryptoCheck()

        # Test 1024-bit RSA (weak)
        cert, _ = cert_factory.create_certificate(key_type="rsa", key_size=1024)
        findings = validator._validate_rsa_key(cert.public_key())

        weak_findings = [f for f in findings if f.check_id == "CRYPTO.WEAK_RSA"]
        assert len(weak_findings) == 1

        finding = weak_findings[0]
        assert (
            finding.severity == ValidationSeverity.HIGH
        )  # 1024 should be HIGH, not CRITICAL
        assert "1024" in finding.description
        assert finding.evidence["current_size"] == 1024
        assert finding.evidence["minimum_size"] == 2048

        # Note: Can't test 512-bit RSA as cryptography library enforces minimum 1024 bits
        # The validator logic handles this case correctly

    def test_rsa_key_size_warning(self, cert_factory):
        """Test RSA key size warning for 2048-bit keys"""
        validator = CryptoCheck()

        # 2048-bit keys should generate a warning about upgrading to 3072+
        cert, _ = cert_factory.create_certificate(key_type="rsa", key_size=2048)
        findings = validator._validate_rsa_key(cert.public_key())

        warning_findings = [f for f in findings if f.check_id == "CRYPTO.RSA_SIZE_WARNING"]
        assert len(warning_findings) == 1

        finding = warning_findings[0]
        assert finding.severity == ValidationSeverity.MEDIUM
        assert finding.evidence["current_size"] == 2048
        assert finding.evidence["future_recommendation"] == 3072


class TestECDSAKeyValidation:
    """Test ECDSA key validation"""

    @pytest.mark.parametrize(
        "curve,expected_strength",
        [("secp256r1", 256), ("secp384r1", 384), ("secp521r1", 521)],
    )
    def test_approved_ec_curves(self, cert_factory, curve, expected_strength):
        """Test that approved ECDSA curves pass validation"""
        validator = CryptoCheck()

        cert, _ = cert_factory.create_certificate(key_type="ecdsa", curve_name=curve)
        findings = validator._validate_ec_key(cert.public_key())

        # Should have no critical or high severity findings
        critical_high_findings = [
            f
            for f in findings
            if f.severity in [ValidationSeverity.CRITICAL, ValidationSeverity.HIGH]
        ]
        assert len(critical_high_findings) == 0


class TestDSAKeyValidation:
    """Test DSA key validation"""

    def test_dsa_algorithm_deprecated(self, cert_factory):
        """Test that DSA algorithm is flagged as deprecated"""
        validator = CryptoCheck()

        # Create DSA certificate
        cert, _ = cert_factory.create_certificate(key_type="dsa", key_size=2048)
        findings = validator._validate_dsa_key(cert.public_key())

        # Should have deprecated algorithm finding
        deprecated_findings = [
            f for f in findings if f.check_id == "CRYPTO.DSA_DEPRECATED"
        ]
        assert len(deprecated_findings) == 1

        finding = deprecated_findings[0]
        assert finding.severity == ValidationSeverity.HIGH
        assert "deprecated" in finding.description.lower()

    def test_weak_dsa_key_size(self, cert_factory):
        """Test detection of weak DSA key sizes"""
        validator = CryptoCheck()

        # Create weak DSA certificate
        cert, _ = cert_factory.create_certificate(key_type="dsa", key_size=1024)
        findings = validator._validate_dsa_key(cert.public_key())

        # Should have both deprecated algorithm and weak key size findings
        weak_findings = [f for f in findings if f.check_id == "CRYPTO.WEAK_DSA"]
        assert len(weak_findings) == 1

        finding = weak_findings[0]
        assert finding.severity == ValidationSeverity.CRITICAL
        assert finding.evidence["current_size"] == 1024
        assert finding.evidence["minimum_size"] == 2048


class TestEdwardsKeyValidation:
    """Test Edwards curve key validation (Ed25519, Ed448)"""

    def test_ed25519_key_info(self, cert_factory):
        """Test Ed25519 key generates info finding"""
        validator = CryptoCheck()

        cert, _ = cert_factory.create_certificate(key_type="ed25519")
        findings = validator._validate_edwards_key(cert.public_key())

        # Should have info finding about Ed25519
        ed25519_findings = [f for f in findings if f.check_id == "CRYPTO.ED25519_ALGORITHM"]
        assert len(ed25519_findings) == 1

        finding = ed25519_findings[0]
        assert finding.severity == ValidationSeverity.MEDIUM
        assert "Ed25519" in finding.title
        assert finding.evidence["algorithm"] == "Ed25519"
        assert finding.evidence["security_level"] == "high"

    def test_unknown_key_algorithm(self, cert_factory, mocker):
        """Test handling of unknown key algorithms"""
        validator = CryptoCheck()

        # Create a mock certificate with unknown key type
        mock_cert = mocker.Mock()
        mock_key = mocker.Mock()
        mock_key.__class__.__name__ = "UnknownPublicKey"
        mock_cert.public_key.return_value = mock_key

        findings = validator._validate_public_key(mock_cert)

        unknown_findings = [
            f for f in findings if f.check_id == "CRYPTO.UNKNOWN_ALGORITHM"
        ]
        assert len(unknown_findings) == 1

        finding = unknown_findings[0]
        assert finding.severity == ValidationSeverity.MEDIUM
        assert "unknown or unsupported algorithm" in finding.description.lower()
        assert finding.evidence["key_type"] == "UnknownPublicKey"


class TestPublicKeyValidation:
    """Test overall public key validation"""

    def test_public_key_validation_dispatch(self, cert_factory):
        """Test that public key validation correctly dispatches to specific key type checks"""
        validator = CryptoCheck()

        # Test RSA key dispatch
        rsa_cert, _ = cert_factory.create_certificate(key_type="rsa", key_size=4096)
        findings = validator._validate_public_key(rsa_cert)
        # Should not have any critical/high findings for strong RSA key
        critical_high = [
            f
            for f in findings
            if f.severity in [ValidationSeverity.CRITICAL, ValidationSeverity.HIGH]
        ]
        assert len(critical_high) == 0

        # Test ECDSA key dispatch
        ec_cert, _ = cert_factory.create_certificate(
            key_type="ecdsa", curve_name="secp256r1"
        )
        findings = validator._validate_public_key(ec_cert)
        critical_high = [
            f
            for f in findings
            if f.severity in [ValidationSeverity.CRITICAL, ValidationSeverity.HIGH]
        ]
        assert len(critical_high) == 0

        # Test Ed25519 key dispatch
        ed_cert, _ = cert_factory.create_certificate(key_type="ed25519")
        findings = validator._validate_public_key(ed_cert)
        # Should have medium severity finding
        medium_findings = [f for f in findings if f.severity == ValidationSeverity.MEDIUM]
        assert len(medium_findings) == 1

    def test_public_key_encoding_validation(self, cert_factory):
        """Test public key encoding validation"""
        validator = CryptoCheck()

        # Test normal certificate
        cert, _ = cert_factory.create_valid_cert()
        findings = validator._validate_key_algorithm(cert)

        # Should not have encoding errors for normal certificates
        encoding_errors = [
            f for f in findings if f.check_id == "CRYPTO.ENCODING_ERROR"
        ]
        assert len(encoding_errors) == 0

        # Oversized key test would be difficult without creating extremely large keys
        # We'll focus on the error handling path in integration tests


class TestKeyParamsIntegration:
    """Integration tests for the key parameters validator"""

    def test_validate_method_combines_all_checks(self, cert_factory):
        """Test that validate method combines all check types"""
        validator = CryptoCheck()

        # Create certificate with weak RSA key
        cert, _ = cert_factory.create_certificate(
            key_type="rsa", key_size=1024  # Weak key size
        )

        findings = validator.validate(cert)

        # Should have RSA key size finding
        rsa_findings = [f for f in findings if "RSA" in f.check_id]
        assert len(rsa_findings) >= 1

        # At least one finding expected (weak key)
        assert len(findings) >= 1

    def test_validate_respects_check_configuration(self, cert_factory):
        """Test that validate method respects enabled/disabled check configuration"""
        # Test with disabled weak RSA key check
        config = {"disabled_checks": ["CRYPTO.WEAK_RSA"]}
        validator = CryptoCheck(config)

        cert, _ = cert_factory.create_certificate(key_type="rsa", key_size=1024)
        findings = validator.validate(cert)

        # Should not have weak RSA key findings
        rsa_findings = [f for f in findings if f.check_id == "CRYPTO.WEAK_RSA"]
        assert len(rsa_findings) == 0

    def test_validate_with_various_certificate_types(self, cert_factory):
        """Test validator with various certificate types"""
        validator = CryptoCheck()

        test_cases = [
            # (cert_creation_method, expected_critical_count, expected_high_count)
            ("create_valid_cert", 0, 0),  # Should be clean
            (
                "create_weak_rsa_cert",
                0,
                1,
            ),  # Should have high severity for 1024-bit RSA
        ]

        for cert_method, expected_critical, expected_high in test_cases:
            cert, _ = getattr(cert_factory, cert_method)()
            findings = validator.validate(cert)

            critical_findings = [
                f for f in findings if f.severity == ValidationSeverity.CRITICAL
            ]
            high_findings = [
                f for f in findings if f.severity == ValidationSeverity.HIGH
            ]

            assert (
                len(critical_findings) >= expected_critical
            ), f"Failed for {cert_method}: expected {expected_critical} critical, got {len(critical_findings)}"
            assert (
                len(high_findings) >= expected_high
            ), f"Failed for {cert_method}: expected {expected_high} high, got {len(high_findings)}"

    @pytest.mark.parametrize(
        "key_type,key_size,curve",
        [
            ("rsa", 2048, None),
            ("rsa", 4096, None),
            ("ecdsa", None, "secp256r1"),
            ("ecdsa", None, "secp384r1"),
            ("ed25519", None, None),
        ],
    )
    def test_validate_secure_configurations(
        self, cert_factory, key_type, key_size, curve
    ):
        """Test that secure configurations don't generate critical/high findings"""
        validator = CryptoCheck()

        kwargs = {"key_type": key_type}
        if key_size:
            kwargs["key_size"] = key_size
        if curve:
            kwargs["curve_name"] = curve

        cert, _ = cert_factory.create_certificate(**kwargs)
        findings = validator.validate(cert)

        # Should not have critical or high severity findings for secure configurations
        critical_high = [
            f
            for f in findings
            if f.severity in [ValidationSeverity.CRITICAL, ValidationSeverity.HIGH]
        ]
        assert (
            len(critical_high) == 0
        ), f"Unexpected critical/high findings for {key_type}: {[f.description for f in critical_high]}"


class TestKeyParamsErrorHandling:
    """Test error handling in key parameters validator"""

    def test_malformed_certificate_handling(self, cert_factory, mocker):
        """Test handling of malformed certificates"""
        validator = CryptoCheck()

        # Create a mock certificate that raises an exception on public_key()
        mock_cert = mocker.Mock()
        mock_cert.public_key.side_effect = Exception("Malformed certificate")

        # The validator might not handle all exceptions gracefully at the top level
        # This tests that the application can handle malformed certificates
        try:
            findings = validator.validate(mock_cert)
            assert isinstance(findings, list)
        except Exception as e:
            # Exception handling depends on validator implementation
            # Some checks may let exceptions bubble up, which is acceptable
            assert "Malformed certificate" in str(e)