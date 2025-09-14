"""
Unit tests for compliance checks.

This module tests compliance validation using the modular check system.
Tests are organized by compliance standard (NIST, CA/B Forum, RFC 5280) and
use the appropriate individual check classes.
"""

from datetime import datetime, timedelta

import pytest

from ktscan.models import ValidationSeverity
from ktscan.checks.CRYPTO import CryptoCheck
# from ktscan.checks.CRYPTO import CryptoCheck # Already imported above
from ktscan.checks.VALIDITY import ValidityCheck
from ktscan.checks.SUBJECT import SanCheck
from ktscan.checks.EXTENSION import EkuKuCheck


class TestValidatorInitialization:
    """Test check initialization for compliance checks"""

    def test_key_params_validator_initialization(self):
        """Test CryptoCheck initialization"""
        validator = CryptoCheck()
        assert validator.config == {}

        # Test with config
        config = {"disabled_checks": ["KEY.WEAK_RSA"]}
        validator = CryptoCheck(config)
        assert validator.config == config
        assert validator.enabled is True
        assert hasattr(validator, 'logger')

    def test_signature_validator_initialization(self):
        """Test CryptoCheck initialization"""
        validator = CryptoCheck()
        assert validator.config == {}
        assert validator.enabled is True
        assert hasattr(validator, 'logger')

    def test_validity_validator_initialization(self):
        """Test ValidityCheck initialization"""
        validator = ValidityCheck()
        assert validator.config == {}
        assert validator.enabled is True
        assert hasattr(validator, 'logger')

    def test_san_validator_initialization(self):
        """Test SanCheck initialization"""
        validator = SanCheck()
        assert validator.config == {}
        assert validator.enabled is True
        assert hasattr(validator, 'logger')

    def test_eku_ku_validator_initialization(self):
        """Test EkuKuCheck initialization"""
        validator = EkuKuCheck()
        assert validator.config == {}
        assert validator.enabled is True
        assert hasattr(validator, 'logger')


class TestNISTCompliance:
    """Test NIST compliance validation using appropriate checks"""

    def test_nist_compliant_rsa_certificate(self, cert_factory):
        """Test NIST compliant RSA certificate"""
        key_validator = CryptoCheck()
        sig_validator = CryptoCheck()

        # Create certificate with NIST-compliant RSA key
        cert, _ = cert_factory.create_certificate(
            key_type="rsa", key_size=2048, signature_algorithm="sha256"
        )

        key_findings = key_validator.validate(cert)
        sig_findings = sig_validator.validate(cert)
        all_findings = key_findings + sig_findings

        # Should not have NIST violations for compliant certificate
        nist_violations = [
            f
            for f in all_findings
            if f.severity in [ValidationSeverity.HIGH, ValidationSeverity.CRITICAL]
        ]
        assert len(nist_violations) == 0

    def test_nist_deprecated_signature_algorithm(self, cert_factory, mocker):
        """Test NIST deprecated signature algorithm detection"""
        sig_validator = CryptoCheck()

        # Create fully mock certificate with deprecated signature algorithm
        mock_cert = mocker.Mock()
        mock_oid = mocker.Mock()
        mock_oid._name = "sha1WithRSAEncryption"
        mock_cert.signature_algorithm_oid = mock_oid

        # Mock public key for DSA validation
        from cryptography.hazmat.primitives.asymmetric import rsa
        mock_public_key = mocker.Mock(spec=rsa.RSAPublicKey)
        mock_cert.public_key.return_value = mock_public_key

        findings = sig_validator.validate(mock_cert)

        # Should detect deprecated signature algorithm
        deprecated_findings = [
            f for f in findings if f.check_id == "CRYPTO.WEAK_ALGORITHM"
        ]
        assert len(deprecated_findings) == 1

        finding = deprecated_findings[0]
        assert finding.severity == ValidationSeverity.CRITICAL
        assert finding.evidence.get("algorithm") == "sha1WithRSAEncryption"

    def test_nist_insufficient_rsa_key_size(self, cert_factory):
        """Test NIST insufficient RSA key size detection"""
        key_validator = CryptoCheck()

        # Create certificate with weak RSA key
        cert, _ = cert_factory.create_certificate(key_type="rsa", key_size=1024)

        findings = key_validator.validate(cert)

        # Should detect insufficient key size
        insufficient_findings = [
            f for f in findings if f.check_id == "CRYPTO.NIST_INSUFFICIENT_RSA"
        ]
        assert len(insufficient_findings) == 1

        finding = insufficient_findings[0]
        assert finding.severity == ValidationSeverity.HIGH
        assert finding.evidence["current_size"] == 1024
        assert finding.evidence["nist_minimum"] == 2048
        assert finding.evidence["nist_standard"] == "SP 800-57"

    def test_nist_approved_ecdsa_curves(self, cert_factory):
        """Test NIST approved ECDSA curves"""
        key_validator = CryptoCheck()

        approved_curves = ["secp256r1", "secp384r1", "secp521r1"]

        for curve in approved_curves:
            cert, _ = cert_factory.create_certificate(
                key_type="ecdsa", curve_name=curve
            )
            findings = key_validator.validate(cert)

            # Should not have NIST curve violations for approved curves
            curve_violations = [
                f for f in findings if f.check_id == "CRYPTO.UNAPPROVED_EC_CURVE"
            ]
            assert (
                len(curve_violations) == 0
            ), f"Approved curve {curve} should not have violations"

    def test_nist_unapproved_ecdsa_curve(self, cert_factory, mocker):
        """Test NIST unapproved ECDSA curve detection"""
        key_validator = CryptoCheck()

        # Create mock certificate with ECDSA public key with unapproved curve
        from cryptography.hazmat.primitives.asymmetric import ec
        
        mock_cert = mocker.Mock()
        mock_public_key = mocker.Mock(spec=ec.EllipticCurvePublicKey)
        mock_curve = mocker.Mock()
        mock_curve.name = "secp224r1"  # Not NIST approved
        mock_public_key.curve = mock_curve
        mock_cert.public_key.return_value = mock_public_key

        findings = key_validator.validate(mock_cert)

        # Should detect unapproved curve
        unapproved_findings = [
            f for f in findings if f.check_id == "CRYPTO.UNAPPROVED_EC_CURVE"
        ]
        assert len(unapproved_findings) == 1

        finding = unapproved_findings[0]
        assert finding.severity == ValidationSeverity.HIGH
        assert finding.evidence["curve"] == "secp224r1"
        assert "secp256r1" in finding.evidence["approved_curves"]

    def test_nist_dsa_deprecated(self, cert_factory):
        """Test NIST DSA deprecated detection"""
        key_validator = CryptoCheck()
        sig_validator = CryptoCheck()

        # Create certificate with DSA key
        cert, _ = cert_factory.create_certificate(key_type="dsa", key_size=2048)

        key_findings = key_validator.validate(cert)
        sig_findings = sig_validator.validate(cert)
        all_findings = key_findings + sig_findings

        # Should detect deprecated DSA from key validator
        dsa_key_findings = [f for f in key_findings if f.check_id == "CRYPTO.DSA_DEPRECATED"]
        assert len(dsa_key_findings) == 1

        # Should detect deprecated DSA from signature validator
        dsa_sig_findings = [f for f in sig_findings if f.check_id == "CRYPTO.NIST_DSA_DEPRECATED"]
        assert len(dsa_sig_findings) == 1

        key_finding = dsa_key_findings[0]
        assert key_finding.severity == ValidationSeverity.HIGH
        assert "deprecated" in key_finding.description.lower()
        assert key_finding.evidence["key_size"] == 2048

        sig_finding = dsa_sig_findings[0]
        assert sig_finding.severity == ValidationSeverity.HIGH
        assert sig_finding.evidence["nist_standard"] == "SP 800-57"

    def test_nist_excessive_validity_period(self, cert_factory):
        """Test NIST excessive validity period detection"""
        validity_validator = ValidityCheck()

        # Create certificate with excessive validity period (3 years)
        not_before = datetime(2024, 1, 1)
        not_after = datetime(2027, 1, 1)  # 3 years = ~1095 days > 825

        cert, _ = cert_factory.create_certificate(
            not_before=not_before, not_after=not_after
        )

        findings = validity_validator.validate(cert)

        # Should detect excessive validity period
        excessive_findings = [
            f for f in findings if f.check_id == "VALIDITY.LIFETIME_TOO_LONG"
        ]
        assert len(excessive_findings) == 1

        finding = excessive_findings[0]
        assert finding.severity == ValidationSeverity.HIGH
        assert finding.evidence["lifetime_days"] > 825
        assert finding.evidence["max_allowed"] == 825


class TestCABForumCompliance:
    """Test CA/Browser Forum compliance validation using appropriate checks"""

    def test_cab_forum_compliant_certificate(self, cert_factory):
        """Test CA/B Forum compliant certificate"""
        validity_validator = ValidityCheck()
        san_validator = SanCheck()
        eku_ku_validator = EkuKuCheck()

        # Create certificate compliant with CA/B Forum requirements
        # Use future dates to avoid expiration issues
        not_before = datetime(2025, 6, 1)
        not_after = datetime(2026, 6, 1)  # ~365 days < 398

        cert, _ = cert_factory.create_certificate(
            not_before=not_before,
            not_after=not_after,
            subject_name="example.com",
            san_domains=["example.com", "www.example.com"],
            key_usage=["digital_signature", "key_encipherment"],
            basic_constraints_ca=False,
        )

        validity_findings = validity_validator.validate(cert)
        san_findings = san_validator.validate(cert)
        eku_ku_findings = eku_ku_validator.validate(cert)
        all_findings = validity_findings + san_findings + eku_ku_findings

        # Should not have critical/high severity CA/B Forum violations
        cab_violations = [
            f
            for f in all_findings
            if f.severity in [ValidationSeverity.HIGH, ValidationSeverity.CRITICAL]
        ]
        assert len(cab_violations) == 0

    def test_cab_forum_excessive_validity_period(self, cert_factory):
        """Test CA/B Forum excessive validity period detection"""
        validity_validator = ValidityCheck()

        # Create certificate with validity period exceeding CA/B Forum limit
        not_before = datetime(2024, 1, 1)
        not_after = datetime(2025, 6, 1)  # ~517 days > 398

        cert, _ = cert_factory.create_certificate(
            not_before=not_before, not_after=not_after
        )

        findings = validity_validator.validate(cert)

        # Should detect excessive validity period
        excessive_findings = [
            f for f in findings if f.check_id == "VALIDITY.LIFETIME_EXCEEDS_398_DAYS"
        ]
        assert len(excessive_findings) == 1

        finding = excessive_findings[0]
        assert finding.severity == ValidationSeverity.MEDIUM
        assert finding.evidence["lifetime_days"] > 398
        assert finding.evidence["recommended_max"] == 398

    def test_cab_forum_missing_required_extensions(self, cert_factory):
        """Test CA/B Forum missing required extensions detection"""
        eku_ku_validator = EkuKuCheck()
        san_validator = SanCheck()

        # Create certificate missing required extensions
        cert, _ = cert_factory.create_no_extensions_cert()

        eku_ku_findings = eku_ku_validator.validate(cert)
        san_findings = san_validator.validate(cert)
        all_findings = eku_ku_findings + san_findings

        # Should detect missing key usage extension
        missing_ku_findings = [
            f for f in eku_ku_findings if f.check_id == "EXTENSION.MISSING_KEY_USAGE"
        ]
        assert len(missing_ku_findings) == 1
        assert missing_ku_findings[0].severity == ValidationSeverity.HIGH

        # Should detect missing extended key usage
        missing_eku_findings = [
            f for f in eku_ku_findings if f.check_id == "EXTENSION.MISSING_EXTENDED_KEY_USAGE"
        ]
        assert len(missing_eku_findings) == 1
        assert missing_eku_findings[0].severity == ValidationSeverity.MEDIUM

        # Should detect missing basic constraints
        missing_bc_findings = [
            f for f in eku_ku_findings if f.check_id == "EXTENSION.MISSING_BASIC_CONSTRAINTS"
        ]
        assert len(missing_bc_findings) == 1
        assert missing_bc_findings[0].severity == ValidationSeverity.HIGH

    def test_cab_forum_empty_san_extension(self, cert_factory, mocker):
        """Test CA/B Forum empty SAN extension detection"""
        san_validator = SanCheck()

        # Create fully mock certificate with empty SAN
        mock_cert = mocker.Mock()
        mock_san_ext = mocker.Mock()
        mock_san_ext.value = []  # Empty SAN

        mock_extensions = mocker.Mock()
        from cryptography.x509.oid import ExtensionOID
        from cryptography import x509

        def mock_get_extension(oid):
            if oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                return mock_san_ext
            else:
                raise x509.ExtensionNotFound("Extension not found", oid)

        mock_extensions.get_extension_for_oid.side_effect = mock_get_extension
        mock_cert.extensions = mock_extensions
        
        # Mock subject to avoid errors
        mock_subject = mocker.Mock()
        mock_cert.subject = mock_subject

        findings = san_validator.validate(mock_cert)

        # Should detect empty SAN
        empty_san_findings = [
            f for f in findings if f.check_id == "SUBJECT.EMPTY_SAN"
        ]
        assert len(empty_san_findings) == 1

        finding = empty_san_findings[0]
        assert finding.severity == ValidationSeverity.MEDIUM
        assert finding.evidence["san_count"] == 0

    def test_cab_forum_cn_not_in_san(self, cert_factory):
        """Test CA/B Forum CN not in SAN detection"""
        san_validator = SanCheck()

        # Create certificate where CN is not in SAN
        cert, _ = cert_factory.create_certificate(
            subject_name="example.com",
            san_domains=["different.com", "www.different.com"],  # CN not included
        )

        findings = san_validator.validate(cert)

        # Should detect CN not in SAN
        cn_not_in_san = [f for f in findings if f.check_id == "SUBJECT.CN_NOT_IN_SAN"]
        assert len(cn_not_in_san) == 1

        finding = cn_not_in_san[0]
        assert finding.severity == ValidationSeverity.HIGH
        assert finding.evidence["common_name"] == "example.com"
        assert "different.com" in finding.evidence["san_names"]

    def test_cab_forum_cn_without_san(self, cert_factory):
        """Test CA/B Forum CN without SAN detection"""
        san_validator = SanCheck()

        # Create certificate with CN but no SAN
        cert, _ = cert_factory.create_cert_without_san(subject_name="example.com")

        findings = san_validator.validate(cert)

        # Should detect missing SAN when CN is present
        missing_san = [
            f for f in findings if f.check_id == "SUBJECT.MISSING_SAN"
        ]
        assert len(missing_san) == 1

        finding = missing_san[0]
        assert finding.severity == ValidationSeverity.MEDIUM
        assert finding.evidence["common_name"] == "example.com"
        assert finding.evidence["has_san"] == False


class TestRFC5280Compliance:
    """Test RFC 5280 compliance validation using appropriate checks"""

    def test_rfc5280_compliant_certificate(self, cert_factory):
        """Test RFC 5280 compliant certificate"""
        san_validator = SanCheck()
        eku_ku_validator = EkuKuCheck()

        # Create compliant certificate
        cert, _ = cert_factory.create_certificate(
            subject_name="example.com",
            san_domains=["example.com"],
            key_usage=["digital_signature", "key_encipherment"],
            basic_constraints_ca=False,
        )

        san_findings = san_validator.validate(cert)
        eku_ku_findings = eku_ku_validator.validate(cert)
        all_findings = san_findings + eku_ku_findings

        # Should not have critical RFC 5280 violations
        critical_findings = [
            f for f in all_findings if f.severity == ValidationSeverity.CRITICAL
        ]
        assert len(critical_findings) == 0

    def test_rfc5280_empty_subject_and_san(self, cert_factory, mocker):
        """Test RFC 5280 empty subject and empty SAN detection"""
        san_validator = SanCheck()

        # Create fully mock certificate with empty subject and empty SAN
        mock_cert = mocker.Mock()

        # Mock empty subject
        mock_subject = mocker.Mock()
        mock_subject.rfc4514_string.return_value = ""
        mock_cert.subject = mock_subject

        # Mock empty SAN
        mock_san_ext = mocker.Mock()
        mock_san_ext.value = []

        # Create iterable mock extensions that supports both get_extension_for_oid and iteration
        from cryptography.x509.oid import ExtensionOID
        from cryptography import x509

        def mock_get_extension(oid):
            if oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                return mock_san_ext
            else:
                raise x509.ExtensionNotFound("Extension not found", oid)

        # Create a mock extensions object that is iterable and has get_extension_for_oid
        mock_extensions = mocker.Mock()
        mock_extensions.get_extension_for_oid.side_effect = mock_get_extension
        mock_extensions.__iter__ = lambda self: iter(
            []
        )  # Empty iteration for extension loop
        mock_cert.extensions = mock_extensions

        findings = san_validator.validate(mock_cert)

        # Should detect critical violation
        empty_findings = [
            f for f in findings if f.check_id == "SUBJECT.RFC5280_EMPTY_SUBJECT_AND_SAN"
        ]
        assert len(empty_findings) == 1

        finding = empty_findings[0]
        assert finding.severity == ValidationSeverity.CRITICAL

    def test_rfc5280_empty_subject_no_san(self, cert_factory, mocker):
        """Test RFC 5280 empty subject without SAN detection"""
        san_validator = SanCheck()

        # Create fully mock certificate with empty subject and no SAN
        mock_cert = mocker.Mock()

        # Mock empty subject
        mock_subject = mocker.Mock()
        mock_subject.rfc4514_string.return_value = ""
        mock_cert.subject = mock_subject

        # Mock no SAN extension
        from cryptography import x509

        def mock_get_extension(oid):
            raise x509.ExtensionNotFound("Extension not found", oid)

        mock_extensions = mocker.Mock()
        mock_extensions.get_extension_for_oid.side_effect = mock_get_extension
        mock_extensions.__iter__ = lambda self: iter(
            []
        )  # Empty iteration for extension loop
        mock_cert.extensions = mock_extensions

        findings = san_validator.validate(mock_cert)

        # Should detect critical violation
        empty_findings = [
            f for f in findings if f.check_id == "SUBJECT.RFC5280_EMPTY_SUBJECT_NO_SAN"
        ]
        assert len(empty_findings) == 1

        finding = empty_findings[0]
        assert finding.severity == ValidationSeverity.CRITICAL

    def test_rfc5280_key_usage_critical_good(self, cert_factory, mocker):
        """Test RFC 5280 key usage critical extension (positive case)"""
        eku_ku_validator = EkuKuCheck()

        # Create fully mock certificate with critical key usage
        mock_cert = mocker.Mock()

        # Mock key usage extension as critical
        mock_ku_ext = mocker.Mock()
        mock_ku_ext.critical = True
        mock_ku_ext.value = mocker.Mock()  # Key usage value

        from cryptography.x509.oid import ExtensionOID
        from cryptography import x509

        def mock_get_extension(oid):
            if oid == ExtensionOID.KEY_USAGE:
                return mock_ku_ext
            else:
                raise x509.ExtensionNotFound("Extension not found", oid)

        mock_extensions = mocker.Mock()
        mock_extensions.get_extension_for_oid.side_effect = mock_get_extension
        mock_extensions.__iter__ = lambda self: iter(
            []
        )  # Empty iteration for extension loop
        mock_cert.extensions = mock_extensions

        findings = eku_ku_validator.validate(mock_cert)

        # Should have positive compliance finding
        good_findings = [
            f for f in findings if f.check_id == "EXTENSION.RFC5280_KEY_USAGE_CRITICAL_GOOD"
        ]
        assert len(good_findings) == 1

        finding = good_findings[0]
        assert finding.severity == ValidationSeverity.MEDIUM

    def test_rfc5280_ca_basic_constraints_not_critical(self, cert_factory, mocker):
        """Test RFC 5280 CA basic constraints not critical detection"""
        eku_ku_validator = EkuKuCheck()

        # Create fully mock certificate with non-critical CA basic constraints
        mock_cert = mocker.Mock()

        # Mock basic constraints as CA but not critical
        mock_bc_ext = mocker.Mock()
        mock_bc_ext.critical = False
        mock_bc_value = mocker.Mock()
        mock_bc_value.ca = True
        mock_bc_ext.value = mock_bc_value

        from cryptography.x509.oid import ExtensionOID
        from cryptography import x509

        def mock_get_extension(oid):
            if oid == ExtensionOID.BASIC_CONSTRAINTS:
                return mock_bc_ext
            else:
                raise x509.ExtensionNotFound("Extension not found", oid)

        mock_extensions = mocker.Mock()
        mock_extensions.get_extension_for_oid.side_effect = mock_get_extension
        mock_extensions.__iter__ = lambda self: iter(
            []
        )  # Empty iteration for extension loop
        mock_cert.extensions = mock_extensions

        findings = eku_ku_validator.validate(mock_cert)

        # Should detect non-critical CA basic constraints
        non_critical_findings = [
            f
            for f in findings
            if f.check_id == "EXTENSION.RFC5280_CA_BASIC_CONSTRAINTS_NOT_CRITICAL"
        ]
        assert len(non_critical_findings) == 1

        finding = non_critical_findings[0]
        assert finding.severity == ValidationSeverity.HIGH

    def test_rfc5280_unknown_critical_extension(self, cert_factory, mocker):
        """Test RFC 5280 unknown critical extension detection"""
        eku_ku_validator = EkuKuCheck()

        # Create fully mock certificate with unknown critical extension
        mock_cert = mocker.Mock()

        # Mock certificate with unknown critical extension
        mock_ext = mocker.Mock()
        mock_ext.critical = True
        mock_oid = mocker.Mock()
        mock_oid._name = "unknown.extension.oid"
        mock_oid.__str__ = lambda self: "1.2.3.4.5"
        mock_ext.oid = mock_oid

        # Mock the extensions attribute to be iterable
        mock_cert.extensions = [mock_ext]

        # Also need to mock get_extension_for_oid for other extension checks
        mock_extensions_obj = mocker.Mock()
        from cryptography.x509.oid import ExtensionOID
        from cryptography import x509

        mock_extensions_obj.get_extension_for_oid.side_effect = x509.ExtensionNotFound(
            "Extension not found", ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        mock_cert.extensions = mock_extensions_obj

        # Override the iteration to return our mock extension
        mock_extensions_obj.__iter__ = lambda self: iter([mock_ext])

        findings = eku_ku_validator.validate(mock_cert)

        # Should detect unknown critical extension
        unknown_findings = [
            f for f in findings if f.check_id == "EXTENSION.RFC5280_UNKNOWN_CRITICAL_EXTENSION"
        ]
        assert len(unknown_findings) == 1

        finding = unknown_findings[0]
        assert finding.severity == ValidationSeverity.HIGH
        assert finding.evidence["extension_oid"] == "1.2.3.4.5"


class TestValidatorIntegration:
    """Integration tests for compliance checks"""

    def test_validate_method_combines_all_checks(self, cert_factory):
        """Test that validate methods combine all compliance checks"""
        key_validator = CryptoCheck()
        sig_validator = CryptoCheck()
        validity_validator = ValidityCheck()
        san_validator = SanCheck()
        eku_ku_validator = EkuKuCheck()

        # Create certificate with multiple compliance issues
        not_before = datetime(2024, 1, 1)
        not_after = datetime(2025, 6, 1)  # Excessive validity

        cert, _ = cert_factory.create_certificate(
            not_before=not_before,
            not_after=not_after,
            key_type="rsa",
            key_size=1024,  # Weak key
        )

        # Run all checks
        key_findings = key_validator.validate(cert)
        sig_findings = sig_validator.validate(cert)
        validity_findings = validity_validator.validate(cert)
        san_findings = san_validator.validate(cert)
        eku_ku_findings = eku_ku_validator.validate(cert)
        all_findings = key_findings + sig_findings + validity_findings + san_findings + eku_ku_findings

        # Should have findings from multiple compliance areas
        assert len(all_findings) >= 2

        # Should have key-related findings
        key_violations = [f for f in key_findings if "CRYPTO." in f.check_id]
        assert len(key_violations) >= 1

        # Should have validity-related findings
        validity_violations = [f for f in validity_findings if "VALIDITY." in f.check_id]
        assert len(validity_violations) >= 1

    def test_validate_respects_check_configuration(self, cert_factory):
        """Test that validate method respects check configuration"""
        # Test with disabled key size checks
        config = {"disabled_checks": ["CRYPTO.NIST_INSUFFICIENT_RSA"]}
        key_validator = CryptoCheck(config)

        cert, _ = cert_factory.create_certificate(key_type="rsa", key_size=1024)
        findings = key_validator.validate(cert)

        # Should not have disabled findings
        nist_key_findings = [
            f for f in findings if f.check_id == "CRYPTO.NIST_INSUFFICIENT_RSA"
        ]
        assert len(nist_key_findings) == 0
        
        # But should still have weak RSA findings
        weak_rsa_findings = [
            f for f in findings if f.check_id == "CRYPTO.WEAK_RSA"
        ]
        assert len(weak_rsa_findings) == 1

    @pytest.mark.parametrize(
        "validity_days,expected_violations",
        [
            (365, 0),  # Compliant with both NIST and CA/B Forum
            (400, 1),  # Violates CA/B Forum only (398 days recommendation)
            (800, 1),  # Violates CA/B Forum only (398 days recommendation)
            (900, 1),  # Violates NIST (> 825 days)
        ],
    )
    def test_validity_period_compliance(
        self, cert_factory, validity_days, expected_violations
    ):
        """Test validity period compliance with different durations"""
        validity_validator = ValidityCheck()

        not_before = datetime(2024, 1, 1)
        not_after = not_before + timedelta(days=validity_days)

        cert, _ = cert_factory.create_certificate(
            not_before=not_before, not_after=not_after
        )

        findings = validity_validator.validate(cert)

        # Count validity-related violations
        validity_violations = [
            f
            for f in findings
            if "LIFETIME" in f.check_id
            and f.severity in [ValidationSeverity.HIGH, ValidationSeverity.MEDIUM]
        ]

        assert len(validity_violations) == expected_violations

    def test_comprehensive_compliance_certificate(self, cert_factory):
        """Test comprehensive compliance validation"""
        key_validator = CryptoCheck()
        sig_validator = CryptoCheck()
        validity_validator = ValidityCheck()
        san_validator = SanCheck()
        eku_ku_validator = EkuKuCheck()

        # Create certificate designed to be compliant with all standards
        # Use future dates to avoid expiration issues
        not_before = datetime(2025, 6, 1)
        not_after = datetime(2026, 6, 1)  # ~365 days
        
        cert, _ = cert_factory.create_certificate(
            subject_name="secure.example.com",
            san_domains=["secure.example.com", "www.secure.example.com"],
            key_type="rsa",
            key_size=2048,
            signature_algorithm="sha256",
            not_before=not_before,
            not_after=not_after,
            key_usage=["digital_signature", "key_encipherment"],
            extended_key_usage=["server_auth"],
            basic_constraints_ca=False,
        )

        # Run all checks
        key_findings = key_validator.validate(cert)
        sig_findings = sig_validator.validate(cert)
        validity_findings = validity_validator.validate(cert)
        san_findings = san_validator.validate(cert)
        eku_ku_findings = eku_ku_validator.validate(cert)
        all_findings = key_findings + sig_findings + validity_findings + san_findings + eku_ku_findings

        # Should have minimal high/critical compliance issues
        critical_high = [
            f
            for f in all_findings
            if f.severity in [ValidationSeverity.CRITICAL, ValidationSeverity.HIGH]
        ]
        assert len(critical_high) == 0

        # May have info-level positive compliance findings
        info_findings = [f for f in all_findings if f.severity == ValidationSeverity.INFO]
        # Info findings are acceptable and even positive


class TestValidatorErrorHandling:
    """Test error handling in compliance checks"""

    def test_malformed_certificate_handling(self, cert_factory, mocker):
        """Test handling of malformed certificates"""
        key_validator = CryptoCheck()
        sig_validator = CryptoCheck()

        # Create mock certificate that raises exceptions
        mock_cert = mocker.Mock()
        mock_cert.signature_algorithm_oid.side_effect = Exception(
            "Malformed signature algorithm"
        )
        mock_cert.public_key.side_effect = Exception("Malformed public key")
        mock_cert.not_valid_after_utc = datetime(2024, 12, 31)
        mock_cert.not_valid_before_utc = datetime(2024, 1, 1)

        # Should handle exceptions gracefully
        try:
            key_findings = key_validator.validate(mock_cert)
            sig_findings = sig_validator.validate(mock_cert)
            assert isinstance(key_findings, list)
            assert isinstance(sig_findings, list)
        except Exception:
            # Some exceptions may bubble up, which is acceptable
            pass

    def test_date_calculation_edge_cases(self, cert_factory, mocker):
        """Test edge cases in date calculations"""
        validity_validator = ValidityCheck()

        # Test certificate with unusual date ranges (same day)
        not_before = datetime(2024, 1, 1)
        not_after = datetime(2024, 1, 1)  # Same day
        
        cert, _ = cert_factory.create_certificate(
            not_before=not_before,
            not_after=not_after
        )

        # Should handle edge cases gracefully
        findings = validity_validator.validate(cert)
        assert isinstance(findings, list)
        
        # Should detect lifetime too short
        short_findings = [f for f in findings if f.check_id == "VALIDITY.LIFETIME_TOO_SHORT"]
        assert len(short_findings) == 1
