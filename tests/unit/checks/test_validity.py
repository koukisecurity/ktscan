"""
Unit tests for certificate validity validation.
"""

from datetime import datetime, timedelta

from freezegun import freeze_time

from ktscan.models import ValidationSeverity
from ktscan.checks.VALIDITY import ValidityCheck


class TestValidityCheck:
    """Test ValidityCheck functionality"""

    def test_init_default_config(self):
        """Test validator initialization with default config"""
        validator = ValidityCheck()
        assert validator.config == {}
        assert validator.enabled is True

    def test_init_with_config(self):
        """Test validator initialization with custom config"""
        config = {"disabled_checks": ["CERT.EXPIRED"]}
        validator = ValidityCheck(config)
        assert validator.config == config
        assert validator.enabled is True

    @freeze_time("2024-06-15")
    def test_validate_certificate_validity_period_valid(self, cert_factory):
        """Test validation of valid certificate"""
        cert, _ = cert_factory.create_certificate(
            not_before=datetime(2024, 1, 1), not_after=datetime(2024, 12, 31)
        )

        validator = ValidityCheck()
        findings = validator._validate_certificate_validity_period(cert)

        # Should have no critical findings for valid certificate
        assert (
            len([f for f in findings if f.severity == ValidationSeverity.CRITICAL]) == 0
        )

    @freeze_time("2024-01-01")
    def test_validate_certificate_not_yet_valid(self, cert_factory):
        """Test validation of certificate not yet valid"""
        cert, _ = cert_factory.create_certificate(
            not_before=datetime(2024, 6, 1), not_after=datetime(2024, 12, 31)
        )

        validator = ValidityCheck()
        findings = validator._validate_certificate_validity_period(cert)

        not_yet_valid = [
            f for f in findings if f.check_id == "VALIDITY.NOT_YET_VALID"
        ]
        assert len(not_yet_valid) == 1
        assert not_yet_valid[0].severity == ValidationSeverity.CRITICAL
        assert "not yet valid" in not_yet_valid[0].description.lower()

    @freeze_time("2024-12-31")
    def test_validate_certificate_expired(self, cert_factory):
        """Test validation of expired certificate"""
        cert, _ = cert_factory.create_certificate(
            not_before=datetime(2024, 1, 1), not_after=datetime(2024, 6, 30)
        )

        validator = ValidityCheck()
        findings = validator._validate_certificate_validity_period(cert)

        expired = [f for f in findings if f.check_id == "VALIDITY.EXPIRED"]
        assert len(expired) == 1
        assert expired[0].severity == ValidationSeverity.CRITICAL
        assert "expired" in expired[0].description.lower()
        assert expired[0].evidence["expired_days"] > 0

    @freeze_time("2024-06-29")
    def test_validate_certificate_expires_very_soon(self, cert_factory):
        """Test validation of certificate expiring in 1 day"""
        cert, _ = cert_factory.create_certificate(
            not_before=datetime(2024, 1, 1), not_after=datetime(2024, 6, 30)
        )

        validator = ValidityCheck()
        findings = validator._validate_certificate_validity_period(cert)

        expires_very_soon = [
            f for f in findings if f.check_id == "VALIDITY.EXPIRES_VERY_SOON"
        ]
        assert len(expires_very_soon) == 1
        assert expires_very_soon[0].severity == ValidationSeverity.MEDIUM
        assert "expires" in expires_very_soon[0].description.lower()
        assert expires_very_soon[0].evidence["days_until_expiry"] == 1

    @freeze_time("2024-06-25")
    def test_validate_certificate_expires_soon(self, cert_factory):
        """Test validation of certificate expiring in 5 days"""
        cert, _ = cert_factory.create_certificate(
            not_before=datetime(2024, 1, 1), not_after=datetime(2024, 6, 30)
        )

        validator = ValidityCheck()
        findings = validator._validate_certificate_validity_period(cert)

        expires_soon = [f for f in findings if f.check_id == "VALIDITY.EXPIRES_SOON"]
        assert len(expires_soon) == 1
        assert expires_soon[0].severity == ValidationSeverity.MEDIUM
        assert "expires" in expires_soon[0].description.lower()
        assert expires_soon[0].evidence["days_until_expiry"] == 5

    @freeze_time("2024-06-15")
    def test_validate_certificate_expires_within_30_days(self, cert_factory):
        """Test validation of certificate expiring in 15 days"""
        cert, _ = cert_factory.create_certificate(
            not_before=datetime(2024, 1, 1), not_after=datetime(2024, 6, 30)
        )

        validator = ValidityCheck()
        findings = validator._validate_certificate_validity_period(cert)

        expires_30_days = [
            f for f in findings if f.check_id == "VALIDITY.EXPIRES_WITHIN_30_DAYS"
        ]
        assert len(expires_30_days) == 1
        assert expires_30_days[0].severity == ValidationSeverity.LOW
        assert "expires" in expires_30_days[0].description.lower()
        assert expires_30_days[0].evidence["days_until_expiry"] == 15

    def test_validate_certificate_lifetime_too_long_825_days(self, cert_factory):
        """Test validation of certificate with lifetime > 825 days"""
        cert, _ = cert_factory.create_certificate(
            not_before=datetime(2024, 1, 1),
            not_after=datetime(2024, 1, 1) + timedelta(days=900),
        )

        validator = ValidityCheck()
        findings = validator._validate_certificate_lifetime(cert)

        too_long = [
            f for f in findings if f.check_id == "VALIDITY.LIFETIME_TOO_LONG"
        ]
        assert len(too_long) == 1
        assert too_long[0].severity == ValidationSeverity.HIGH
        assert "lifetime" in too_long[0].description.lower()
        assert too_long[0].evidence["lifetime_days"] == 900
        assert too_long[0].evidence["max_allowed"] == 825

    def test_validate_certificate_lifetime_exceeds_398_days(self, cert_factory):
        """Test validation of certificate with lifetime > 398 days"""
        cert, _ = cert_factory.create_certificate(
            not_before=datetime(2024, 1, 1),
            not_after=datetime(2024, 1, 1) + timedelta(days=500),
        )

        validator = ValidityCheck()
        findings = validator._validate_certificate_lifetime(cert)

        exceeds_398 = [
            f for f in findings if f.check_id == "VALIDITY.LIFETIME_EXCEEDS_398_DAYS"
        ]
        assert len(exceeds_398) == 1
        assert exceeds_398[0].severity == ValidationSeverity.MEDIUM
        assert "398 days" in exceeds_398[0].description.lower() or "lifetime" in exceeds_398[0].description.lower()
        assert exceeds_398[0].evidence["lifetime_days"] == 500
        assert exceeds_398[0].evidence["recommended_max"] == 398

    def test_validate_certificate_lifetime_too_short(self, cert_factory):
        """Test validation of certificate with very short lifetime"""
        now = datetime(2024, 1, 1)
        cert, _ = cert_factory.create_certificate(
            not_before=now, not_after=now + timedelta(hours=12)
        )

        validator = ValidityCheck()
        findings = validator._validate_certificate_lifetime(cert)

        too_short = [
            f for f in findings if f.check_id == "VALIDITY.LIFETIME_TOO_SHORT"
        ]
        assert len(too_short) == 1
        assert too_short[0].severity == ValidationSeverity.HIGH
        assert "lifetime" in too_short[0].description.lower() and "short" in too_short[0].description.lower()
        assert too_short[0].evidence["lifetime_seconds"] == 43200.0