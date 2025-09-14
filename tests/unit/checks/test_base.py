"""
Unit tests for base validator functionality.
"""

import pytest

from ktscan.models import (
    BaseCheck,
    ValidationFinding,
    ValidationSeverity,
    ValidationCheck,
    CheckInfo,
    ConfidenceLevel,
)


class MockValidator(BaseCheck):
    """Concrete implementation of BaseCheck for testing"""

    def get_check_info(self) -> CheckInfo:
        return CheckInfo(
            check_id="mock",
            title="Mock Validator",
            description="A mock validator for testing purposes"
        )

    def _register_checks(self) -> None:
        """Register test checks"""
        self.register_check(ValidationCheck(
            check_id="test_check",
            title="Test Check",
            description="This is a test finding"
        ))
        
        self.register_check(ValidationCheck(
            check_id="info_check",
            title="Info Check",
            description="This is an info finding",
            remediation="No action needed"
        ))

    def validate(self, certificate, context=None):
        findings = []

        # Example check that can be enabled/disabled
        if self.is_check_enabled("test_check"):
            findings.append(
                self.create_finding(
                    check_id="test_check"
                )
            )

        # Another example check
        if self.is_check_enabled("info_check"):
            findings.append(
                self.create_finding(
                    check_id="info_check",
                    evidence={"extra": "information"},
                )
            )

        return findings


class TestValidationSeverity:
    """Test ValidationSeverity enum"""

    def test_severity_values(self):
        """Test that severity enum has correct string values"""
        assert ValidationSeverity.CRITICAL.value == "CRITICAL"
        assert ValidationSeverity.HIGH.value == "HIGH"
        assert ValidationSeverity.MEDIUM.value == "MEDIUM"
        assert ValidationSeverity.LOW.value == "LOW"
        assert ValidationSeverity.INFO.value == "INFO"

    def test_severity_ordering(self):
        """Test that we can compare severities (useful for filtering)"""
        severities = [
            ValidationSeverity.INFO,
            ValidationSeverity.LOW,
            ValidationSeverity.MEDIUM,
            ValidationSeverity.HIGH,
            ValidationSeverity.CRITICAL,
        ]

        # Enum members can be compared by their definition order
        assert ValidationSeverity.CRITICAL != ValidationSeverity.HIGH
        assert ValidationSeverity.INFO != ValidationSeverity.CRITICAL


class TestValidationFinding:
    """Test ValidationFinding dataclass"""

    def test_basic_finding_creation(self):
        """Test creating a basic finding"""
        finding = ValidationFinding(
            check_id="test_check",
            severity=ValidationSeverity.MEDIUM,
            confidence=ConfidenceLevel.HIGH,
            title="Test Finding",
            description="This is a test finding",
        )

        assert finding.check_id == "test_check"
        assert finding.severity == ValidationSeverity.MEDIUM
        assert finding.title == "Test Finding"
        assert finding.description == "This is a test finding"
        assert finding.remediation is None
        assert finding.evidence == {}

    def test_finding_with_optional_fields(self):
        """Test creating finding with optional fields"""
        details = {"key": "value", "number": 42}
        finding = ValidationFinding(
            check_id="detailed_check",
            severity=ValidationSeverity.CRITICAL,
            confidence=ConfidenceLevel.HIGH,
            title="Critical Issue",
            description="Something is very wrong",
            remediation="Fix it immediately",
            evidence=details,
        )

        assert finding.remediation == "Fix it immediately"
        assert finding.evidence == details

    def test_finding_string_representation(self):
        """Test string representation of finding"""
        finding = ValidationFinding(
            check_id="test",
            severity=ValidationSeverity.LOW,
            confidence=ConfidenceLevel.HIGH,
            title="Test Title",
            description="Test description",
        )

        # ValidationFinding now has a different string representation
        finding_str = str(finding)
        assert "LOW" in finding_str
        assert "Test Title" in finding_str


class TestBaseCheck:
    """Test BaseCheck functionality"""

    def test_validator_with_no_config(self):
        """Test validator with default configuration"""
        validator = MockValidator()

        assert validator.config == {}
        assert validator.disabled_checks == set()
        assert validator.enabled is True

    def test_validator_with_config(self):
        """Test validator with configuration"""
        config = {
            "disabled_checks": ["check3", "check4"],
            "other_setting": "value",
        }
        validator = MockValidator(config)

        assert validator.config == config
        assert validator.disabled_checks == {"check3", "check4"}
        assert validator.enabled is True

    def test_is_check_enabled_with_no_restrictions(self):
        """Test check enabling with no enabled/disabled lists"""
        validator = MockValidator()

        # All checks should be enabled by default
        assert validator.is_check_enabled("any_check") is True
        
    def test_is_validator_enabled_default(self):
        """Test validator enabled by default"""
        validator = MockValidator()
        assert validator.enabled is True
        
    def test_is_validator_enabled_when_disabled(self):
        """Test validator when explicitly disabled"""
        config = {"disabled": True}
        validator = MockValidator(config)
        assert validator.enabled is False
        
    def test_is_check_enabled_when_validator_disabled(self):
        """Test that no checks are enabled when validator is disabled"""
        config = {"disabled": True}
        validator = MockValidator(config)
        assert validator.is_check_enabled("any_check") is False
        assert validator.is_check_enabled("another_check") is False

    def test_is_check_enabled_with_disabled_list(self):
        """Test check enabling with disabled checks list"""
        config = {"disabled_checks": ["disabled_check1", "disabled_check2"]}
        validator = MockValidator(config)

        # Disabled checks should return False
        assert validator.is_check_enabled("disabled_check1") is False
        assert validator.is_check_enabled("disabled_check2") is False

        # Other checks should be enabled
        assert validator.is_check_enabled("enabled_check") is True

    def test_is_check_enabled_all_enabled_by_default(self):
        """Test that all checks are enabled by default when no restrictions are set"""
        validator = MockValidator()

        # All checks should be enabled by default
        assert validator.is_check_enabled("any_check1") is True
        assert validator.is_check_enabled("any_check2") is True
        assert validator.is_check_enabled("other_check") is True

    def test_disabled_validator(self):
        """Test validator when explicitly disabled"""
        config = {"disabled": True}
        validator = MockValidator(config)
        
        assert validator.enabled is False
        # When validator is disabled, no checks should be enabled
        assert validator.is_check_enabled("any_check") is False

    def test_create_finding_basic(self):
        """Test creating a basic finding"""
        validator = MockValidator()
        finding = validator.create_finding(
            check_id="test_check"
        )

        assert isinstance(finding, ValidationFinding)
        assert finding.check_id == "test_check"
        assert finding.severity == ValidationSeverity.MEDIUM
        assert finding.title == "Test Check"
        assert finding.description == "This is a test finding"
        assert finding.remediation is None
        assert finding.evidence == {}

    def test_create_finding_with_optional_params(self):
        """Test creating finding with optional parameters"""
        validator = MockValidator()
        details = {"extra": "info"}
        finding = validator.create_finding(
            check_id="info_check",
            evidence=details,
        )

        assert finding.check_id == "info_check"
        assert finding.severity == ValidationSeverity.MEDIUM
        assert finding.title == "Info Check"
        assert finding.description == "This is an info finding"
        assert finding.remediation == "No action needed"
        assert finding.evidence == details

    def test_validate_method_with_enabled_checks(self, cert_factory):
        """Test validation method respects check configuration"""
        # Test with all checks enabled (default)
        validator = MockValidator()
        cert, _ = cert_factory.create_valid_cert()

        findings = validator.validate(cert)

        # Should have both test findings
        assert len(findings) == 2
        check_ids = [f.check_id for f in findings]
        assert "test_check" in check_ids
        assert "info_check" in check_ids

    def test_validate_method_with_disabled_checks(self, cert_factory):
        """Test validation with some checks disabled"""
        config = {"disabled_checks": ["test_check"]}
        validator = MockValidator(config)
        cert, _ = cert_factory.create_valid_cert()

        findings = validator.validate(cert)

        # Should only have info_check
        assert len(findings) == 1
        assert findings[0].check_id == "info_check"

    def test_validate_method_with_disabled_validator(self, cert_factory):
        """Test validation when validator is disabled"""
        config = {"disabled": True}
        validator = MockValidator(config)
        cert, _ = cert_factory.create_valid_cert()

        findings = validator.validate(cert)

        # Should have no findings when validator is disabled
        assert len(findings) == 0

    def test_validate_method_with_all_checks_disabled(self, cert_factory):
        """Test validation with all checks disabled"""
        config = {"disabled_checks": ["test_check", "info_check"]}
        validator = MockValidator(config)
        cert, _ = cert_factory.create_valid_cert()

        findings = validator.validate(cert)

        # Should have no findings
        assert len(findings) == 0


# Integration test to ensure the base validator works with real certificate objects
class TestBaseCheckIntegration:
    """Integration tests for BaseCheck with real certificates"""

    def test_validator_with_real_certificate(self, cert_factory):
        """Test that validator works with real certificate objects"""
        validator = MockValidator()
        cert, _ = cert_factory.create_valid_cert(subject_name="test.example.com")

        # Should not raise any exceptions
        findings = validator.validate(cert)
        assert isinstance(findings, list)

        # Test with context
        context = {"hostname": "test.example.com", "ip": "192.0.2.1", "port": 443}
        findings_with_context = validator.validate(cert, context)
        assert isinstance(findings_with_context, list)

    @pytest.mark.parametrize(
        "cert_type",
        [
            "valid",
            "expired",
            "future",
            "weak_rsa",
            "sha1",
            "self_signed",
            "no_extensions",
        ],
    )
    def test_validator_with_different_cert_types(self, cert_factory, cert_type):
        """Test validator works with different certificate types"""
        validator = MockValidator()

        # Get certificate based on type
        if cert_type == "valid":
            cert, _ = cert_factory.create_valid_cert()
        elif cert_type == "expired":
            cert, _ = cert_factory.create_expired_cert()
        elif cert_type == "future":
            cert, _ = cert_factory.create_future_cert()
        elif cert_type == "weak_rsa":
            cert, _ = cert_factory.create_weak_rsa_cert()
        elif cert_type == "sha1":
            cert, _ = cert_factory.create_sha1_cert()
        elif cert_type == "self_signed":
            cert, _ = cert_factory.create_self_signed_cert()
        elif cert_type == "no_extensions":
            cert, _ = cert_factory.create_no_extensions_cert()

        # Should not raise exceptions for any certificate type
        findings = validator.validate(cert)
        assert isinstance(findings, list)
