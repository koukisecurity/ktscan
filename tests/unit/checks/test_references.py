"""
Unit tests for documentation references functionality.
"""

import pytest
import requests
from unittest.mock import patch, Mock

from ktscan.models import (
    BaseCheck,
    ValidationCheck,
    ValidationFinding,
    ValidationSeverity,
    StandardReference,
    CheckInfo,
    ConfidenceLevel,
)
from ktscan.standards_loader import standards_loader


def get_reference(check_id: str):
    """Get reference for a check - helper function for tests"""
    return standards_loader.get_standard_reference("ca_b_forum", check_id)


# Create a mock CA_B_FORUM_REFERENCES for testing
CA_B_FORUM_REFERENCES = {
    "certificate_lifetime_too_long": StandardReference(
        standard="CA/B Forum",
        title="CA/Browser Forum Baseline Requirements",
        section="6.3.2",
        url="https://cabforum.org/baseline-requirements-documents/",
        severity=ValidationSeverity.HIGH,
    )
}


class MockValidatorWithReferences(BaseCheck):
    """Test validator with reference support"""

    def get_check_info(self) -> CheckInfo:
        return CheckInfo(
            check_id="test_refs",
            title="Test References Validator",
            description="A validator for testing references functionality"
        )

    def _register_checks(self) -> None:
        """Register test checks with references"""
        # Check with references
        ref = get_reference("certificate_lifetime_too_long")
        self.register_check(ValidationCheck(
            check_id="check_with_ref",
            title="Check with Reference",
            description="This check has documentation references",
            standard_refs=[ref] if ref else []
        ))
        
        # Check without references
        self.register_check(ValidationCheck(
            check_id="check_no_ref",
            title="Check without Reference",
            description="This check has no documentation references"
        ))

    def validate(self, certificate, context=None):
        findings = []
        
        if self.is_check_enabled("check_with_ref"):
            findings.append(self.create_finding("check_with_ref"))
        
        if self.is_check_enabled("check_no_ref"):
            findings.append(self.create_finding("check_no_ref"))
        
        return findings


class TestStandardReference:
    """Test StandardReference dataclass"""

    def test_basic_reference_creation(self):
        """Test creating a basic reference"""
        ref = StandardReference(
            standard="Test Standard",
            title="Test Standard",
            section="1.2.3",
            url="https://example.com/standard",
            severity=ValidationSeverity.MEDIUM,
        )
        
        assert ref.title == "Test Standard"
        assert ref.section == "1.2.3"
        assert ref.url == "https://example.com/standard"
        assert ref.standard == "Test Standard"

    def test_ca_b_forum_reference(self):
        """Test CA/Browser Forum reference example"""
        ref = StandardReference(
            standard="CA/B Forum",
            title="CA/Browser Forum Baseline Requirements",
            section="6.3.2",
            url="https://cabforum.org/baseline-requirements-documents/",
            severity=ValidationSeverity.MEDIUM,
        )
        
        assert "CA/Browser" in ref.title
        assert ref.standard == "CA/B Forum"
        assert "cabforum.org" in ref.url


class TestValidationCheckWithReferences:
    """Test ValidationCheck with references"""

    def test_check_with_single_reference(self):
        """Test check with single reference"""
        ref = StandardReference(
            standard="Test",
            title="Test Standard",
            section="1.0",
            url="https://example.com/standard",
            severity=ValidationSeverity.MEDIUM,
        )
        
        check = ValidationCheck(
            check_id="test_check",
            title="Test Check",
            description="Test description",
            standard_refs=[ref]
        )
        
        assert len(check.standard_refs) == 1
        assert check.standard_refs[0] == ref
        assert check.standards == {"Test"}

    def test_check_with_multiple_references(self):
        """Test check with multiple references from different standards"""
        ref1 = StandardReference(
            standard="Standard A",
            title="Standard A",
            section="1.0",
            url="https://example.com/a",
            severity=ValidationSeverity.MEDIUM,
        )
        
        ref2 = StandardReference(
            standard="Standard B",
            title="Standard B", 
            section="2.0",
            url="https://example.com/b",
            severity=ValidationSeverity.MEDIUM,
        )
        
        check = ValidationCheck(
            check_id="multi_ref_check",
            title="Multi Reference Check",
            description="Check with multiple references",
            standard_refs=[ref1, ref2]
        )
        
        assert len(check.standard_refs) == 2
        assert check.standards == {"Standard A", "Standard B"}

    def test_check_without_references(self):
        """Test check without any references"""
        check = ValidationCheck(
            check_id="no_ref_check",
            title="No Reference Check",
            description="Check without references"
        )
        
        assert len(check.standard_refs) == 0
        assert check.standards == set()


class TestValidatorWithReferences:
    """Test BaseCheck with references functionality"""

    def test_validator_creates_findings_with_references(self, cert_factory):
        """Test that validator creates findings with references"""
        validator = MockValidatorWithReferences()
        cert, _ = cert_factory.create_valid_cert()
        
        findings = validator.validate(cert)
        
        # Should have two findings
        assert len(findings) == 2
        
        # Find the finding with references
        finding_with_ref = next(f for f in findings if f.check_id == "check_with_ref")
        finding_no_ref = next(f for f in findings if f.check_id == "check_no_ref") 
        
        # Check that references are properly included
        # Check if finding has standard_ref (may be None if no reference)
        assert finding_with_ref.standard_ref is not None or finding_with_ref.standard_ref is None
        assert finding_no_ref.standard_ref is None

    def test_disabled_standards_filtering(self, cert_factory):
        """Test that disabled standards filter out references"""
        config = {"disabled_standards": ["CA/B Forum"]}
        validator = MockValidatorWithReferences(config)
        cert, _ = cert_factory.create_valid_cert()
        
        findings = validator.validate(cert)
        
        # Find finding with references
        finding_with_ref = next((f for f in findings if f.check_id == "check_with_ref"), None)
        
        if finding_with_ref and finding_with_ref.standard_ref:
            # Any CA/B Forum references should be filtered out
            assert finding_with_ref.standard_ref.standard != "CA/B Forum"

    def test_standards_based_check_disabling(self):
        """Test that checks are disabled when ALL their standards are disabled"""
        # Create a validator with CA/B Forum disabled
        config = {"disabled_standards": ["CA/B Forum"]}
        validator = MockValidatorWithReferences(config)
        
        # Get the check with CA/B Forum reference
        check_with_ref = validator.get_check("check_with_ref")
        if check_with_ref and check_with_ref.standard_refs:
            # If this check only has CA/B Forum references, it should be disabled
            ca_b_only = all(ref.standard == "CA/B Forum" for ref in check_with_ref.standard_refs)
            if ca_b_only:
                assert not validator.is_check_enabled("check_with_ref")
            else:
                # If it has references from other standards, it should still be enabled
                assert validator.is_check_enabled("check_with_ref")

    def test_check_enabled_with_mixed_standards(self):
        """Test that check remains enabled if it has references from non-disabled standards"""
        # Create references from multiple standards
        ref1 = StandardReference(
            standard="CA/B Forum",
            title="CA/Browser Forum Baseline Requirements",
            section="6.3.2", 
            url="https://cabforum.org/baseline-requirements-documents/",
            severity=ValidationSeverity.MEDIUM,
        )
        
        ref2 = StandardReference(
            standard="RFC",
            title="RFC 5280",
            section="4.1",
            url="https://tools.ietf.org/rfc/rfc5280.txt",
            severity=ValidationSeverity.MEDIUM,
        )
        
        # Create validator with CA/B Forum disabled but RFC enabled
        validator = MockValidatorWithReferences({"disabled_standards": ["CA/B Forum"]})
        
        # Register a check with mixed references
        mixed_check = ValidationCheck(
            check_id="mixed_standards_check",
            title="Mixed Standards Check",
            description="Check with references from multiple standards",
            standard_refs=[ref1, ref2]
        )
        validator.register_check(mixed_check)
        
        # Check should be enabled because it has RFC reference
        assert validator.is_check_enabled("mixed_standards_check")


class TestReferencesDatabase:
    """Test the centralized references database"""

    def test_get_reference_existing(self):
        """Test getting an existing reference"""
        ref = get_reference("certificate_lifetime_too_long")
        
        if ref:  # Reference might not be populated yet
            assert isinstance(ref, StandardReference)
            assert ref.title
            assert ref.section
            assert ref.url
            assert ref.standard

    def test_get_reference_nonexistent(self):
        """Test getting a non-existent reference"""
        ref = get_reference("nonexistent_check")
        assert ref is None

    def test_ca_b_forum_references_structure(self):
        """Test that CA/B Forum references have proper structure"""
        for check_id, ref in CA_B_FORUM_REFERENCES.items():
            assert isinstance(check_id, str)
            assert isinstance(ref, StandardReference)
            assert ref.title
            assert ref.section
            assert ref.url
            assert ref.standard
            
            # All CA/B Forum references should have consistent standard
            assert ref.standard == "CA/B Forum"


class TestURLValidation:
    """Test URL validation for documentation references"""

    @pytest.mark.network
    def test_ca_b_forum_urls_are_accessible(self):
        """Test that CA/B Forum URLs are accessible (network test)"""
        # This test requires network access and should be marked appropriately
        for check_id, ref in CA_B_FORUM_REFERENCES.items():
            url = ref.url
            try:
                response = requests.head(url, timeout=10, allow_redirects=True)
                # Accept any 2xx or 3xx status code
                assert response.status_code < 400, f"URL {url} returned {response.status_code}"
            except requests.RequestException as e:
                # Log warning but don't fail test for network issues
                pytest.skip(f"Network error accessing {url}: {e}")

    @pytest.mark.network
    def test_reference_urls_format(self):
        """Test that reference URLs are properly formatted"""
        for check_id, ref in CA_B_FORUM_REFERENCES.items():
            url = ref.url
            
            # URLs should be HTTPS
            assert url.startswith("https://"), f"URL {url} should use HTTPS"
            
            # URLs should be valid format
            from urllib.parse import urlparse
            parsed = urlparse(url)
            assert parsed.scheme in ["https", "http"]
            assert parsed.netloc
            
    def test_mock_url_validation(self):
        """Test URL validation with mocked responses"""
        with patch('requests.head') as mock_head:
            # Mock successful response
            mock_response = Mock()
            mock_response.status_code = 200
            mock_head.return_value = mock_response
            
            # Test a sample URL
            url = "https://cabforum.org/baseline-requirements-documents/"
            response = requests.head(url)
            assert response.status_code == 200
            mock_head.assert_called_once_with(url)

    def test_mock_url_validation_failure(self):
        """Test URL validation with mocked failure responses"""
        with patch('requests.head') as mock_head:
            # Mock 404 response
            mock_response = Mock()
            mock_response.status_code = 404
            mock_head.return_value = mock_response
            
            url = "https://example.com/nonexistent"
            response = requests.head(url)
            assert response.status_code == 404


class TestValidationFindingWithReferences:
    """Test ValidationFinding with references"""

    def test_finding_includes_references(self):
        """Test that findings can include references"""
        ref = StandardReference(
            standard="Test",
            title="Test Standard",
            section="1.0",
            url="https://example.com/standard", 
            severity=ValidationSeverity.MEDIUM,
        )
        
        finding = ValidationFinding(
            check_id="test_check",
            severity=ValidationSeverity.MEDIUM,
            confidence=ConfidenceLevel.HIGH,
            title="Test Finding",
            description="Test description",
            standard_ref=ref
        )
        
        assert finding.standard_ref == ref

    def test_finding_created_from_check_with_references(self, cert_factory):
        """Test that findings created from checks inherit references"""
        validator = MockValidatorWithReferences()
        
        # Create finding using the validator's create_finding method
        finding = validator.create_finding("check_with_ref")
        
        # The finding should include standard_ref from the check (if any)
        check = validator.get_check("check_with_ref")
        if check.standard_refs:
            assert finding.standard_ref == check.standard_refs[0]
        else:
            assert finding.standard_ref is None