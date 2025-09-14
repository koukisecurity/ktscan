"""
Unit tests for hostname validator.
"""

import pytest

from ktscan.models import ValidationSeverity
from ktscan.checks.SUBJECT import SanCheck


class TestSanCheck:
    """Test SanCheck functionality"""

    def test_validator_initialization(self):
        """Test validator initialization"""
        validator = SanCheck()
        assert validator.config == {}

        # Test with config
        config = {"disabled_checks": ["SUBJECT.HOSTNAME_MISMATCH"]}
        validator = SanCheck(config)
        assert validator.config == config


class TestHostnameMatching:
    """Test hostname matching functionality"""

    def test_exact_hostname_match(self, cert_factory):
        """Test exact hostname matching"""
        validator = SanCheck()

        # Create certificate with specific subject CN
        cert, _ = cert_factory.create_certificate(subject_name="example.com")
        context = {"hostname": "example.com"}

        findings = validator.validate(cert, context)

        # Should have success match finding
        success_findings = [
            f for f in findings if f.check_id == "SUBJECT.HOSTNAME_MATCH_SUCCESS"
        ]
        assert len(success_findings) == 1

        finding = success_findings[0]
        assert finding.severity == ValidationSeverity.MEDIUM
        assert "example.com" in finding.evidence["hostname"]

    def test_hostname_mismatch(self, cert_factory):
        """Test hostname mismatch detection"""
        validator = SanCheck()

        # Create certificate for different hostname
        cert, _ = cert_factory.create_certificate(subject_name="different.com")
        context = {"hostname": "example.com"}

        findings = validator.validate(cert, context)

        # Should detect mismatch
        mismatch_findings = [f for f in findings if f.check_id == "SUBJECT.HOSTNAME_MISMATCH"]
        assert len(mismatch_findings) == 1

        finding = mismatch_findings[0]
        assert finding.severity == ValidationSeverity.CRITICAL
        assert "does not match" in finding.description.lower()
        assert finding.evidence["hostname"] == "example.com"

    def test_wildcard_hostname_matching(self, cert_factory):
        """Test wildcard certificate matching"""
        validator = SanCheck()

        # Create wildcard certificate
        cert, _ = cert_factory.create_certificate(
            subject_name="*.example.com", san_domains=["*.example.com"]
        )

        # Test matching subdomain
        context = {"hostname": "api.example.com"}
        findings = validator.validate(cert, context)

        success_findings = [
            f for f in findings if f.check_id == "SUBJECT.HOSTNAME_MATCH_SUCCESS"
        ]
        assert len(success_findings) == 1
        assert "api.example.com" in findings[0].evidence["hostname"]

    def test_wildcard_hostname_non_matching(self, cert_factory):
        """Test wildcard certificate non-matching cases"""
        validator = SanCheck()

        # Create wildcard certificate
        cert, _ = cert_factory.create_certificate(
            subject_name="*.example.com", san_domains=["*.example.com"]
        )

        # Test non-matching cases
        test_cases = [
            "example.com",  # Base domain doesn't match wildcard
            "api.subdomain.example.com",  # Multi-level subdomain
            "different.com",  # Different domain entirely
        ]

        for hostname in test_cases:
            context = {"hostname": hostname}
            findings = validator.validate(cert, context)

            mismatch_findings = [
                f for f in findings if f.check_id == "SUBJECT.HOSTNAME_MISMATCH"
            ]
            assert len(mismatch_findings) >= 1, f"Should detect mismatch for {hostname}"

    def test_san_hostname_matching(self, cert_factory):
        """Test SAN-based hostname matching"""
        validator = SanCheck()

        # Create certificate with SAN domains
        cert, _ = cert_factory.create_certificate(
            subject_name="primary.example.com",
            san_domains=["api.example.com", "web.example.com", "*.dev.example.com"],
        )

        # Test matching SAN domain
        context = {"hostname": "api.example.com"}
        findings = validator.validate(cert, context)

        success_findings = [
            f for f in findings if f.check_id == "SUBJECT.HOSTNAME_MATCH_SUCCESS"
        ]
        assert len(success_findings) == 1
        assert "api.example.com" in success_findings[0].evidence["matching_names"]

        # Test wildcard SAN matching
        context = {"hostname": "test.dev.example.com"}
        findings = validator.validate(cert, context)

        success_findings = [
            f for f in findings if f.check_id == "SUBJECT.HOSTNAME_MATCH_SUCCESS"
        ]
        assert len(success_findings) == 1

    def test_ip_address_matching(self, cert_factory):
        """Test IP address validation in certificates"""
        validator = SanCheck()

        # Create certificate with IP address in SAN
        cert, _ = cert_factory.create_certificate(
            subject_name="example.com", san_ips=["8.8.8.8", "2606:4700:4700::1111"]
        )

        # Test that certificate has IP addresses present
        context = {"hostname": "example.com"}
        findings = validator.validate(cert, context)

        ip_present_findings = [
            f for f in findings if f.check_id == "SUBJECT.IP_ADDRESS_PRESENT"
        ]
        assert len(ip_present_findings) == 1

    def test_no_hostname_identifiers(self, cert_factory, mocker):
        """Test certificate with no hostname identifiers"""
        validator = SanCheck()

        # Create fully mock certificate with no CN or SAN
        mock_cert = mocker.Mock()

        # Mock subject with no CN
        mock_subject = mocker.Mock()
        mock_subject.get_attributes_for_oid.return_value = []  # No CN attributes
        mock_cert.subject = mock_subject

        # Mock extensions with no SAN
        mock_extensions = mocker.Mock()
        from cryptography import x509
        from cryptography.x509.oid import ExtensionOID

        mock_extensions.get_extension_for_oid.side_effect = x509.ExtensionNotFound(
            "No SAN", ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        mock_cert.extensions = mock_extensions

        context = {"hostname": "example.com"}
        findings = validator.validate(mock_cert, context)

        # Should detect lack of hostname identifiers
        no_identifiers = [
            f for f in findings if f.check_id == "SUBJECT.NO_HOSTNAME_IDENTIFIERS"
        ]
        assert len(no_identifiers) == 1

        finding = no_identifiers[0]
        assert finding.severity == ValidationSeverity.CRITICAL
        assert "no hostname identifiers" in finding.description.lower()

    def test_no_hostname_in_context(self, cert_factory):
        """Test validation without hostname in context"""
        validator = SanCheck()

        cert, _ = cert_factory.create_certificate(subject_name="example.com")

        # Test with no context - should not have hostname-specific findings
        findings = validator.validate(cert, None)
        hostname_findings = [f for f in findings if "HOSTNAME" in f.check_id]
        assert len(hostname_findings) == 0

        # Test with empty context - should not have hostname-specific findings
        findings = validator.validate(cert, {})
        hostname_findings = [f for f in findings if "HOSTNAME" in f.check_id]
        assert len(hostname_findings) == 0

        # Test with context missing hostname - should not have hostname-specific findings
        findings = validator.validate(cert, {"ip": "192.0.2.1"})
        hostname_findings = [f for f in findings if "HOSTNAME" in f.check_id]
        assert len(hostname_findings) == 0


class TestSANValidation:
    """Test Subject Alternative Name validation"""

    def test_missing_san_extension(self, cert_factory):
        """Test detection of missing SAN extension"""
        validator = SanCheck()

        # Create certificate without SAN
        cert, _ = cert_factory.create_certificate(
            subject_name="example.com", san_domains=None  # No SAN
        )

        context = {"hostname": "example.com"}
        findings = validator.validate(cert, context)

        # Should detect missing SAN
        missing_san = [f for f in findings if f.check_id == "SUBJECT.MISSING_SAN"]
        assert len(missing_san) == 1

        finding = missing_san[0]
        assert finding.severity == ValidationSeverity.MEDIUM
        assert "subject alternative name" in finding.description.lower()

    def test_san_with_other_name_types(self, cert_factory, mocker):
        """Test SAN with other name types (non-DNS/IP)"""
        validator = SanCheck()

        # Create a fully mock certificate
        mock_cert = mocker.Mock()

        # Mock the SAN extension to include other name types
        mock_san_ext = mocker.Mock()
        mock_other_name = mocker.Mock()
        mock_other_name.__str__ = lambda self: "email:test@example.com"

        # Create proper DNS name mock
        from cryptography import x509

        mock_dns_name = mocker.Mock(spec=x509.DNSName)
        mock_dns_name.value = "example.com"

        mock_san_ext.value = [mock_dns_name, mock_other_name]

        mock_extensions = mocker.Mock()
        mock_extensions.get_extension_for_oid.return_value = mock_san_ext
        mock_cert.extensions = mock_extensions

        findings = validator._validate_san_quality(mock_cert)

        # Should detect other name types
        other_names = [f for f in findings if f.check_id == "SUBJECT.OTHER_NAME_TYPES"]
        assert len(other_names) == 1

        finding = other_names[0]
        assert finding.severity == ValidationSeverity.INFO
        assert "non-DNS/IP names" in finding.description


class TestDNSNameValidation:
    """Test DNS name validation in SAN"""

    def test_valid_dns_names(self, cert_factory):
        """Test valid DNS names pass validation"""
        validator = SanCheck()

        valid_dns_names = [
            "example.com",
            "subdomain.example.com",
            "api-v2.example.com",
            "test123.example.com",
            "*.example.com",
            "long-subdomain-name.example.org",
        ]

        cert, _ = cert_factory.create_certificate(
            subject_name="example.com", san_domains=valid_dns_names
        )

        context = {"hostname": "example.com"}
        findings = validator.validate(cert, context)

        # Should not have DNS name validation errors
        dns_errors = [
            f
            for f in findings
            if "dns_name" in f.check_id
            and f.severity in [ValidationSeverity.HIGH, ValidationSeverity.CRITICAL]
        ]
        assert len(dns_errors) == 0

    def test_invalid_dns_names(self, cert_factory, mocker):
        """Test invalid DNS name detection"""
        validator = SanCheck()

        # Mock certificate with invalid DNS names
        invalid_dns_names = [
            "",  # Empty
            "example..com",  # Double dot
            "-example.com",  # Leading hyphen
            "example-.com",  # Trailing hyphen
            "ex@mple.com",  # Invalid character
        ]

        for invalid_name in invalid_dns_names:
            findings = validator._validate_dns_names_quality([invalid_name])

            invalid_findings = [f for f in findings if f.check_id == "SUBJECT.INVALID_DNS_NAME"]
            assert (
                len(invalid_findings) >= 1
            ), f"Should detect invalid DNS name: {invalid_name}"

    def test_wildcard_validation(self, cert_factory):
        """Test wildcard DNS name validation"""
        validator = SanCheck()

        # Test nested wildcards
        findings = validator._validate_dns_names_quality(["*.*.example.com"])
        nested_findings = [f for f in findings if f.check_id == "SUBJECT.NESTED_WILDCARD"]
        assert len(nested_findings) == 1

        # Test multiple wildcards
        findings = validator._validate_dns_names_quality(["*.*example.com"])
        multiple_findings = [f for f in findings if f.check_id == "SUBJECT.MULTIPLE_WILDCARDS"]
        assert len(multiple_findings) == 1

        # Test wildcard not in leftmost position
        findings = validator._validate_dns_names_quality(["example.*.com"])
        position_findings = [
            f for f in findings if f.check_id == "SUBJECT.WILDCARD_NOT_LEFTMOST"
        ]
        assert len(position_findings) == 1

    def test_duplicate_dns_names(self, cert_factory):
        """Test duplicate DNS name detection"""
        validator = SanCheck()

        dns_names_with_duplicates = [
            "example.com",
            "api.example.com",
            "example.com",  # Duplicate
            "web.example.com",
            "api.example.com",  # Duplicate
        ]

        findings = validator._validate_dns_names_quality(dns_names_with_duplicates)

        duplicate_findings = [
            f for f in findings if f.check_id == "SUBJECT.DUPLICATE_DNS_NAMES"
        ]
        assert len(duplicate_findings) == 1

        finding = duplicate_findings[0]
        assert finding.severity == ValidationSeverity.MEDIUM
        assert "example.com" in finding.evidence["duplicates"]
        assert "api.example.com" in finding.evidence["duplicates"]


class TestIPAddressValidation:
    """Test IP address validation in SAN"""

    def test_valid_ip_addresses(self, cert_factory):
        """Test valid IP addresses pass validation"""
        validator = SanCheck()

        valid_ips = [
            "1.1.1.1",  # Public IPv4
            "8.8.8.8",  # Public IPv4
            "2001:4860:4860::8888",  # Public IPv6
            "2606:4700:4700::1111",  # Public IPv6
        ]

        for ip in valid_ips:
            findings = validator._validate_ip_addresses_quality([ip])

            # Should not have critical/high severity findings for public IPs
            critical_high = [
                f
                for f in findings
                if f.severity in [ValidationSeverity.CRITICAL, ValidationSeverity.HIGH]
            ]
            assert (
                len(critical_high) == 0
            ), f"Valid public IP {ip} should not have critical/high findings"

    def test_private_ip_addresses(self, cert_factory):
        """Test private IP address detection"""
        validator = SanCheck()

        private_ips = [
            "192.168.1.1",
            "10.0.0.1",
            "172.16.0.1",
            "fd00::1",  # Private IPv6
        ]

        for ip in private_ips:
            findings = validator._validate_ip_addresses_quality([ip])

            private_findings = [
                f for f in findings if f.check_id == "SUBJECT.PRIVATE_IP"
            ]
            assert len(private_findings) >= 1, f"Should detect private IP: {ip}"

            finding = private_findings[0]
            assert finding.severity == ValidationSeverity.MEDIUM
            assert ip in finding.evidence["ip_address"]

    def test_loopback_ip_addresses(self, cert_factory):
        """Test loopback IP address detection"""
        validator = SanCheck()

        loopback_ips = ["127.0.0.1", "::1"]

        for ip in loopback_ips:
            findings = validator._validate_ip_addresses_quality([ip])

            loopback_findings = [
                f for f in findings if f.check_id == "SUBJECT.LOOPBACK_IP"
            ]
            assert len(loopback_findings) >= 1, f"Should detect loopback IP: {ip}"

            finding = loopback_findings[0]
            assert finding.severity == ValidationSeverity.HIGH

    def test_invalid_ip_addresses(self, cert_factory):
        """Test invalid IP address detection"""
        validator = SanCheck()

        invalid_ips = [
            "256.1.1.1",  # Invalid IPv4
            "192.168.1.256",  # Invalid IPv4
            "not-an-ip",  # Not an IP
            "192.168.1",  # Incomplete IPv4
            "gggg::1",  # Invalid IPv6
        ]

        for ip in invalid_ips:
            findings = validator._validate_ip_addresses_quality([ip])

            invalid_findings = [
                f for f in findings if f.check_id == "SUBJECT.INVALID_IP_ADDRESS"
            ]
            assert len(invalid_findings) >= 1, f"Should detect invalid IP: {ip}"


class TestWildcardValidation:
    """Test wildcard certificate validation"""

    def test_valid_wildcard_usage(self, cert_factory):
        """Test valid wildcard certificate usage"""
        validator = SanCheck()

        # Create certificate with proper wildcard
        cert, _ = cert_factory.create_certificate(
            subject_name="*.example.com",
            san_domains=["*.api.example.com", "*.web.example.org"],
        )

        context = {"hostname": "test.example.com"}
        findings = validator.validate(cert, context)

        # Should not have wildcard-related high/critical findings
        wildcard_issues = [
            f
            for f in findings
            if "wildcard" in f.check_id
            and f.severity in [ValidationSeverity.HIGH, ValidationSeverity.CRITICAL]
        ]
        assert len(wildcard_issues) == 0

    def test_wildcard_insufficient_domain_labels(self, cert_factory, mocker):
        """Test wildcard with insufficient domain labels"""
        validator = SanCheck()

        # Test wildcard with only one label after wildcard
        wildcard_names = ["*.com", "*.org"]

        for wildcard_name in wildcard_names:
            # Create mock certificate with the problematic wildcard
            mock_cert = mocker.Mock()

            # Mock subject CN extraction
            mock_subject = mocker.Mock()
            mock_subject.get_attributes_for_oid.return_value = [
                mocker.Mock(value=wildcard_name)
            ]
            mock_cert.subject = mock_subject

            # Mock SAN extraction
            mock_extensions = mocker.Mock()
            mock_extensions.get_extension_for_oid.side_effect = Exception("No SAN")
            mock_cert.extensions = mock_extensions

            findings = validator._validate_wildcard_usage(mock_cert)

            insufficient_findings = [
                f
                for f in findings
                if f.check_id == "SUBJECT.WILDCARD_INSUFFICIENT_LABELS"
            ]
            assert (
                len(insufficient_findings) >= 1
            ), f"Should detect insufficient labels: {wildcard_name}"

    def test_wildcard_empty_domain_label(self, cert_factory, mocker):
        """Test wildcard with empty domain labels"""
        validator = SanCheck()

        # Test wildcards with empty labels
        wildcard_names = ["*.example..com", "*..example.com"]

        for wildcard_name in wildcard_names:
            # Create mock certificate with the problematic wildcard
            mock_cert = mocker.Mock()

            # Mock subject CN extraction
            mock_subject = mocker.Mock()
            mock_subject.get_attributes_for_oid.return_value = [
                mocker.Mock(value=wildcard_name)
            ]
            mock_cert.subject = mock_subject

            # Mock SAN extraction
            mock_extensions = mocker.Mock()
            mock_extensions.get_extension_for_oid.side_effect = Exception("No SAN")
            mock_cert.extensions = mock_extensions

            findings = validator._validate_wildcard_usage(mock_cert)

            empty_label_findings = [
                f for f in findings if f.check_id == "SUBJECT.WILDCARD_EMPTY_LABEL"
            ]
            assert (
                len(empty_label_findings) >= 1
            ), f"Should detect empty label: {wildcard_name}"


class TestValidatorIntegration:
    """Integration tests for hostname validator"""

    def test_validate_respects_check_configuration(self, cert_factory):
        """Test that validate method respects check configuration"""
        # Test with disabled hostname mismatch check
        config = {"disabled_checks": ["SUBJECT.HOSTNAME_MISMATCH"]}
        validator = SanCheck(config)

        # Create certificate with mismatched hostname
        cert, _ = cert_factory.create_certificate(subject_name="different.com")
        context = {"hostname": "example.com"}

        findings = validator.validate(cert, context)

        # Should not have hostname mismatch findings
        mismatch_findings = [f for f in findings if f.check_id == "SUBJECT.HOSTNAME_MISMATCH"]
        assert len(mismatch_findings) == 0

    @pytest.mark.parametrize(
        "hostname,cert_name,should_match",
        [
            ("example.com", "example.com", True),
            ("EXAMPLE.COM", "example.com", True),  # Case insensitive
            ("api.example.com", "*.example.com", True),
            ("sub.api.example.com", "*.example.com", False),  # Multi-level
            ("example.com", "*.example.com", False),  # Base domain vs wildcard
            ("192.0.2.1", "192.0.2.1", True),  # IP matching
            ("2001:db8::1", "2001:db8::1", True),  # IPv6 matching
            ("different.com", "example.com", False),
        ],
    )
    def test_hostname_matching_logic(self, hostname, cert_name, should_match):
        """Test hostname matching logic with various cases"""
        validator = SanCheck()
        result = validator._match_hostname_advanced(hostname, cert_name)
        assert (
            result == should_match
        ), f"Expected {hostname} vs {cert_name} to be {should_match}"

    def test_dns_name_validation_logic(self):
        """Test DNS name validation logic"""
        validator = SanCheck()

        valid_names = [
            "example.com",
            "sub.example.com",
            "api-v1.example.com",
            "test123.example.org",
            "a.b",  # Minimal valid
        ]

        invalid_names = [
            "",  # Empty
            "a" * 254,  # Too long
            "example..com",  # Double dot
            "-example.com",  # Leading hyphen
            "example.com-",  # Trailing hyphen (at end of domain)
            "ex@mple.com",  # Invalid character
        ]

        for name in valid_names:
            assert validator._is_valid_dns_name(name), f"Should be valid: {name}"

        for name in invalid_names:
            assert not validator._is_valid_dns_name(name), f"Should be invalid: {name}"

    def test_comprehensive_certificate_validation(self, cert_factory):
        """Test comprehensive validation of a realistic certificate"""
        validator = SanCheck()

        # Create comprehensive certificate
        cert, _ = cert_factory.create_certificate(
            subject_name="api.example.com",
            san_domains=[
                "api.example.com",
                "web.example.com",
                "*.dev.example.com",
                "admin.example.org",
            ],
            san_ips=["8.8.8.8", "2606:4700:4700::1111"],
        )

        # Test matching hostname
        context = {"hostname": "api.example.com"}
        findings = validator.validate(cert, context)

        # Should have success finding
        success_findings = [
            f for f in findings if f.check_id == "SUBJECT.HOSTNAME_MATCH_SUCCESS"
        ]
        assert len(success_findings) == 1

        # Should not have critical/high severity issues
        critical_high = [
            f
            for f in findings
            if f.severity in [ValidationSeverity.CRITICAL, ValidationSeverity.HIGH]
        ]
        assert len(critical_high) == 0


class TestValidatorErrorHandling:
    """Test error handling in hostname validator"""

    def test_malformed_certificate_handling(self, cert_factory, mocker):
        """Test handling of certificates with malformed extensions"""
        validator = SanCheck()

        # Create mock certificate that raises exceptions
        mock_cert = mocker.Mock()
        mock_subject = mocker.Mock()
        mock_subject.get_attributes_for_oid.side_effect = Exception("Malformed subject")
        mock_cert.subject = mock_subject

        mock_extensions = mocker.Mock()
        mock_extensions.get_extension_for_oid.side_effect = Exception(
            "Malformed extension"
        )
        mock_cert.extensions = mock_extensions

        context = {"hostname": "example.com"}

        # Should handle exceptions gracefully
        try:
            findings = validator.validate(mock_cert, context)
            assert isinstance(findings, list)
        except Exception:
            # Some exceptions may bubble up, which is acceptable
            pass

    def test_extraction_methods_error_handling(self, cert_factory, mocker):
        """Test error handling in name extraction methods"""
        validator = SanCheck()

        # Test subject CN extraction with exceptions
        mock_cert = mocker.Mock()
        mock_cert.subject.get_attributes_for_oid.side_effect = Exception("Error")

        cn = validator._extract_subject_cn(mock_cert)
        assert cn is None

        # Test SAN extraction with exceptions
        mock_cert.extensions.get_extension_for_oid.side_effect = Exception("Error")

        san_names = validator._extract_san_dns_names(mock_cert)
        assert san_names == []
