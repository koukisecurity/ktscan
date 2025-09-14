"""
Tests for ktscan.checks.TRUST module
"""

import socket
from unittest.mock import Mock, patch, mock_open
from urllib.error import URLError

from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import AuthorityInformationAccessOID
from cryptography.x509.verification import Store

from ktscan.models import ValidationSeverity
from ktscan.checks.TRUST import TrustCheck


class TestTrustCheck:

    def test_init_default_config(self):
        """Test validator initialization with default config"""
        validator = TrustCheck()
        assert validator.timeout == 10
        assert validator.thread_manager is None
        # _trust_store no longer exists in current implementation
        assert validator._intermediate_cache == {}

    def test_init_with_config(self):
        """Test validator initialization with custom config"""
        config = {"enabled_checks": ["chain_validation"]}
        thread_manager = Mock()
        validator = TrustCheck(config, timeout=30, thread_manager=thread_manager)
        assert validator.timeout == 30
        assert validator.thread_manager == thread_manager
        assert validator.config == config

    def test_is_root_ca_self_signed(self, cert_factory):
        """Test identification of root CA (self-signed certificate)"""
        cert, _ = cert_factory.create_self_signed_cert(subject_name="Root CA")

        validator = TrustCheck()
        assert validator._is_root_ca(cert) is True

    def test_is_root_ca_not_self_signed(self, cert_factory):
        """Test identification of non-root certificate"""
        cert, _ = cert_factory.create_certificate(
            subject_name="example.com", issuer_name="Intermediate CA"
        )

        validator = TrustCheck()
        assert validator._is_root_ca(cert) is False

    def test_get_certificate_chain_from_context(self, cert_factory):
        """Test getting certificate chain from context"""
        chain = cert_factory.create_cert_chain(levels=3)
        cert_chain = [cert for cert, _ in chain]

        validator = TrustCheck()
        context = {"certificate_chain": cert_chain}

        result = validator._get_certificate_chain(cert_chain[0], context)
        assert len(result) == 3
        assert result == cert_chain

    def test_get_certificate_chain_single_cert(self, cert_factory):
        """Test getting certificate chain with single certificate (no intermediates)"""
        cert, _ = cert_factory.create_certificate()

        validator = TrustCheck()
        with patch.object(
            validator, "_fetch_intermediate_certificates", return_value=[]
        ):
            result = validator._get_certificate_chain(cert)
            assert len(result) == 1
            assert result[0] == cert

    def test_extract_ca_issuers_urls(self, cert_factory):
        """Test extraction of CA Issuers URLs from AIA extension"""
        cert, _ = cert_factory.create_certificate(
            ocsp_urls=["https://ocsp.example.com"]  # This adds AIA extension
        )

        validator = TrustCheck()
        urls = validator._extract_ca_issuers_urls(cert)
        # Our test certificate doesn't have CA Issuers URLs, only OCSP
        assert urls == []

    def test_extract_ca_issuers_urls_no_aia(self, cert_factory):
        """Test extraction with no AIA extension"""
        cert, _ = cert_factory.create_certificate()

        validator = TrustCheck()
        urls = validator._extract_ca_issuers_urls(cert)
        assert urls == []

    def test_extract_ca_issuers_urls_with_mocked_aia(self):
        """Test extraction with mocked AIA extension containing CA Issuers"""
        # Create mock certificate with AIA extension
        mock_cert = Mock()
        mock_ext = Mock()
        mock_access_desc = Mock()
        mock_access_desc.access_method = AuthorityInformationAccessOID.CA_ISSUERS
        mock_location = Mock()
        mock_location.value = "https://ca.example.com/intermediate.crt"
        mock_access_desc.access_location = mock_location
        mock_ext.value = [mock_access_desc]

        mock_extensions = Mock()
        mock_extensions.get_extension_for_oid.return_value = mock_ext
        mock_cert.extensions = mock_extensions

        # Mock isinstance to return True for UniformResourceIdentifier
        with patch("ktscan.checks.TRUST.isinstance", return_value=True):
            validator = TrustCheck()
            urls = validator._extract_ca_issuers_urls(mock_cert)

            assert urls == ["https://ca.example.com/intermediate.crt"]

    def test_download_certificate_der_success(self, cert_factory):
        """Test successful certificate download in DER format"""
        cert, _ = cert_factory.create_certificate()
        cert_der = cert.public_bytes(serialization.Encoding.DER)

        validator = TrustCheck()

        with patch("ktscan.checks.TRUST.urlopen") as mock_urlopen:
            # Mock urlopen response
            mock_response = Mock()
            mock_response.read.return_value = cert_der
            mock_response.__enter__ = Mock(return_value=mock_response)
            mock_response.__exit__ = Mock(return_value=None)
            mock_urlopen.return_value = mock_response

            result = validator._download_certificate("https://example.com/cert.crt")

            assert result is not None
            assert result.subject == cert.subject

    def test_download_certificate_pem_success(self, cert_factory):
        """Test successful certificate download in PEM format"""
        cert, _ = cert_factory.create_certificate()
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)

        validator = TrustCheck()

        with patch("ktscan.checks.TRUST.urlopen") as mock_urlopen:
            # Mock urlopen to fail DER parsing but succeed with PEM
            mock_response = Mock()
            mock_response.read.return_value = cert_pem
            mock_response.__enter__ = Mock(return_value=mock_response)
            mock_response.__exit__ = Mock(return_value=None)
            mock_urlopen.return_value = mock_response

            result = validator._download_certificate("https://example.com/cert.crt")

            assert result is not None
            assert result.subject == cert.subject

    @patch("ktscan.checks.TRUST.urlopen")
    def test_download_certificate_invalid_format(self, mock_urlopen):
        """Test certificate download with invalid format"""
        # Mock invalid certificate data
        mock_response = Mock()
        mock_response.read.return_value = b"invalid certificate data"
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=None)
        mock_urlopen.return_value = mock_response

        validator = TrustCheck()
        result = validator._download_certificate("https://example.com/cert.crt")

        assert result is None

    @patch("ktscan.checks.TRUST.urlopen")
    def test_download_certificate_network_error(self, mock_urlopen):
        """Test certificate download with network error"""
        mock_urlopen.side_effect = URLError("Network error")

        validator = TrustCheck()
        result = validator._download_certificate("https://example.com/cert.crt")

        assert result is None

    @patch("ktscan.checks.TRUST.urlopen")
    def test_download_certificate_timeout(self, mock_urlopen):
        """Test certificate download with timeout"""
        mock_urlopen.side_effect = socket.timeout("Timeout")

        validator = TrustCheck()
        result = validator._download_certificate("https://example.com/cert.crt")

        assert result is None

    def test_download_certificate_cached(self, cert_factory):
        """Test certificate download uses cache"""
        cert, _ = cert_factory.create_certificate()
        url = "https://example.com/cert.crt"

        validator = TrustCheck()
        validator._intermediate_cache[url] = cert

        result = validator._download_certificate(url)

        assert result == cert

    def test_verify_issuer_relationship_valid(self, cert_factory):
        """Test valid issuer relationship verification"""
        # Create a certificate chain
        chain = cert_factory.create_cert_chain(levels=2)
        end_entity_cert = chain[0][0]  # First cert in chain
        root_cert = chain[1][0]  # Second cert in chain (root)

        validator = TrustCheck()
        result = validator._verify_issuer_relationship(end_entity_cert, root_cert)

        # Should be True since we created a valid chain
        assert result is True

    def test_verify_issuer_relationship_name_mismatch(self, cert_factory):
        """Test issuer relationship with mismatched names"""
        cert1, _ = cert_factory.create_certificate(
            subject_name="cert1.com", issuer_name="CA1"
        )
        cert2, _ = cert_factory.create_certificate(
            subject_name="CA2", issuer_name="Root"
        )

        validator = TrustCheck()
        result = validator._verify_issuer_relationship(cert1, cert2)

        # Should be False due to name mismatch
        assert result is False

    def test_validate_chain_signatures_incomplete_chain(self, cert_factory):
        """Test validation with incomplete chain (single certificate)"""
        cert, _ = cert_factory.create_certificate()

        validator = TrustCheck()
        findings = validator._validate_chain_signatures([cert])

        incomplete = [f for f in findings if f.check_id == "TRUST.INCOMPLETE_CHAIN"]
        assert len(incomplete) == 1
        assert incomplete[0].severity == ValidationSeverity.MEDIUM
        assert "only the end-entity certificate" in incomplete[0].description

    def test_validate_chain_signatures_valid_chain(self, cert_factory):
        """Test validation with valid certificate chain"""
        chain = cert_factory.create_cert_chain(levels=2)
        cert_chain = [cert for cert, _ in chain]

        validator = TrustCheck()
        with patch.object(validator, "_verify_issuer_relationship", return_value=True):
            findings = validator._validate_chain_signatures(cert_chain)

            # Should have no signature errors
            signature_errors = [
                f for f in findings if f.check_id == "TRUST.SIGNATURE_INVALID"
            ]
            assert len(signature_errors) == 0

    def test_validate_chain_signatures_invalid_signature(self, cert_factory):
        """Test validation with invalid chain signature"""
        cert1, _ = cert_factory.create_certificate(subject_name="cert1.com")
        cert2, _ = cert_factory.create_certificate(subject_name="cert2.com")

        validator = TrustCheck()
        with patch.object(validator, "_verify_issuer_relationship", return_value=False):
            findings = validator._validate_chain_signatures([cert1, cert2])

            signature_errors = [
                f for f in findings if f.check_id == "TRUST.SIGNATURE_INVALID"
            ]
            assert len(signature_errors) == 1
            assert signature_errors[0].severity == ValidationSeverity.HIGH

    def test_validate_chain_path_no_trust_store(self, cert_factory):
        """Test path validation when trust store is unavailable"""
        cert, _ = cert_factory.create_certificate()

        validator = TrustCheck()
        with patch.object(validator, "_get_trust_store", return_value=None):
            findings = validator._validate_chain_path([cert])

            trust_store_errors = [
                f for f in findings if f.check_id == "TRUST.STORE_UNAVAILABLE"
            ]
            assert len(trust_store_errors) == 1
            assert trust_store_errors[0].severity == ValidationSeverity.MEDIUM

    def test_validate_chain_path_validation_error(self, cert_factory):
        """Test path validation with validation error"""
        cert, _ = cert_factory.create_certificate()

        validator = TrustCheck()
        mock_store = Mock(spec=Store)

        with patch.object(
            validator, "_get_trust_store", return_value=mock_store
        ), patch("cryptography.x509.verification.PolicyBuilder") as mock_policy_builder:

            # Mock the verification to raise an exception
            mock_builder = Mock()
            mock_verifier = Mock()
            mock_verifier.verify.side_effect = Exception("Certificate expired")
            mock_builder.build_server_verifier.return_value = mock_verifier
            mock_builder.store.return_value = mock_builder
            mock_policy_builder.return_value = mock_builder

            findings = validator._validate_chain_path([cert])

            path_errors = [
                f for f in findings if f.check_id == "TRUST.EXPIRED_IN_CHAIN"
            ]
            assert len(path_errors) == 1
            assert "expired" in path_errors[0].evidence["validation_error"].lower()

    def test_validate_chain_path_untrusted_root(self, cert_factory):
        """Test path validation with untrusted root"""
        cert, _ = cert_factory.create_certificate()

        validator = TrustCheck()
        mock_store = Mock(spec=Store)

        with patch.object(
            validator, "_get_trust_store", return_value=mock_store
        ), patch("cryptography.x509.verification.PolicyBuilder") as mock_policy_builder:

            # Mock the verification to return empty chain (untrusted)
            mock_builder = Mock()
            mock_verifier = Mock()
            mock_verifier.verify.return_value = []
            mock_builder.build_server_verifier.return_value = mock_verifier
            mock_builder.store.return_value = mock_builder
            mock_policy_builder.return_value = mock_builder

            findings = validator._validate_chain_path([cert])

            untrusted_errors = [f for f in findings if f.check_id == "TRUST.UNTRUSTED_ROOT"]
            assert len(untrusted_errors) == 1
            assert untrusted_errors[0].severity == ValidationSeverity.HIGH

    def test_has_ocsp_endpoint_present(self, cert_factory):
        """Test detection of OCSP endpoint"""
        cert, _ = cert_factory.create_cert_with_revocation_info(
            ocsp_urls=["https://ocsp.example.com"]
        )

        validator = TrustCheck()
        assert validator._has_ocsp_endpoint(cert) is True

    def test_has_ocsp_endpoint_absent(self, cert_factory):
        """Test detection of missing OCSP endpoint"""
        cert, _ = cert_factory.create_certificate()

        validator = TrustCheck()
        assert validator._has_ocsp_endpoint(cert) is False

    def test_has_crl_endpoint_present(self, cert_factory):
        """Test detection of CRL endpoint"""
        cert, _ = cert_factory.create_cert_with_revocation_info(
            crl_urls=["https://crl.example.com/cert.crl"]
        )

        validator = TrustCheck()
        assert validator._has_crl_endpoint(cert) is True

    def test_has_crl_endpoint_absent(self, cert_factory):
        """Test detection of missing CRL endpoint"""
        cert, _ = cert_factory.create_certificate()

        validator = TrustCheck()
        assert validator._has_crl_endpoint(cert) is False

    def test_validate_intermediate_revocation_sequential(self, cert_factory):
        """Test intermediate revocation validation in sequential mode"""
        # Create a 3-level chain (end-entity -> intermediate -> root)
        chain = cert_factory.create_cert_chain(levels=3)
        cert_chain = [cert for cert, _ in chain]

        validator = TrustCheck()

        # Mock that intermediate has no revocation info
        with patch.object(
            validator, "_has_ocsp_endpoint", return_value=False
        ), patch.object(
            validator, "_has_crl_endpoint", return_value=False
        ), patch.object(
            validator, "_is_root_ca", side_effect=lambda c: c == cert_chain[-1]
        ):

            findings = validator._validate_intermediate_revocation(
                cert_chain
            )

            missing_revocation = [
                f
                for f in findings
                if f.check_id == "TRUST.INTERMEDIATE_MISSING_REVOCATION"
            ]
            assert (
                len(missing_revocation) >= 1
            )  # At least one intermediate should be flagged

    def test_validate_intermediate_revocation_parallel(self, cert_factory):
        """Test intermediate revocation validation in parallel mode"""
        # Create a 3-level chain
        chain = cert_factory.create_cert_chain(levels=3)
        cert_chain = [cert for cert, _ in chain]

        thread_manager = Mock()
        validator = TrustCheck(thread_manager=thread_manager)

        with patch.object(
            validator, "_is_root_ca", side_effect=lambda c: c == cert_chain[-1]
        ), patch.object(
            validator, "_has_ocsp_endpoint", return_value=False
        ), patch.object(
            validator, "_has_crl_endpoint", return_value=False
        ):
            findings = validator._validate_intermediate_revocation(cert_chain)

            # Should work with the existing method
            assert isinstance(findings, list)

    @patch("truststore.inject_into_ssl")
    @patch("ssl.create_default_context")
    def test_get_trust_store_truststore_success(
        self, mock_ssl, mock_truststore, cert_factory
    ):
        """Test trust store loading with truststore library"""
        # Mock successful truststore integration
        mock_ssl.create_default_context.return_value = Mock()

        validator = TrustCheck()

        with patch.object(validator, "_load_system_ca_fallback") as mock_fallback:
            mock_fallback.return_value = Mock(spec=Store)
            result = validator._get_trust_store()

            # Should call truststore.inject_into_ssl()
            mock_truststore.assert_called_once()
            assert result is not None

    @patch("truststore.inject_into_ssl")
    def test_get_trust_store_truststore_fails(self, mock_truststore, cert_factory):
        """Test trust store loading when truststore fails"""
        # Mock truststore failure
        mock_truststore.side_effect = Exception("Truststore error")

        validator = TrustCheck()

        with patch.object(validator, "_load_system_ca_fallback") as mock_fallback:
            mock_fallback.return_value = Mock(spec=Store)
            result = validator._get_trust_store()

            # Should fall back to direct CA loading
            mock_fallback.assert_called_once()

    @patch(
        "builtins.open",
        new_callable=mock_open,
        read_data=b"""-----BEGIN CERTIFICATE-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7t8Cqb7j8Qx9Z...
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA8u9Drb8k9Ry0B...
-----END CERTIFICATE-----""",
    )
    @patch("os.path.exists")
    def test_load_system_ca_fallback_success(self, mock_exists, mock_file):
        """Test fallback system CA loading"""
        mock_exists.return_value = True

        validator = TrustCheck()

        with patch(
            "cryptography.x509.load_pem_x509_certificate"
        ) as mock_load, patch(
            "cryptography.x509.verification.Store"
        ) as mock_store_class:

            # Mock certificate loading
            mock_cert1 = Mock()
            mock_cert2 = Mock()
            mock_load.side_effect = [mock_cert1, mock_cert2]
            mock_store = Mock(spec=Store)
            mock_store_class.return_value = mock_store

            result = validator._load_system_ca_fallback()

            assert result == mock_store
            mock_store_class.assert_called_once()

    @patch("os.path.exists")
    def test_load_system_ca_fallback_no_ca_files(self, mock_exists):
        """Test fallback system CA loading with no CA files found"""
        mock_exists.return_value = False

        validator = TrustCheck()
        result = validator._load_system_ca_fallback()

        assert result is None

    def test_fetch_intermediate_certificates_sequential(self, cert_factory):
        """Test sequential intermediate certificate fetching"""
        cert, _ = cert_factory.create_certificate()

        validator = TrustCheck()

        with patch.object(
            validator,
            "_extract_ca_issuers_urls",
            return_value=["https://ca.example.com/cert.crt"],
        ), patch.object(
            validator, "_download_certificate"
        ) as mock_download, patch.object(
            validator, "_verify_issuer_relationship", return_value=True
        ):

            intermediate_cert, _ = cert_factory.create_certificate(
                subject_name="Intermediate CA"
            )
            mock_download.return_value = intermediate_cert

            result = validator._fetch_intermediate_certificates_sequential(cert)

            assert len(result) == 1
            assert result[0] == intermediate_cert

    def test_fetch_intermediate_certificates_parallel(self, cert_factory):
        """Test parallel intermediate certificate fetching"""
        cert, _ = cert_factory.create_certificate()

        thread_manager = Mock()
        intermediate_cert, _ = cert_factory.create_certificate(
            subject_name="Intermediate CA"
        )
        
        validator = TrustCheck(thread_manager=thread_manager)

        with patch.object(
            validator,
            "_extract_ca_issuers_urls",
            return_value=["https://ca.example.com/cert.crt"],
        ), patch.object(
            validator, "_fetch_intermediate_certificates_sequential", return_value=[intermediate_cert]
        ):
            # The TrustCheck uses the generic _fetch_intermediate_certificates method
            # which delegates to sequential or parallel based on thread_manager
            result = validator._fetch_intermediate_certificates(cert)

            # Should return the intermediate certificate
            assert len(result) == 1
            assert result[0] == intermediate_cert

    def test_validate_disabled_check(self, cert_factory):
        """Test validation when specific checks are disabled"""
        cert, _ = cert_factory.create_certificate()

        # Disable all checks that would normally fire for a single certificate
        config = {"disabled_checks": ["TRUST.INCOMPLETE_CHAIN", "TRUST.SELF_SIGNED"]}
        validator = TrustCheck(config)

        findings = validator.validate(cert)

        # Should have fewer findings when specific checks are disabled
        assert len([f for f in findings if f.check_id in ["TRUST.INCOMPLETE_CHAIN", "TRUST.SELF_SIGNED"]]) == 0

    def test_validate_complete_workflow(self, cert_factory):
        """Test complete validation workflow"""
        cert, _ = cert_factory.create_certificate()

        validator = TrustCheck()

        with patch.object(
            validator, "_get_certificate_chain", return_value=[cert]
        ), patch.object(
            validator, "_validate_chain_signatures", return_value=[]
        ), patch.object(
            validator, "_validate_intermediate_revocation", return_value=[]
        ):

            findings = validator.validate(cert)

            # Should complete without errors
            assert isinstance(findings, list)

    def test_validate_with_exception(self, cert_factory):
        """Test validation with exception handling"""
        cert, _ = cert_factory.create_certificate()

        validator = TrustCheck()

        with patch.object(
            validator, "_get_certificate_chain", side_effect=Exception("Test error")
        ):
            findings = validator.validate(cert)

            error_findings = [
                f for f in findings if f.check_id == "TRUST.VALIDATION_ERROR"
            ]
            assert len(error_findings) == 1
            assert error_findings[0].severity == ValidationSeverity.HIGH
            assert "Test error" in error_findings[0].evidence["error"]

    def test_validate_with_context_hostname(self, cert_factory):
        """Test validation with hostname context"""
        cert, _ = cert_factory.create_certificate()
        context = {"hostname": "example.com"}

        validator = TrustCheck()

        with patch.object(
            validator, "_get_certificate_chain", return_value=[cert]
        ), patch.object(
            validator, "_validate_chain_signatures", return_value=[]
        ), patch.object(
            validator, "_validate_intermediate_revocation", return_value=[]
        ):

            findings = validator.validate(cert, context)

            # Should complete with hostname context
            assert isinstance(findings, list)

    def test_verify_issuer_relationship_signature_unsupported(self, cert_factory):
        """Test issuer relationship verification with unsupported signature algorithm"""
        # Create mock certificates with matching names
        mock_cert1 = Mock()
        mock_cert1.issuer = Mock()
        mock_cert1.issuer.__eq__ = Mock(return_value=True)

        mock_cert2 = Mock()
        mock_cert2.subject = Mock()
        mock_cert2.subject.__eq__ = Mock(return_value=True)

        # Mock the public key to raise unsupported algorithm error
        mock_key = Mock()
        mock_key.verify.side_effect = Exception("unsupported elliptic curve algorithm")
        mock_cert2.public_key.return_value = mock_key

        validator = TrustCheck()
        result = validator._verify_issuer_relationship(mock_cert1, mock_cert2)

        # Should accept based on name matching when signature is unsupported
        assert result is True

    def test_verify_issuer_relationship_signature_failed(self, cert_factory):
        """Test issuer relationship verification with signature verification failure"""
        # Create mock certificates with matching names
        mock_cert1 = Mock()
        mock_cert1.issuer = Mock()
        mock_cert1.issuer.__eq__ = Mock(return_value=True)

        mock_cert2 = Mock()
        mock_cert2.subject = Mock()
        mock_cert2.subject.__eq__ = Mock(return_value=True)

        # Mock the public key to raise verification error
        mock_key = Mock()
        mock_key.verify.side_effect = Exception("signature verification failed")
        mock_cert2.public_key.return_value = mock_key

        validator = TrustCheck()
        result = validator._verify_issuer_relationship(mock_cert1, mock_cert2)

        # Should reject when signature verification fails for other reasons
        assert result is False
