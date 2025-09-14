"""
Certificate trust and chain validation checks.

This module contains checks related to certificate trust validation,
chain structure, intermediate certificate handling, signature verification,
and path validation according to RFC 5280.
"""

import logging
import socket
from typing import List, Optional
from urllib.error import URLError
from urllib.request import urlopen

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding

from ..models import (
    BaseCheck,
    ValidationFinding,
    ValidationSeverity,
    ValidationCheck,
    CheckInfo,
)

# Chain fetching constants
MAX_CHAIN_DEPTH = 10  # Prevent infinite loops when following certificate chains


class TrustCheck(BaseCheck):
    """Certificate trust and chain validation checks"""

    def __init__(self, config: dict = None, timeout: int = 10, thread_manager=None):
        super().__init__(config)
        self.timeout = timeout
        self.thread_manager = thread_manager
        self.logger = logging.getLogger(__name__)
        self._intermediate_cache = {}
        self._trust_store = None
        
    def get_check_info(self) -> CheckInfo:
        return CheckInfo(
            check_id="TRUST",
            title="Certificate Trust and Chain Checks",
            description="Validates certificate trust, chain structure, intermediate fetching, and signature verification"
        )

    def _register_checks(self) -> None:
        """Register all trust and chain-related checks"""

        # CRITICAL severity checks
        self.register_check(ValidationCheck(
            check_id="TRUST.SELF_SIGNED",
            title="Self-Signed Certificate",
            description="This certificate is self-signed and not issued by a trusted Certificate Authority",
            remediation="For production use, obtain a certificate from a trusted Certificate Authority (CA)",
        ))
        
        self.register_check(ValidationCheck(
            check_id="TRUST.UNTRUSTED_ROOT",
            title="Untrusted Root Certificate",
            description="Certificate chain does not terminate at a trusted root",
            remediation="Ensure certificate is issued by a trusted Certificate Authority",
        ))
        
        # HIGH severity checks  
        self.register_check(ValidationCheck(
            check_id="TRUST.SIGNATURE_INVALID",
            title="Invalid Certificate Chain Signature",
            description="Certificate signature verification failed in the chain",
            remediation="Verify certificate chain integrity and order",
        ))
        
        self.register_check(ValidationCheck(
            check_id="TRUST.VALIDATION_ERROR",
            title="Chain Validation Error",
            description="Failed to perform chain validation",
            remediation="Check certificate and network connectivity",
        ))
        
        self.register_check(ValidationCheck(
            check_id="TRUST.PATH_VALIDATION_FAILED",
            title="Path Validation Failed",
            description="Certificate chain path validation failed",
            remediation="Verify certificate chain meets RFC 5280 requirements",
        ))
        
        self.register_check(ValidationCheck(
            check_id="TRUST.HOSTNAME_MISMATCH",
            title="Trust Hostname Mismatch",
            description="Hostname validation failed in trust context",
            remediation="Ensure certificate matches the intended hostname",
        ))
        
        self.register_check(ValidationCheck(
            check_id="TRUST.EXPIRED_IN_CHAIN",
            title="Expired Certificate in Chain",
            description="One or more certificates in the chain have expired",
            remediation="Renew expired certificates in the chain",
        ))
        
        self.register_check(ValidationCheck(
            check_id="TRUST.REVOKED_IN_CHAIN",
            title="Revoked Certificate in Chain",
            description="One or more certificates in the chain have been revoked",
            remediation="Replace revoked certificates with valid ones",
        ))
        
        # MEDIUM severity checks
        self.register_check(ValidationCheck(
            check_id="TRUST.INCOMPLETE_CHAIN",
            title="Incomplete Certificate Chain",
            description="Certificate chain contains only the end-entity certificate",
            remediation="Ensure server provides complete certificate chain including intermediates",
        ))
        
        self.register_check(ValidationCheck(
            check_id="TRUST.INTERMEDIATE_MISSING_REVOCATION",
            title="Intermediate Missing Revocation Information",
            description="Intermediate certificate lacks OCSP and CRL revocation information",
            remediation="Use intermediate certificates with revocation checking capabilities",
        ))
        
        self.register_check(ValidationCheck(
            check_id="TRUST.STORE_UNAVAILABLE",
            title="Trust Store Unavailable",
            description="System trust store is not available for validation",
            remediation="Ensure system has proper trust store configuration",
        ))
        
        self.register_check(ValidationCheck(
            check_id="TRUST.PATH_VALIDATION_ERROR",
            title="Path Validation Error",
            description="Error occurred during RFC 5280 path validation",
            remediation="Check certificate chain structure and validity",
        ))
        
        # INFO severity checks
        self.register_check(ValidationCheck(
            check_id="TRUST.AIA_FETCH_SUCCESS",
            title="Intermediate Fetched via AIA",
            description="Successfully fetched intermediate certificate via Authority Information Access",
        ))

    def validate(
        self, certificate: x509.Certificate, context: dict = None
    ) -> List[ValidationFinding]:
        """Validate certificate trust and chain"""
        findings = []

        try:
            # Get certificate chain from context or fetch it
            chain = self._get_certificate_chain(certificate, context)
            
            # Perform comprehensive chain path validation
            findings.extend(self._validate_chain_path(chain, context))

        except Exception as e:
            self.logger.error(f"Trust validation failed: {e}")
            findings.append(
                self.create_finding(
                    check_id="TRUST.VALIDATION_ERROR",
                    evidence={"error": str(e)}
                )
            )

        return [f for f in findings if self.is_check_enabled(f.check_id)]
    
    def _validate_chain_path(
        self, chain: List[x509.Certificate], context: dict = None
    ) -> List[ValidationFinding]:
        """Validate certificate chain path including signatures, trust store, and revocation"""
        findings = []
        
        try:
            # Basic chain verification
            findings.extend(self._validate_chain_signatures(chain))

            # Revocation checking for intermediates
            findings.extend(self._validate_intermediate_revocation(chain))
            
            # Trust store validation
            findings.extend(self._validate_trust_store(chain, context))
            
        except Exception as e:
            self.logger.debug(f"Path validation error: {e}")
            findings.append(
                self.create_finding(
                    check_id="TRUST.PATH_VALIDATION_ERROR",
                    evidence={"error": str(e)}
                )
            )
        
        return findings

    def _validate_trust_store(
        self, chain: List[x509.Certificate], context: dict = None
    ) -> List[ValidationFinding]:
        """Validate certificate using system trust store"""
        findings = []
        
        # Get trust store using the dedicated method
        store = self._get_trust_store()
        
        if store is None:
            findings.append(
                self.create_finding(
                    check_id="TRUST.STORE_UNAVAILABLE",
                    evidence={"error": "Trust store validation dependencies not available"}
                )
            )
            return findings
        
        try:
            # Import here to avoid dependency issues
            try:
                from cryptography.x509.verification import PolicyBuilder
                
                # Build policy with the retrieved store
                builder = PolicyBuilder().store(store)
                verifier = builder.build_server_verifier(x509.DNSName("example.com"))
                
                # Perform validation
                leaf_cert = chain[0]
                intermediates = chain[1:] if len(chain) > 1 else []
                
                try:
                    # Attempt path validation
                    chain_result = verifier.verify(leaf_cert, intermediates)
                    
                    # Check if the result indicates untrusted (empty chain)
                    if not chain_result:
                        findings.append(
                            self.create_finding(
                                check_id="TRUST.UNTRUSTED_ROOT",
                                evidence={"validation_error": "Certificate chain validation returned empty result"}
                            )
                        )
                    
                except Exception as validation_error:
                    error_msg = str(validation_error).lower()
                    
                    if "untrusted" in error_msg or "unknown" in error_msg:
                        findings.append(
                            self.create_finding(
                                check_id="TRUST.UNTRUSTED_ROOT",
                                evidence={"validation_error": str(validation_error)}
                            )
                        )
                    elif "expired" in error_msg:
                        findings.append(
                            self.create_finding(
                                check_id="TRUST.EXPIRED_IN_CHAIN",
                                evidence={"validation_error": str(validation_error)}
                            )
                        )
                    elif "revoked" in error_msg:
                        findings.append(
                            self.create_finding(
                                check_id="TRUST.REVOKED_IN_CHAIN",
                                evidence={"validation_error": str(validation_error)}
                            )
                        )
                    elif "hostname" in error_msg:
                        findings.append(
                            self.create_finding(
                                check_id="TRUST.HOSTNAME_MISMATCH",
                                evidence={"validation_error": str(validation_error)}
                            )
                        )
                    else:
                        # Generic untrusted root for other validation failures
                        findings.append(
                            self.create_finding(
                                check_id="TRUST.UNTRUSTED_ROOT",
                                evidence={"validation_error": str(validation_error)}
                            )
                        )
                        findings.append(
                            self.create_finding(
                                check_id="TRUST.PATH_VALIDATION_FAILED",
                                evidence={"validation_error": str(validation_error)}
                            )
                        )
                        
            except ImportError:
                # certifi or cryptography validation not available
                findings.append(
                    self.create_finding(
                        check_id="TRUST.STORE_UNAVAILABLE",
                        evidence={"error": "Trust store validation dependencies not available"}
                    )
                )
                
        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="TRUST.PATH_VALIDATION_ERROR",
                    evidence={"error": str(e)}
                )
            )
            
        return findings

    def _get_trust_store(self):
        """Get system trust store with fallback"""
        # Return cached store if available
        if self._trust_store is not None:
            return self._trust_store
            
        try:
            # Try using truststore first
            import truststore
            import ssl
            truststore.inject_into_ssl()
            ssl.create_default_context()
            store = self._load_system_ca_fallback()
            self._trust_store = store
            return store
        except Exception:
            # Fall back to manual CA loading
            store = self._load_system_ca_fallback()
            self._trust_store = store
            return store
    
    def _load_system_ca_fallback(self):
        """Load system CA certificates as fallback"""
        try:
            import certifi
            from cryptography.x509.verification import Store
            import os
            
            # Try common CA bundle paths
            ca_paths = [
                certifi.where(),  # certifi bundle
                '/etc/ssl/certs/ca-certificates.crt',  # Debian/Ubuntu
                '/etc/pki/tls/certs/ca-bundle.crt',   # RHEL/CentOS
                '/etc/ssl/ca-bundle.pem',             # OpenSUSE
            ]
            
            for ca_path in ca_paths:
                if os.path.exists(ca_path):
                    try:
                        with open(ca_path, 'rb') as f:
                            ca_bundle = f.read()
                        
                        # Parse certificates and create store
                        certs = []
                        current_cert = b""
                        in_cert = False
                        
                        for line in ca_bundle.split(b'\n'):
                            if b'-----BEGIN CERTIFICATE-----' in line:
                                in_cert = True
                                current_cert = line + b'\n'
                            elif b'-----END CERTIFICATE-----' in line:
                                current_cert += line + b'\n'
                                try:
                                    from cryptography import x509
                                    from cryptography.utils import CryptographyDeprecationWarning
                                    import warnings
                                    with warnings.catch_warnings():
                                        warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
                                        cert = x509.load_pem_x509_certificate(current_cert)
                                    certs.append(cert)
                                except Exception:
                                    pass
                                current_cert = b""
                                in_cert = False
                            elif in_cert:
                                current_cert += line + b'\n'
                        
                        if certs:
                            store = Store(certs)
                            return store
                    except Exception:
                        continue
            
            return None
        except Exception:
            return None

    def _is_root_ca(self, certificate: x509.Certificate) -> bool:
        """Check if a certificate is a root CA (self-signed)"""
        try:
            return certificate.subject == certificate.issuer
        except Exception:
            return False

    def _get_certificate_chain(
        self, certificate: x509.Certificate, context: dict = None
    ) -> List[x509.Certificate]:
        """Get full certificate chain using hybrid approach"""
        chain = [certificate]

        # Try to get chain from context (server-provided)
        if context and "certificate_chain" in context:
            server_chain = context["certificate_chain"]
            if isinstance(server_chain, list) and len(server_chain) > 1:
                return server_chain

        # Fetch missing intermediates using AIA
        try:
            self.logger.debug(
                f"Attempting to fetch intermediate certificates via AIA for certificate subject: {certificate.subject}"
            )
            intermediates = self._fetch_intermediate_certificates(certificate)
            if intermediates:
                self.logger.debug(
                    f"Successfully fetched {len(intermediates)} intermediate certificate(s)"
                )
                chain.extend(intermediates)
            else:
                self.logger.debug("No intermediate certificates found via AIA")
        except Exception as e:
            self.logger.debug(f"Failed to fetch intermediate certificates: {e}")

        self.logger.debug(f"Final certificate chain length: {len(chain)}")
        return chain

    def _fetch_intermediate_certificates(
        self, certificate: x509.Certificate
    ) -> List[x509.Certificate]:
        """Fetch intermediate certificates using Authority Information Access extension"""
        if self.thread_manager:
            return self._fetch_intermediate_certificates_parallel(certificate)
        else:
            return self._fetch_intermediate_certificates_sequential(certificate)

    def _fetch_intermediate_certificates_sequential(
        self, certificate: x509.Certificate
    ) -> List[x509.Certificate]:
        """Fetch intermediate certificates sequentially"""
        intermediates = []
        current_cert = certificate
        visited_urls = set()

        for _ in range(MAX_CHAIN_DEPTH):  # Prevent infinite loops
            ca_issuers_urls = self._extract_ca_issuers_urls(current_cert)
            if not ca_issuers_urls:
                break

            intermediate_cert = None
            for url in ca_issuers_urls:
                if url in visited_urls:
                    continue
                visited_urls.add(url)

                try:
                    self.logger.debug(
                        f"Attempting to download intermediate certificate from: {url}"
                    )
                    intermediate_cert = self._download_certificate(url)
                    if intermediate_cert:
                        self.logger.debug(
                            f"Successfully downloaded intermediate certificate: {intermediate_cert.subject}"
                        )
                        if self._verify_issuer_relationship(current_cert, intermediate_cert):
                            self.logger.debug("Intermediate certificate verified as issuer")
                            intermediates.append(intermediate_cert)
                            current_cert = intermediate_cert
                            break
                        else:
                            self.logger.debug("Intermediate certificate does not match as issuer")
                    else:
                        self.logger.debug(f"Failed to download certificate from {url}")
                except Exception as e:
                    self.logger.debug(f"Exception downloading intermediate from {url}: {e}")

            if not intermediate_cert:
                break

        return intermediates

    def _fetch_intermediate_certificates_parallel(
        self, certificate: x509.Certificate
    ) -> List[x509.Certificate]:
        """Fetch intermediate certificates using parallel processing"""
        # For now, delegate to sequential since parallel implementation would be complex
        # The thread_manager can be used for other parallel operations
        return self._fetch_intermediate_certificates_sequential(certificate)

    def _extract_ca_issuers_urls(self, certificate: x509.Certificate) -> List[str]:
        """Extract CA Issuers URLs from Authority Information Access extension"""
        try:
            aia = certificate.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.AUTHORITY_INFORMATION_ACCESS
            )
            ca_issuers_urls = []

            self.logger.debug(f"Found AIA extension with {len(aia.value)} access descriptions")

            for access_description in aia.value:
                self.logger.debug(f"AIA access method: {access_description.access_method}")
                if (
                    access_description.access_method
                    == x509.oid.AuthorityInformationAccessOID.CA_ISSUERS
                ):
                    if isinstance(
                        access_description.access_location,
                        x509.UniformResourceIdentifier,
                    ):
                        url = access_description.access_location.value
                        self.logger.debug(f"Found CA Issuers URL: {url}")
                        if url.startswith(("http://", "https://")):
                            ca_issuers_urls.append(url)
                        else:
                            self.logger.debug(f"Skipping non-HTTP URL: {url}")

            self.logger.debug(f"Extracted {len(ca_issuers_urls)} CA Issuers URLs: {ca_issuers_urls}")
            return ca_issuers_urls
        except x509.ExtensionNotFound:
            self.logger.debug("No Authority Information Access extension found")
            return []

    def _download_certificate(self, url: str) -> Optional[x509.Certificate]:
        """Download certificate from URL with caching"""
        if url in self._intermediate_cache:
            return self._intermediate_cache[url]

        try:
            with urlopen(url, timeout=self.timeout) as response:
                cert_data = response.read()

                # Try DER format first, then PEM
                try:
                    cert = x509.load_der_x509_certificate(cert_data)
                except ValueError:
                    try:
                        cert = x509.load_pem_x509_certificate(cert_data)
                    except ValueError:
                        self.logger.debug(f"Certificate from {url} is not in DER or PEM format")
                        return None

                self._intermediate_cache[url] = cert
                return cert

        except (URLError, socket.timeout) as e:
            self.logger.debug(f"Failed to download certificate from {url}: {e}")
            return None

    def _verify_issuer_relationship(
        self, subject_cert: x509.Certificate, issuer_cert: x509.Certificate
    ) -> bool:
        """Verify that issuer_cert actually issued subject_cert"""
        try:
            self.logger.debug(f"Verifying issuer relationship:")
            self.logger.debug(f"  Subject cert issuer: {subject_cert.issuer}")
            self.logger.debug(f"  Issuer cert subject: {issuer_cert.subject}")

            if subject_cert.issuer != issuer_cert.subject:
                self.logger.debug("Issuer names do not match")
                return False

            self.logger.debug("Issuer names match, verifying signature...")

            # Verify signature (but be lenient with unsupported algorithms)
            issuer_public_key = issuer_cert.public_key()
            try:
                signature_algorithm = subject_cert.signature_hash_algorithm

                if hasattr(issuer_public_key, "verify"):
                    if hasattr(issuer_public_key, "curve"):  # ECDSA key
                        issuer_public_key.verify(
                            subject_cert.signature,
                            subject_cert.tbs_certificate_bytes,
                            signature_algorithm,
                        )
                    else:  # RSA key
                        issuer_public_key.verify(
                            subject_cert.signature,
                            subject_cert.tbs_certificate_bytes,
                            padding.PKCS1v15(),
                            signature_algorithm,
                        )
                self.logger.debug("Signature verification successful")
                return True
            except Exception as e:
                error_msg = str(e).lower()
                if "unsupported" in error_msg and ("elliptic" in error_msg or "ecdsa" in error_msg):
                    self.logger.debug(f"Signature verification unsupported but names match - accepting: {e}")
                    return True
                else:
                    self.logger.debug(f"Signature verification failed: {e}")
                    return False

        except Exception as e:
            self.logger.debug(f"Exception in issuer verification: {e}")
            return False

    def _validate_chain_signatures(self, chain: List[x509.Certificate]) -> List[ValidationFinding]:
        """Validate signatures in certificate chain"""
        findings = []

        if len(chain) < 2:
            # Check if this is a self-signed certificate
            is_self_signed = len(chain) == 1 and self._is_root_ca(chain[0])
            
            if is_self_signed:
                findings.append(
                    self.create_finding(
                        check_id="TRUST.SELF_SIGNED",
                        evidence={"is_self_signed": True, "subject": str(chain[0].subject).replace('\n', ' ')}
                    )
                )
            else:
                # Only flag as incomplete if it's not self-signed
                findings.append(
                    self.create_finding(
                        check_id="TRUST.INCOMPLETE_CHAIN",
                        evidence={"chain_length": len(chain)}
                    )
                )
            return findings

        # Verify each certificate in the chain
        for i in range(len(chain) - 1):
            subject_cert = chain[i]
            issuer_cert = chain[i + 1]

            if not self._verify_issuer_relationship(subject_cert, issuer_cert):
                findings.append(
                    self.create_finding(
                        check_id="TRUST.SIGNATURE_INVALID",
                        evidence={"position": i, "subject": str(subject_cert.subject).replace('\n', ' ')}
                    )
                )

        return findings

    def _validate_intermediate_revocation(self, chain: List[x509.Certificate]) -> List[ValidationFinding]:
        """Check revocation information for intermediate certificates"""
        findings = []

        # Skip end-entity certificate and root CAs (self-signed)
        intermediates = []
        for cert in chain[1:]:  # Skip end-entity
            if not self._is_root_ca(cert):  # Skip root CAs
                intermediates.append(cert)

        for i, intermediate in enumerate(intermediates):
            try:
                # Check if intermediate has revocation information
                has_ocsp = self._has_ocsp_endpoint(intermediate)
                has_crl = self._has_crl_endpoint(intermediate)

                if not has_ocsp and not has_crl:
                    findings.append(
                        self.create_finding(
                            check_id="TRUST.INTERMEDIATE_MISSING_REVOCATION",
                            evidence={
                                "position": i + 1,
                                "subject": str(intermediate.subject),
                            }
                        )
                    )

            except Exception as e:
                self.logger.debug(f"Error checking revocation info for intermediate {i+1}: {e}")

        return findings

    def _has_ocsp_endpoint(self, certificate: x509.Certificate) -> bool:
        """Check if certificate has OCSP endpoint"""
        try:
            aia = certificate.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.AUTHORITY_INFORMATION_ACCESS
            )
            for access_description in aia.value:
                if (
                    access_description.access_method
                    == x509.oid.AuthorityInformationAccessOID.OCSP
                ):
                    return True
        except x509.ExtensionNotFound:
            pass
        return False

    def _has_crl_endpoint(self, certificate: x509.Certificate) -> bool:
        """Check if certificate has CRL endpoint"""
        try:
            crl_dp = certificate.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.CRL_DISTRIBUTION_POINTS
            )
            return len(crl_dp.value) > 0
        except x509.ExtensionNotFound:
            pass
        return False