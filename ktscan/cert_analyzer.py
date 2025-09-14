import logging
import socket
import ssl
from typing import Optional, List, Dict, Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

from .check_registry import check_registry
from .models import (
    ValidationFinding,
    ValidationSeverity,
    ScanResult,
    SecuritySummary,
    ScanStatus,
)

# Security scoring constants
MAX_SECURITY_SCORE = 100
CRITICAL_PENALTY = 25
HIGH_PENALTY = 10
MEDIUM_PENALTY = 3
LOW_PENALTY = 1
MIN_SECURITY_SCORE = 0


class CertAnalyzer:
    def __init__(
        self, timeout: int = 10, validation_config: Optional[Dict[str, Any]] = None, thread_manager: Optional[Any] = None
    ) -> None:
        self.timeout = timeout
        self.thread_manager = thread_manager
        self.logger = logging.getLogger(__name__)
        self.validation_config = validation_config or {}

        # Configure check registry based on validation config
        # Prioritize explicit standards over profiles
        if "standards" in self.validation_config:
            check_registry.configure_for_standards(self.validation_config["standards"])
        elif "profile" in self.validation_config:
            check_registry.configure_for_profile(self.validation_config["profile"])
        else:
            # Default to SERVER_DEFAULT profile when no specific configuration is provided
            check_registry.configure_for_profile("SERVER_DEFAULT")

    def scan_certificate(self, ip: str, port: int, hostname: str = "") -> ScanResult:
        # Create ScanResult directly
        result = ScanResult(
            target=hostname or f"{ip}:{port}",
            endpoints=[(ip, port)]
        )

        try:
            cert_der = self._get_certificate(ip, port, hostname)
            if not cert_der:
                result.errors.append("Failed to retrieve certificate")
                result.status = ScanStatus.FAILED
                return result

            cert = x509.load_der_x509_certificate(cert_der)
            
            # Parse certificate and populate ScanResult
            result = self._parse_certificate_to_scan_result(cert, result)
            
            # Certificate successfully parsed
            result.status = ScanStatus.SCANNED

        except ValueError as e:
            self.logger.error(f"Invalid certificate format for {ip}:{port} - {e}")
            result.errors.append(f"Invalid certificate: {str(e)}")
            result.status = ScanStatus.FAILED
        except OSError as e:
            self.logger.error(f"Network error scanning {ip}:{port} - {e}")
            result.errors.append(f"Network error: {str(e)}")
            result.status = ScanStatus.FAILED
        except Exception as e:
            self.logger.error(f"Unexpected error scanning {ip}:{port} - {e}")
            result.errors.append(f"Unexpected error: {str(e)}")
            result.status = ScanStatus.FAILED

        return result

    def _get_certificate(
        self, ip: str, port: int, hostname: str = ""
    ) -> Optional[bytes]:
        """
        Retrieve certificate from server for analysis purposes.
        
        Note: This intentionally disables certificate verification to allow
        analysis of invalid, expired, or self-signed certificates. This is
        safe because we're only retrieving the certificate for analysis,
        not trusting the connection for data exchange.
        """
        # Create SSL context optimized for certificate collection
        context = ssl.create_default_context()
        
        # Disable certificate verification ONLY for certificate collection
        # This is necessary to analyze invalid/expired/self-signed certificates
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        # Set secure cipher options while still allowing certificate retrieval
        context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
        context.minimum_version = ssl.TLSVersion.TLSv1_2

        try:
            addr_info = socket.getaddrinfo(
                ip, port, socket.AF_UNSPEC, socket.SOCK_STREAM
            )
            if not addr_info:
                return None

            family, socktype, proto, canonname, sockaddr = addr_info[0]
            sock = socket.socket(family, socktype)
            sock.settimeout(self.timeout)

            try:
                sock.connect(sockaddr)
                server_hostname = hostname if hostname else ip
                with context.wrap_socket(
                    sock, server_hostname=server_hostname
                ) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    return cert_der
            finally:
                sock.close()

        except ssl.SSLError as e:
            self.logger.debug(f"SSL error retrieving certificate from {ip}:{port} - {e}")
            return None
        except socket.timeout:
            self.logger.debug(f"Timeout retrieving certificate from {ip}:{port}")
            return None
        except socket.error as e:
            self.logger.debug(f"Socket error retrieving certificate from {ip}:{port} - {e}")
            return None
        except Exception as e:
            self.logger.warning(f"Unexpected error retrieving certificate from {ip}:{port} - {e}")
            return None


    def _parse_certificate_to_scan_result(
        self, cert: x509.Certificate, result: ScanResult
    ) -> ScanResult:
        try:
            # Create CertificateData object
            from .models import CertificateData
            
            expires = cert.not_valid_after_utc
            issued = cert.not_valid_before_utc
            
            issuer = self._extract_name_attribute(
                cert.issuer, NameOID.COMMON_NAME
            ) or str(cert.issuer).replace('\n', ' ')
            subject = self._extract_name_attribute(
                cert.subject, NameOID.COMMON_NAME
            ) or str(cert.subject).replace('\n', ' ')
            
            serial_number = str(cert.serial_number)
            signature_algorithm = cert.signature_algorithm_oid._name
            
            public_key = cert.public_key()
            key_size = getattr(public_key, "key_size", None)
            public_key_algorithm = self._get_public_key_algorithm(public_key)
            
            san_domains = self._extract_san_domains(cert)
            certificate_fingerprint = self._calculate_certificate_fingerprint(cert)
            
            # Create CertificateData with all parsed information
            result.certificate = CertificateData(
                subject=subject,
                san_domains=san_domains,
                issuer=issuer,
                valid=True,  # Will be updated during validation
                trusted=None,  # Will be updated during validation
                expires=expires,
                issued=issued,
                serial_number=serial_number,
                signature_algorithm=signature_algorithm,
                public_key_algorithm=public_key_algorithm,
                key_size=key_size,
                certificate_fingerprint=certificate_fingerprint,
                _certificate=cert  # Store the raw certificate for validation
            )

        except (AttributeError, ValueError, KeyError) as e:
            result.errors.append(f"Certificate parsing failed: {str(e)}")
            if result.certificate:
                result.certificate.valid = False
        except x509.ExtensionNotFound as e:
            # This is not necessarily an error, just missing extensions
            self.logger.debug(f"Extension not found during parsing: {e}")
        except Exception as e:
            result.errors.append(f"Unexpected error parsing certificate: {str(e)}")
            self.logger.warning(f"Unexpected certificate parsing error: {e}")
            if result.certificate:
                result.certificate.valid = False

        return result

    def _determine_trust_status(
        self, findings: List[ValidationFinding]
    ) -> Optional[bool]:
        """Determine if certificate is trusted based on chain validation results"""
        # Check if chain validation is enabled in configuration
        chain_config = self.validation_config.get("chain", {})
        disabled_checks = chain_config.get("disabled_checks", [])

        # If chain validation is explicitly disabled, return None
        if "chain_validation" in disabled_checks:
            return None

        # Chain validation is enabled - check for failure findings
        chain_findings = [
            f
            for f in findings
            if (f.check_id.startswith("CHAIN.") or 
                f.check_id.startswith("TRUST."))
        ]

        # Check for trust/chain validation failures using new check IDs
        trust_failures = [
            "CHAIN.PATH_VALIDATION_FAILED",
            "TRUST.PATH_VALIDATION_FAILED",
            "TRUST.STORE_UNAVAILABLE",
            "CHAIN.VALIDATION_ERROR",
            "CHAIN.SIGNATURE_INVALID",
            "CHAIN.SELF_SIGNED",  # Self-signed certificates are not trusted
            "TRUST.UNTRUSTED_ROOT",
        ]

        for finding in chain_findings:
            if finding.check_id in trust_failures:
                return False

        # If chain validation was enabled and no trust failures found, certificate is trusted
        return True

    def _get_public_key_algorithm(self, public_key: Any) -> str:
        """Extract the public key algorithm from the certificate's public key"""
        try:
            from cryptography.hazmat.primitives.asymmetric import (
                rsa,
                ec,
                ed25519,
                ed448,
                dsa,
            )

            if isinstance(public_key, rsa.RSAPublicKey):
                return "RSA"
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                curve_name = public_key.curve.name
                return f"ECDSA ({curve_name})"
            elif isinstance(public_key, ed25519.Ed25519PublicKey):
                return "Ed25519"
            elif isinstance(public_key, ed448.Ed448PublicKey):
                return "Ed448"
            elif isinstance(public_key, dsa.DSAPublicKey):
                return "DSA"
            else:
                # Fallback for unknown key types
                return (
                    type(public_key).__name__.replace("PublicKey", "").replace("_", " ")
                )
        except Exception as e:
            self.logger.debug(f"Failed to determine public key algorithm: {e}")
            return "Unknown"

    def _calculate_certificate_fingerprint(self, cert: x509.Certificate) -> str:
        """Calculate SHA-256 fingerprint of the certificate for deduplication"""
        try:
            from cryptography.hazmat.primitives import serialization

            cert_der = cert.public_bytes(encoding=serialization.Encoding.DER)
            digest = hashes.Hash(hashes.SHA256())
            digest.update(cert_der)
            fingerprint = digest.finalize()
            return fingerprint.hex()
        except Exception as e:
            self.logger.debug(f"Failed to calculate certificate fingerprint: {e}")
            return ""

    def _extract_name_attribute(
        self, name: x509.Name, oid: x509.ObjectIdentifier
    ) -> Optional[str]:
        try:
            attributes = name.get_attributes_for_oid(oid)
            if attributes:
                return attributes[0].value
        except Exception:
            pass
        return None

    def _extract_san_domains(self, cert: x509.Certificate) -> List[str]:
        domains = []
        try:
            san_extension = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            for name in san_extension.value:
                if isinstance(name, x509.DNSName):
                    domains.append(name.value)
                elif isinstance(name, x509.IPAddress):
                    domains.append(str(name.value))
        except x509.ExtensionNotFound:
            pass
        except Exception as e:
            self.logger.debug(f"Failed to extract SAN domains: {e}")

        return domains


    def _apply_severity_filtering(
        self, findings: List[ValidationFinding]
    ) -> List[ValidationFinding]:
        """Filter findings based on configured severity threshold"""
        if not findings:
            return findings

        severity_filter = self.validation_config.get("severity_filter", "MEDIUM")

        # Define severity hierarchy (lower index = lower severity)
        severity_order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

        try:
            threshold_index = severity_order.index(severity_filter)
        except ValueError:
            # If invalid severity filter, default to MEDIUM
            threshold_index = severity_order.index("MEDIUM")

        # Filter findings to only include those at or above the threshold
        filtered_findings = []
        for finding in findings:
            try:
                severity_str = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
                finding_index = severity_order.index(severity_str)
                if finding_index >= threshold_index:
                    filtered_findings.append(finding)
            except (ValueError, AttributeError):
                # If we can't determine severity, include the finding to be safe
                filtered_findings.append(finding)

        return filtered_findings


    def validate_scan_result(
        self, scan_result: 'ScanResult', hostname: str = None
    ) -> 'ScanResult':
        """Validate a ScanResult and update it with findings"""
        if not scan_result.certificate or not scan_result.certificate._certificate:
            return scan_result
        
        try:
            # Create validation context
            context = {
                "hostname": hostname,
                "ip": scan_result.primary_ip,
                "port": scan_result.primary_port,
            }

            # Run all check categories from registry
            all_findings = []
            for check_category in check_registry._checks.values():
                all_findings.extend(
                    check_category.validate(scan_result.certificate._certificate, context)
                )

            # Apply severity filtering based on configuration
            filtered_findings = self._apply_severity_filtering(all_findings)
            scan_result.findings = filtered_findings

            # Determine trust status from chain validation results
            scan_result.certificate.trusted = self._determine_trust_status(all_findings)

            # Calculate security score and summary
            self._calculate_scan_result_security_metrics(scan_result, all_findings)

            # Log validation results
            critical_findings = [
                f for f in all_findings if f.severity == ValidationSeverity.CRITICAL
            ]
            high_findings = [
                f for f in all_findings if f.severity == ValidationSeverity.HIGH
            ]

            if critical_findings:
                self.logger.debug(
                    f"Certificate has {len(critical_findings)} critical findings for {scan_result.primary_ip}:{scan_result.primary_port}"
                )
            if high_findings:
                self.logger.debug(
                    f"Certificate has {len(high_findings)} high severity findings for {scan_result.primary_ip}:{scan_result.primary_port}"
                )
            if not critical_findings and not high_findings:
                self.logger.debug(
                    f"Certificate passed critical/high validation for {scan_result.primary_ip}:{scan_result.primary_port}"
                )

        except Exception as e:
            scan_result.errors.append(f"Certificate validation failed: {str(e)}")
            if scan_result.certificate:
                scan_result.certificate.valid = False
            self.logger.error(f"Validation error for {scan_result.primary_ip}:{scan_result.primary_port}: {e}")

        return scan_result

    def _calculate_scan_result_security_metrics(
        self, scan_result: 'ScanResult', all_findings: List[ValidationFinding] = None
    ) -> None:
        """Calculate security metrics for a ScanResult"""
        # Use all findings for scoring if provided, otherwise use the filtered findings
        scoring_findings = all_findings if all_findings is not None else scan_result.findings

        if not scoring_findings:
            if scan_result.certificate:
                scan_result.certificate.valid = True
            scan_result.summary = SecuritySummary(security_score=MAX_SECURITY_SCORE)
            return

        # Count findings by severity (using all findings for accurate scoring)
        severity_counts = {
            ValidationSeverity.CRITICAL: 0,
            ValidationSeverity.HIGH: 0,
            ValidationSeverity.MEDIUM: 0,
            ValidationSeverity.LOW: 0,
            ValidationSeverity.INFO: 0,
        }

        for finding in scoring_findings:
            severity_counts[finding.severity] += 1

        # Certificate is invalid if it has critical findings
        certificate_valid = severity_counts[ValidationSeverity.CRITICAL] == 0
        if scan_result.certificate:
            scan_result.certificate.valid = certificate_valid

        # Calculate security score (0-100)
        score = MAX_SECURITY_SCORE
        score -= severity_counts[ValidationSeverity.CRITICAL] * CRITICAL_PENALTY
        score -= severity_counts[ValidationSeverity.HIGH] * HIGH_PENALTY
        score -= severity_counts[ValidationSeverity.MEDIUM] * MEDIUM_PENALTY
        score -= severity_counts[ValidationSeverity.LOW] * LOW_PENALTY

        security_score = max(MIN_SECURITY_SCORE, score)

        # Count filtered findings for summary
        filtered_severity_counts = {
            ValidationSeverity.CRITICAL: 0,
            ValidationSeverity.HIGH: 0,
            ValidationSeverity.MEDIUM: 0,
            ValidationSeverity.LOW: 0,
            ValidationSeverity.INFO: 0,
        }

        for finding in scan_result.findings:
            filtered_severity_counts[finding.severity] += 1

        # Create security summary
        scan_result.summary = SecuritySummary(
            security_score=security_score,
            critical_count=filtered_severity_counts[ValidationSeverity.CRITICAL],
            high_count=filtered_severity_counts[ValidationSeverity.HIGH],
            medium_count=filtered_severity_counts[ValidationSeverity.MEDIUM],
            low_count=filtered_severity_counts[ValidationSeverity.LOW],
            info_count=filtered_severity_counts[ValidationSeverity.INFO]
        )

