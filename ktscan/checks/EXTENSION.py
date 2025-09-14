"""
Extended Key Usage and Key Usage validation checks.

This module contains checks related to Key Usage, Extended Key Usage,
Basic Constraints, and certificate purpose validation.
"""

import logging
from typing import List

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, ExtendedKeyUsageOID

from ..models import (
    BaseCheck,
    ValidationFinding,
    ValidationSeverity,
    ValidationCheck,
    CheckInfo,
)


class EkuKuCheck(BaseCheck):
    """Extended Key Usage and Key Usage validation checks"""

    CRITICAL_KEY_USAGE_COMBINATIONS = {
        frozenset(
            [x509.KeyUsage.digital_signature, x509.KeyUsage.key_cert_sign]
        ): "Digital signature and certificate signing should not be combined",
        frozenset(
            [x509.KeyUsage.key_encipherment, x509.KeyUsage.key_cert_sign]
        ): "Key encipherment and certificate signing should not be combined",
    }

    def __init__(self, config: dict = None):
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        
    def get_check_info(self) -> CheckInfo:
        return CheckInfo(
            check_id="EXTENSION",
            title="Key Usage and Extended Key Usage Checks",
            description="Validates Key Usage, Extended Key Usage, Basic Constraints, and certificate purpose consistency"
        )

    def _register_checks(self) -> None:
        """Register all EKU/KU checks"""
        
        # CRITICAL severity checks
        self.register_check(ValidationCheck(
            check_id="EXTENSION.DANGEROUS_KEY_USAGE_COMBINATION",
            title="Dangerous Key Usage Combination",
            description="Certificate has dangerous key usage combination",
            remediation="Separate key usage purposes into different certificates",
        ))
        
        self.register_check(ValidationCheck(
            check_id="EXTENSION.CA_MISSING_CERT_SIGN",
            title="CA Missing Certificate Signing",
            description="CA certificate lacks Key Cert Sign usage",
            remediation="Add Key Cert Sign to Key Usage extension",
        ))
        
        self.register_check(ValidationCheck(
            check_id="EXTENSION.END_ENTITY_WITH_CERT_SIGN",
            title="End Entity with Certificate Signing",
            description="End entity certificate should not have Key Cert Sign usage",
            remediation="Remove Key Cert Sign from Key Usage extension or set CA=TRUE",
        ))
        
        # HIGH severity checks
        self.register_check(ValidationCheck(
            check_id="EXTENSION.MISSING_KEY_USAGE",
            title="Missing Key Usage Extension",
            description="Certificate lacks Key Usage extension",
            remediation="Add Key Usage extension to specify permitted cryptographic operations",
        ))
        
        self.register_check(ValidationCheck(
            check_id="EXTENSION.KEY_USAGE_PARSE_ERROR",
            title="Key Usage Parse Error",
            description="Failed to parse Key Usage extension",
            remediation="Verify certificate integrity and Key Usage extension format",
        ))
        
        self.register_check(ValidationCheck(
            check_id="EXTENSION.EXTENDED_KEY_USAGE_PARSE_ERROR",
            title="Extended Key Usage Parse Error",
            description="Failed to parse Extended Key Usage extension",
            remediation="Verify certificate integrity and Extended Key Usage extension format",
        ))
        
        self.register_check(ValidationCheck(
            check_id="EXTENSION.BASIC_CONSTRAINTS_PARSE_ERROR",
            title="Basic Constraints Parse Error",
            description="Failed to parse Basic Constraints extension",
            remediation="Verify certificate integrity and Basic Constraints extension format",
        ))
        
        self.register_check(ValidationCheck(
            check_id="EXTENSION.RFC5280_CA_BASIC_CONSTRAINTS_NOT_CRITICAL",
            title="RFC 5280 CA Basic Constraints Not Critical",
            description="CA certificate's Basic Constraints extension must be critical per RFC 5280",
            remediation="Mark Basic Constraints extension as critical for CA certificates",
        ))
        
        self.register_check(ValidationCheck(
            check_id="EXTENSION.RFC5280_UNKNOWN_CRITICAL_EXTENSION",
            title="RFC 5280 Unknown Critical Extension",
            description="Certificate contains unknown critical extension",
            remediation="Remove unknown critical extensions or ensure they are properly supported",
        ))
        
        self.register_check(ValidationCheck(
            check_id="EXTENSION.CABF_MISSING_POLICY_IDENTIFIER",
            title="CABF Missing Policy Identifier",
            description="Certificate lacks required CA/Browser Forum Policy Identifier",
            remediation="Add CA/Browser Forum Policy Identifier to Certificate Policies extension",
        ))
        
        self.register_check(ValidationCheck(
            check_id="EXTENSION.MISSING_CERTIFICATE_POLICIES",
            title="Missing Certificate Policies Extension",
            description="Certificate lacks Certificate Policies extension",
            remediation="Add Certificate Policies extension with appropriate policy identifiers",
        ))
        
        self.register_check(ValidationCheck(
            check_id="EXTENSION.CA_BASIC_CONSTRAINTS_NOT_CRITICAL",
            title="CA Basic Constraints Not Critical",
            description="CA certificate's Basic Constraints extension should be marked as critical",
            remediation="Mark Basic Constraints extension as critical for CA certificates",
        ))
        
        self.register_check(ValidationCheck(
            check_id="EXTENSION.INVALID_PATH_LENGTH",
            title="Invalid Path Length Constraint",
            description="CA certificate has invalid path length constraint",
            remediation="Set valid path length constraint (≥0) or remove constraint",
        ))
        
        self.register_check(ValidationCheck(
            check_id="EXTENSION.ANY_EXTENDED_KEY_USAGE",
            title="Any Extended Key Usage",
            description="Certificate allows any extended key usage (anyExtendedKeyUsage)",
            remediation="Specify explicit Extended Key Usage values instead of anyExtendedKeyUsage",
        ))
        
        self.register_check(ValidationCheck(
            check_id="EXTENSION.SERVER_AUTH_INSUFFICIENT_KEY_USAGE",
            title="Insufficient Key Usage for Server Auth",
            description="Server authentication requires Digital Signature or Key Encipherment",
            remediation="Add Digital Signature and/or Key Encipherment to Key Usage",
        ))
        
        self.register_check(ValidationCheck(
            check_id="EXTENSION.CODE_SIGNING_MISSING_DIGITAL_SIGNATURE",
            title="Code Signing Missing Digital Signature",
            description="Code signing requires Digital Signature in Key Usage",
            remediation="Add Digital Signature to Key Usage extension",
        ))
        
        # MEDIUM severity checks
        self.register_check(ValidationCheck(
            check_id="EXTENSION.MISSING_EXTENDED_KEY_USAGE",
            title="Missing Extended Key Usage Extension",
            description="Certificate lacks Extended Key Usage extension",
            remediation="Add Extended Key Usage extension to specify certificate purpose",
        ))
        
        self.register_check(ValidationCheck(
            check_id="EXTENSION.MISSING_BASIC_CONSTRAINTS",
            title="Missing Basic Constraints Extension",
            description="Certificate lacks Basic Constraints extension",
            remediation="Add Basic Constraints extension to clearly indicate CA status",
        ))
        
        self.register_check(ValidationCheck(
            check_id="EXTENSION.KEY_USAGE_NOT_CRITICAL",
            title="Key Usage Extension Not Critical",
            description="Key Usage extension should typically be marked as critical",
            remediation="Mark Key Usage extension as critical for better security",
        ))
        
        self.register_check(ValidationCheck(
            check_id="EXTENSION.CONFLICTING_EXTENDED_KEY_USAGE",
            title="Conflicting Extended Key Usage",
            description="Certificate has potentially conflicting purposes",
            remediation="Consider using separate certificates for different purposes",
        ))
        
        self.register_check(ValidationCheck(
            check_id="EXTENSION.KEY_USAGE_VALIDATION_ERROR",
            title="Key Usage Validation Error",
            description="Error validating key agreement related usage",
            remediation="Review certificate key usage configuration",
        ))
        
        # INFO severity checks
        self.register_check(ValidationCheck(
            check_id="EXTENSION.SERVER_AUTH_PRESENT",
            title="Server Authentication Purpose",
            description="Certificate is valid for server authentication (TLS/SSL)",
        ))
        
        self.register_check(ValidationCheck(
            check_id="EXTENSION.RFC5280_KEY_USAGE_CRITICAL_GOOD",
            title="RFC 5280 Compliant Key Usage",
            description="Key Usage extension is properly marked as critical",
        ))

    def validate(
        self, certificate: x509.Certificate, context: dict = None
    ) -> List[ValidationFinding]:
        """Validate Key Usage and Extended Key Usage"""
        findings = []

        findings.extend(self._validate_key_usage(certificate))
        findings.extend(self._validate_extended_key_usage(certificate))
        findings.extend(self._validate_basic_constraints(certificate))
        findings.extend(self._validate_usage_consistency(certificate))
        findings.extend(self._validate_rfc5280_extension_compliance(certificate))
        findings.extend(self._validate_certificate_policies(certificate))

        return [f for f in findings if self.is_check_enabled(f.check_id)]

    def _validate_key_usage(self, certificate: x509.Certificate) -> List[ValidationFinding]:
        """Validate Key Usage extension"""
        findings = []

        try:
            key_usage_ext = certificate.extensions.get_extension_for_oid(
                ExtensionOID.KEY_USAGE
            )
            key_usage = key_usage_ext.value

            findings.extend(self._check_key_usage_combinations(key_usage))
            findings.extend(self._check_key_usage_criticality(key_usage_ext))

        except x509.ExtensionNotFound:
            findings.append(
                self.create_finding(
                    check_id="EXTENSION.MISSING_KEY_USAGE",
                    evidence={}
                )
            )
        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="EXTENSION.KEY_USAGE_PARSE_ERROR",
                    evidence={"error": str(e)}
                )
            )

        return findings

    def _validate_extended_key_usage(self, certificate: x509.Certificate) -> List[ValidationFinding]:
        """Validate Extended Key Usage extension"""
        findings = []

        try:
            eku_ext = certificate.extensions.get_extension_for_oid(
                ExtensionOID.EXTENDED_KEY_USAGE
            )
            eku = eku_ext.value

            findings.extend(self._check_extended_key_usage_values(eku))
            findings.extend(self._check_eku_server_auth(eku))

        except x509.ExtensionNotFound:
            findings.append(
                self.create_finding(
                    check_id="EXTENSION.MISSING_EXTENDED_KEY_USAGE",
                    evidence={}
                )
            )
        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="EXTENSION.EXTENDED_KEY_USAGE_PARSE_ERROR",
                    evidence={"error": str(e)}
                )
            )

        return findings

    def _validate_basic_constraints(self, certificate: x509.Certificate) -> List[ValidationFinding]:
        """Validate Basic Constraints extension"""
        findings = []

        try:
            bc_ext = certificate.extensions.get_extension_for_oid(
                ExtensionOID.BASIC_CONSTRAINTS
            )
            basic_constraints = bc_ext.value

            if basic_constraints.ca:
                findings.extend(
                    self._validate_ca_certificate(basic_constraints, certificate)
                )
            else:
                findings.extend(
                    self._validate_end_entity_certificate(
                        basic_constraints, certificate
                    )
                )

            if not bc_ext.critical and basic_constraints.ca:
                findings.append(
                    self.create_finding(
                        check_id="EXTENSION.CA_BASIC_CONSTRAINTS_NOT_CRITICAL",
                        evidence={"is_ca": basic_constraints.ca}
                    )
                )

        except x509.ExtensionNotFound:
            findings.append(
                self.create_finding(
                    check_id="EXTENSION.MISSING_BASIC_CONSTRAINTS",
                    evidence={}
                )
            )
        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="EXTENSION.BASIC_CONSTRAINTS_PARSE_ERROR",
                    evidence={"error": str(e)}
                )
            )

        return findings

    def _check_key_usage_combinations(self, key_usage: x509.KeyUsage) -> List[ValidationFinding]:
        """Check for dangerous key usage combinations"""
        findings = []

        active_usages = set()
        usage_attributes = [
            "digital_signature",
            "content_commitment",
            "key_encipherment",
            "data_encipherment",
            "key_agreement",
            "key_cert_sign",
            "crl_sign",
            "encipher_only",
            "decipher_only",
        ]

        for attr in usage_attributes:
            try:
                if getattr(key_usage, attr):
                    active_usages.add(getattr(x509.KeyUsage, attr))
            except ValueError:
                pass

        for forbidden_combo, message in self.CRITICAL_KEY_USAGE_COMBINATIONS.items():
            if forbidden_combo.issubset(active_usages):
                findings.append(
                    self.create_finding(
                        check_id="EXTENSION.DANGEROUS_KEY_USAGE_COMBINATION",
                        evidence={
                            "active_usages": [str(usage) for usage in active_usages],
                            "violation_message": message
                        }
                    )
                )

        # Check encipher_only/decipher_only only when key_agreement is True
        try:
            if key_usage.key_agreement:
                try:
                    if key_usage.encipher_only:
                        pass  # Valid combination
                except ValueError:
                    pass

                try:
                    if key_usage.decipher_only:
                        pass  # Valid combination
                except ValueError:
                    pass
        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="EXTENSION.KEY_USAGE_VALIDATION_ERROR",
                    evidence={"error": str(e)}
                )
            )

        return findings

    def _check_key_usage_criticality(self, key_usage_ext) -> List[ValidationFinding]:
        """Check Key Usage extension criticality"""
        findings = []

        if not key_usage_ext.critical:
            findings.append(
                self.create_finding(
                    check_id="EXTENSION.KEY_USAGE_NOT_CRITICAL",
                    evidence={}
                )
            )

        return findings

    def _check_extended_key_usage_values(self, eku: x509.ExtendedKeyUsage) -> List[ValidationFinding]:
        """Check Extended Key Usage values for issues"""
        findings = []

        if ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE in eku:
            findings.append(
                self.create_finding(
                    check_id="EXTENSION.ANY_EXTENDED_KEY_USAGE",
                    evidence={"eku_oids": [str(oid) for oid in eku]}
                )
            )

        conflicting_purposes = []
        if (
            ExtendedKeyUsageOID.SERVER_AUTH in eku
            and ExtendedKeyUsageOID.CLIENT_AUTH in eku
        ):
            conflicting_purposes.append("server and client authentication")

        if (
            ExtendedKeyUsageOID.CODE_SIGNING in eku
            and ExtendedKeyUsageOID.SERVER_AUTH in eku
        ):
            conflicting_purposes.append("code signing and server authentication")

        if conflicting_purposes:
            findings.append(
                self.create_finding(
                    check_id="EXTENSION.CONFLICTING_EXTENDED_KEY_USAGE",
                    evidence={"purposes": conflicting_purposes}
                )
            )

        return findings

    def _check_eku_server_auth(self, eku: x509.ExtendedKeyUsage) -> List[ValidationFinding]:
        """Check for server authentication purpose"""
        findings = []

        if ExtendedKeyUsageOID.SERVER_AUTH in eku:
            findings.append(
                self.create_finding(
                    check_id="EXTENSION.SERVER_AUTH_PRESENT",
                    evidence={}
                )
            )

        return findings

    def _validate_ca_certificate(
        self, basic_constraints: x509.BasicConstraints, certificate: x509.Certificate
    ) -> List[ValidationFinding]:
        """Validate CA certificate requirements"""
        findings = []

        if (
            basic_constraints.path_length is not None
            and basic_constraints.path_length < 0
        ):
            findings.append(
                self.create_finding(
                    check_id="EXTENSION.INVALID_PATH_LENGTH",
                    evidence={"path_length": basic_constraints.path_length}
                )
            )

        try:
            key_usage_ext = certificate.extensions.get_extension_for_oid(
                ExtensionOID.KEY_USAGE
            )
            if not key_usage_ext.value.key_cert_sign:
                findings.append(
                    self.create_finding(
                        check_id="EXTENSION.CA_MISSING_CERT_SIGN",
                        evidence={}
                    )
                )
        except x509.ExtensionNotFound:
            pass

        return findings

    def _validate_end_entity_certificate(
        self, basic_constraints: x509.BasicConstraints, certificate: x509.Certificate
    ) -> List[ValidationFinding]:
        """Validate end entity certificate requirements"""
        findings = []

        try:
            key_usage_ext = certificate.extensions.get_extension_for_oid(
                ExtensionOID.KEY_USAGE
            )
            if key_usage_ext.value.key_cert_sign:
                findings.append(
                    self.create_finding(
                        check_id="EXTENSION.END_ENTITY_WITH_CERT_SIGN",
                        evidence={}
                    )
                )
        except x509.ExtensionNotFound:
            pass

        return findings

    def _validate_usage_consistency(self, certificate: x509.Certificate) -> List[ValidationFinding]:
        """Validate consistency between Key Usage and Extended Key Usage"""
        findings = []

        try:
            key_usage_ext = certificate.extensions.get_extension_for_oid(
                ExtensionOID.KEY_USAGE
            )
            eku_ext = certificate.extensions.get_extension_for_oid(
                ExtensionOID.EXTENDED_KEY_USAGE
            )

            key_usage = key_usage_ext.value
            eku = eku_ext.value

            if ExtendedKeyUsageOID.SERVER_AUTH in eku and not (
                key_usage.digital_signature or key_usage.key_encipherment
            ):
                findings.append(
                    self.create_finding(
                        check_id="EXTENSION.SERVER_AUTH_INSUFFICIENT_KEY_USAGE",
                        evidence={}
                    )
                )

            if (
                ExtendedKeyUsageOID.CODE_SIGNING in eku
                and not key_usage.digital_signature
            ):
                findings.append(
                    self.create_finding(
                        check_id="EXTENSION.CODE_SIGNING_MISSING_DIGITAL_SIGNATURE",
                        evidence={}
                    )
                )

        except x509.ExtensionNotFound:
            pass

        return findings

    def _validate_rfc5280_extension_compliance(self, certificate: x509.Certificate) -> List[ValidationFinding]:
        """Validate RFC 5280 extension compliance requirements"""
        findings = []

        # Check Key Usage extension criticality
        try:
            key_usage_ext = certificate.extensions.get_extension_for_oid(
                ExtensionOID.KEY_USAGE
            )
            if key_usage_ext.critical:
                findings.append(
                    self.create_finding(
                        check_id="EXTENSION.RFC5280_KEY_USAGE_CRITICAL_GOOD",
                        evidence={},
                    )
                )
        except x509.ExtensionNotFound:
            pass

        # Check Basic Constraints criticality for CA certificates
        try:
            basic_constraints_ext = certificate.extensions.get_extension_for_oid(
                ExtensionOID.BASIC_CONSTRAINTS
            )
            if basic_constraints_ext.value.ca and not basic_constraints_ext.critical:
                findings.append(
                    self.create_finding(
                        check_id="EXTENSION.RFC5280_CA_BASIC_CONSTRAINTS_NOT_CRITICAL",
                        evidence={},
                    )
                )
        except x509.ExtensionNotFound:
            pass

        # Check for unknown critical extensions
        for extension in certificate.extensions:
            if not hasattr(extension, "critical"):
                continue

            if extension.critical and extension.oid._name.startswith("unknown"):
                findings.append(
                    self.create_finding(
                        check_id="EXTENSION.RFC5280_UNKNOWN_CRITICAL_EXTENSION",
                        evidence={"extension_oid": str(extension.oid)},
                    )
                )

        return findings

    def _validate_certificate_policies(self, certificate: x509.Certificate) -> List[ValidationFinding]:
        """Validate Certificate Policies extension and CABF requirements"""
        findings = []
        
        # CABF Policy Identifier (commonly used OIDs)
        CABF_POLICY_OIDS = [
            "2.23.140.1.2.1",  # Domain Validated
            "2.23.140.1.2.2",  # Organization Validated  
            "2.23.140.1.2.3",  # Extended Validation
        ]
        
        try:
            cert_policies_ext = certificate.extensions.get_extension_for_oid(
                ExtensionOID.CERTIFICATE_POLICIES
            )
            
            # Check if certificate has CABF policy identifier
            has_cabf_policy = False
            for policy in cert_policies_ext.value:
                policy_oid_str = str(policy.policy_identifier)
                if policy_oid_str in CABF_POLICY_OIDS:
                    has_cabf_policy = True
                    break
                    
            if not has_cabf_policy:
                findings.append(
                    self.create_finding(
                        check_id="EXTENSION.CABF_MISSING_POLICY_IDENTIFIER",
                        evidence={
                            "present_policies": [str(p.policy_identifier) for p in cert_policies_ext.value],
                            "required_cabf_policies": CABF_POLICY_OIDS
                        },
                    )
                )
                
        except x509.ExtensionNotFound:
            findings.append(
                self.create_finding(
                    check_id="EXTENSION.MISSING_CERTIFICATE_POLICIES",
                    evidence={},
                )
            )
            
        return findings