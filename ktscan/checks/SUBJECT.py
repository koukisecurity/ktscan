"""
Subject Alternative Name (SAN) validation checks.

This module contains checks related to SAN extension validation,
hostname matching, wildcard certificate policies, and DNS name quality.
"""

import ipaddress
import logging
import re
from typing import List

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID

from ..models import (
    BaseCheck,
    ValidationFinding,
    ValidationSeverity,
    ValidationCheck,
    CheckInfo,
)


class SanCheck(BaseCheck):
    """Subject Alternative Name validation checks"""

    def __init__(self, config: dict = None):
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        
    def get_check_info(self) -> CheckInfo:
        return CheckInfo(
            check_id="SUBJECT",
            title="Subject Alternative Name Checks",
            description="Validates SAN extension presence, content, and hostname matching requirements"
        )

    def _register_checks(self) -> None:
        """Register all SAN-related checks"""
        
        # CRITICAL severity checks
        self.register_check(ValidationCheck(
            check_id="SUBJECT.RFC5280_EMPTY_SUBJECT_AND_SAN",
            title="RFC 5280 Empty Subject and SAN",
            description="Certificate has empty subject and empty Subject Alternative Name",
            remediation="Provide either a meaningful subject or populate Subject Alternative Name",
        ))
        
        self.register_check(ValidationCheck(
            check_id="SUBJECT.RFC5280_EMPTY_SUBJECT_NO_SAN",
            title="RFC 5280 Empty Subject Without SAN",
            description="Certificate has empty subject and no Subject Alternative Name",
            remediation="Provide either a meaningful subject or add Subject Alternative Name extension",
        ))
        
        self.register_check(ValidationCheck(
            check_id="SUBJECT.CABF_OU_PROHIBITED",
            title="CABF organizationalUnitName Prohibited",
            description="organizationalUnitName field is prohibited in server certificates",
            remediation="Remove organizationalUnitName from certificate subject",
        ))
        
        self.register_check(ValidationCheck(
            check_id="SUBJECT.RESERVED_IP_ADDRESS",
            title="Reserved IP Address in SAN",
            description="Certificate contains reserved or internal IP address",
            remediation="Remove reserved IP addresses from Subject Alternative Name",
        ))
        
        self.register_check(ValidationCheck(
            check_id="SUBJECT.INTERNAL_NAME",
            title="Internal Name in Certificate",
            description="Certificate contains internal server name",
            remediation="Remove internal names from certificate",
        ))
        
        # HIGH severity checks
        self.register_check(ValidationCheck(
            check_id="SUBJECT.MISSING_SAN",
            title="Missing SAN Extension",
            description="Certificate lacks required Subject Alternative Name extension",
            remediation="Add Subject Alternative Name extension with appropriate DNS names",
        ))
        
        self.register_check(ValidationCheck(
            check_id="SUBJECT.EMPTY_SAN",
            title="Empty SAN Extension",
            description="Subject Alternative Name extension is present but empty",
            remediation="Populate SAN with at least one DNS name or IP address",
        ))
        
        self.register_check(ValidationCheck(
            check_id="SUBJECT.CN_NOT_IN_SAN",
            title="CN Not in SAN",
            description="Common Name must be included in Subject Alternative Name",
            remediation="Add Common Name to Subject Alternative Name extension",
        ))
        
        self.register_check(ValidationCheck(
            check_id="SUBJECT.HOSTNAME_MISMATCH",
            title="SAN Hostname Mismatch",
            description="Hostname does not match any SAN entry",
            remediation="Add hostname to Subject Alternative Name extension",
        ))
        
        # MEDIUM severity checks
        self.register_check(ValidationCheck(
            check_id="SUBJECT.WILDCARD_IN_PUBLIC_SUFFIX",
            title="Wildcard in Public Suffix",
            description="Wildcard certificate includes public suffix domain",
            remediation="Avoid wildcards that span public suffix boundaries",
        ))
        
        self.register_check(ValidationCheck(
            check_id="SUBJECT.EXCESSIVE_WILDCARDS",
            title="Excessive Wildcard Usage",
            description="Certificate contains multiple wildcard entries",
            remediation="Consider using specific hostnames instead of multiple wildcards",
        ))
        
        # LOW severity checks
        self.register_check(ValidationCheck(
            check_id="SUBJECT.MIXED_CASE_DOMAINS",
            title="Mixed Case Domain Names",
            description="SAN contains mixed case domain names",
            remediation="Use lowercase domain names for consistency",
        ))
        
        # Additional CRITICAL severity checks from hostname validation
        self.register_check(ValidationCheck(
            check_id="SUBJECT.NO_HOSTNAME_IDENTIFIERS",
            title="No Hostname Identifiers",
            description="Certificate contains no hostname identifiers (CN or SAN)",
            remediation="Add Subject Alternative Name or Common Name to identify the certificate purpose",
        ))
        
        # Additional HIGH severity checks from hostname validation
        self.register_check(ValidationCheck(
            check_id="SUBJECT.INVALID_DNS_NAME",
            title="Invalid DNS Name in SAN",
            description="Invalid DNS name format in Subject Alternative Name",
            remediation="Use valid DNS name format in Subject Alternative Name",
        ))
        
        self.register_check(ValidationCheck(
            check_id="SUBJECT.NESTED_WILDCARD",
            title="Nested Wildcard DNS Name",
            description="DNS name contains nested wildcard",
            remediation="Use single-level wildcards only (e.g., *.example.com)",
        ))
        
        self.register_check(ValidationCheck(
            check_id="SUBJECT.MULTIPLE_WILDCARDS",
            title="Multiple Wildcards in DNS Name",
            description="DNS name contains multiple wildcards",
            remediation="Use only one wildcard per DNS name",
        ))
        
        self.register_check(ValidationCheck(
            check_id="SUBJECT.WILDCARD_NOT_LEFTMOST",
            title="Wildcard Not in Leftmost Position",
            description="Wildcard not in leftmost position",
            remediation="Place wildcard only in leftmost label (e.g., *.example.com)",
        ))
        
        self.register_check(ValidationCheck(
            check_id="SUBJECT.LOOPBACK_IP",
            title="Loopback IP Address in SAN",
            description="SAN contains loopback IP address",
            remediation="Remove loopback addresses from Subject Alternative Name",
        ))
        
        self.register_check(ValidationCheck(
            check_id="SUBJECT.INVALID_IP_ADDRESS",
            title="Invalid IP Address in SAN",
            description="Invalid IP address format in Subject Alternative Name",
            remediation="Use valid IP address format in Subject Alternative Name",
        ))
        
        self.register_check(ValidationCheck(
            check_id="SUBJECT.WILDCARD_INSUFFICIENT_LABELS",
            title="Wildcard Insufficient Domain Labels",
            description="Wildcard domain has insufficient labels",
            remediation="Ensure wildcard domains have at least two labels after the wildcard",
        ))
        
        self.register_check(ValidationCheck(
            check_id="SUBJECT.WILDCARD_EMPTY_LABEL",
            title="Wildcard Empty Domain Label",
            description="Wildcard domain contains empty label",
            remediation="Remove empty labels from wildcard domain names",
        ))
        
        # Additional MEDIUM severity checks
        self.register_check(ValidationCheck(
            check_id="SUBJECT.DUPLICATE_DNS_NAMES",
            title="Duplicate DNS Names in SAN",
            description="SAN contains duplicate DNS names",
            remediation="Remove duplicate entries from Subject Alternative Name",
        ))
        
        self.register_check(ValidationCheck(
            check_id="SUBJECT.PRIVATE_IP",
            title="Private IP Address in SAN",
            description="SAN contains private IP address",
            remediation="Consider if private IP addresses should be in publicly trusted certificates",
        ))

        # INFO severity checks
        self.register_check(ValidationCheck(
            check_id="SUBJECT.IP_ADDRESS_PRESENT",
            title="IP Address in SAN",
            description="SAN contains IP address entries",
        ))
        
        self.register_check(ValidationCheck(
            check_id="SUBJECT.HOSTNAME_MATCH_SUCCESS",
            title="Hostname Match Successful",
            description="Hostname matches certificate names successfully",
        ))
        
        self.register_check(ValidationCheck(
            check_id="SUBJECT.OTHER_NAME_TYPES",
            title="SAN Contains Other Name Types",
            description="SAN contains non-DNS/IP names",
        ))

    def validate(
        self, certificate: x509.Certificate, context: dict = None
    ) -> List[ValidationFinding]:
        """Validate Subject Alternative Name extension"""
        findings = []
        hostname = context.get("hostname", "") if context else ""

        findings.extend(self._validate_san_presence(certificate))
        findings.extend(self._validate_san_content(certificate, hostname))
        findings.extend(self._validate_cn_in_san(certificate))
        findings.extend(self._validate_hostname_matching(certificate, hostname))
        findings.extend(self._validate_san_quality(certificate))
        findings.extend(self._validate_wildcard_usage(certificate))
        findings.extend(self._validate_rfc5280_subject_requirements(certificate))

        return [f for f in findings if self.is_check_enabled(f.check_id)]

    def _validate_san_presence(self, certificate: x509.Certificate) -> List[ValidationFinding]:
        """Validate SAN extension presence and basic requirements"""
        findings = []
        
        try:
            san_ext = certificate.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            
            # Check if SAN is empty
            san_entries = list(san_ext.value)
            if not san_entries:
                findings.append(
                    self.create_finding(
                        check_id="SUBJECT.EMPTY_SAN",
                        evidence={"san_count": 0}
                    )
                )
                
        except x509.ExtensionNotFound:
            # Check if we have a meaningful subject, if not SAN is required
            try:
                cn = None
                for attribute in certificate.subject:
                    if attribute.oid == NameOID.COMMON_NAME:
                        cn = attribute.value
                        break
                
                if not cn or cn.strip() == "":
                    findings.append(
                        self.create_finding(
                            check_id="SUBJECT.MISSING_SAN",
                            evidence={"has_common_name": False}
                        )
                    )
            except Exception:
                findings.append(
                    self.create_finding(
                        check_id="SUBJECT.MISSING_SAN",
                        evidence={"subject_parse_error": True}
                    )
                )
        
        return findings

    def _validate_san_content(self, certificate: x509.Certificate, hostname: str) -> List[ValidationFinding]:
        """Validate SAN content and hostname matching"""
        findings = []
        
        try:
            san_ext = certificate.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            
            dns_names = []
            ip_addresses = []
            wildcard_count = 0
            
            for name in san_ext.value:
                if isinstance(name, x509.DNSName):
                    dns_name = name.value
                    dns_names.append(dns_name)
                    
                    # Check for wildcards
                    if '*' in dns_name:
                        wildcard_count += 1
                    
                    # Check for mixed case
                    if dns_name != dns_name.lower():
                        findings.append(
                            self.create_finding(
                                check_id="SUBJECT.MIXED_CASE_DOMAINS",
                                evidence={"mixed_case_domain": dns_name}
                            )
                        )
                        
                elif isinstance(name, x509.IPAddress):
                    ip_addresses.append(str(name.value))
            
            # Check for excessive wildcards
            if wildcard_count > 2:
                findings.append(
                    self.create_finding(
                        check_id="SUBJECT.EXCESSIVE_WILDCARDS",
                        evidence={"wildcard_count": wildcard_count}
                    )
                )
            
            # Check for IP addresses (informational)
            if ip_addresses:
                findings.append(
                    self.create_finding(
                        check_id="SUBJECT.IP_ADDRESS_PRESENT",
                        evidence={"ip_addresses": ip_addresses}
                    )
                )
            
            # Note: hostname matching is handled comprehensively in _validate_hostname_matching method
                    
        except x509.ExtensionNotFound:
            # Already handled in _validate_san_presence
            pass
        except Exception as e:
            self.logger.debug(f"Error validating SAN content: {e}")
        
        return findings

    def _validate_cn_in_san(self, certificate: x509.Certificate) -> List[ValidationFinding]:
        """Validate that Common Name is included in SAN"""
        findings = []
        
        try:
            # Get Common Name
            cn = None
            for attribute in certificate.subject:
                if attribute.oid == NameOID.COMMON_NAME:
                    cn = attribute.value
                    break
            
            if not cn:
                return findings
            
            # Get SAN DNS names
            try:
                san_ext = certificate.extensions.get_extension_for_oid(
                    ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                )
                
                san_dns_names = [
                    name.value for name in san_ext.value 
                    if isinstance(name, x509.DNSName)
                ]
                
                # Check if CN is in SAN
                if cn not in san_dns_names:
                    findings.append(
                        self.create_finding(
                            check_id="SUBJECT.CN_NOT_IN_SAN",
                            evidence={"common_name": cn, "san_names": san_dns_names}
                        )
                    )
                    
            except x509.ExtensionNotFound:
                # No SAN extension but we have CN
                findings.append(
                    self.create_finding(
                        check_id="SUBJECT.MISSING_SAN",
                        evidence={"common_name": cn, "has_san": False}
                    )
                )
                
        except Exception as e:
            self.logger.debug(f"Error validating CN in SAN: {e}")
        
        return findings

    def _hostname_matches_san(self, hostname: str, san_names: List[str]) -> bool:
        """Check if hostname matches any SAN entry (including wildcards)"""
        hostname_lower = hostname.lower()
        
        for san_name in san_names:
            san_lower = san_name.lower()
            
            if san_lower == hostname_lower:
                return True
            
            # Handle wildcard matching
            if '*' in san_lower:
                # Convert wildcard to regex pattern
                pattern = san_lower.replace('.', r'\.').replace('*', r'[^.]*')
                if re.match(f"^{pattern}$", hostname_lower):
                    return True
        
        return False

    def _validate_hostname_matching(self, certificate: x509.Certificate, hostname: str) -> List[ValidationFinding]:
        """Validate hostname matching against certificate names"""
        findings = []

        if not hostname:
            return findings

        subject_cn = self._extract_subject_cn(certificate)
        san_names = self._extract_san_dns_names(certificate)

        all_names = []
        if subject_cn:
            all_names.append(subject_cn)
        all_names.extend(san_names)

        if not all_names:
            findings.append(
                self.create_finding(
                    check_id="SUBJECT.NO_HOSTNAME_IDENTIFIERS",
                    evidence={"hostname": hostname}
                )
            )
            return findings

        hostname_matches = any(
            self._match_hostname_advanced(hostname, name) for name in all_names
        )

        if not hostname_matches:
            findings.append(
                self.create_finding(
                    check_id="SUBJECT.HOSTNAME_MISMATCH",
                    evidence={
                        "hostname": hostname,
                        "certificate_names": all_names,
                        "subject_cn": subject_cn,
                        "san_names": san_names,
                    }
                )
            )
        else:
            matching_names = [
                name for name in all_names if self._match_hostname_advanced(hostname, name)
            ]
            findings.append(
                self.create_finding(
                    check_id="SUBJECT.HOSTNAME_MATCH_SUCCESS",
                    evidence={"hostname": hostname, "matching_names": matching_names}
                )
            )

        return findings

    def _validate_san_quality(self, certificate: x509.Certificate) -> List[ValidationFinding]:
        """Validate SAN extension quality and format"""
        findings = []

        try:
            san_ext = certificate.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )

            dns_names = []
            ip_addresses = []
            other_names = []

            for name in san_ext.value:
                if isinstance(name, x509.DNSName):
                    dns_names.append(name.value)
                elif isinstance(name, x509.IPAddress):
                    ip_addresses.append(str(name.value))
                else:
                    other_names.append(str(name))

            findings.extend(self._validate_dns_names_quality(dns_names))
            findings.extend(self._validate_ip_addresses_quality(ip_addresses))

            if other_names:
                findings.append(
                    self.create_finding(
                        check_id="SUBJECT.OTHER_NAME_TYPES",
                        evidence={"other_names": other_names}
                    )
                )

        except x509.ExtensionNotFound:
            pass

        return findings

    def _validate_wildcard_usage(self, certificate: x509.Certificate) -> List[ValidationFinding]:
        """Validate wildcard usage in certificate names"""
        findings = []

        subject_cn = self._extract_subject_cn(certificate)
        san_names = self._extract_san_dns_names(certificate)

        all_names = []
        if subject_cn:
            all_names.append(subject_cn)
        all_names.extend(san_names)

        wildcard_names = [name for name in all_names if "*" in name]

        if not wildcard_names:
            return findings

        for wildcard_name in wildcard_names:
            if wildcard_name.startswith("*."):
                domain = wildcard_name[2:]
                labels = domain.split(".")

                if len(labels) < 2:
                    findings.append(
                        self.create_finding(
                            check_id="SUBJECT.WILDCARD_INSUFFICIENT_LABELS",
                            evidence={"wildcard_name": wildcard_name, "labels": labels}
                        )
                    )

                if any(label == "" for label in labels):
                    findings.append(
                        self.create_finding(
                            check_id="SUBJECT.WILDCARD_EMPTY_LABEL",
                            evidence={"wildcard_name": wildcard_name}
                        )
                    )

        return findings

    def _validate_dns_names_quality(self, dns_names: List[str]) -> List[ValidationFinding]:
        """Validate DNS name quality and format"""
        findings = []

        for dns_name in dns_names:
            if not self._is_valid_dns_name(dns_name):
                findings.append(
                    self.create_finding(
                        check_id="SUBJECT.INVALID_DNS_NAME",
                        evidence={"invalid_dns_name": dns_name}
                    )
                )

            if dns_name.startswith("*.*."):
                findings.append(
                    self.create_finding(
                        check_id="SUBJECT.NESTED_WILDCARD",
                        evidence={"dns_name": dns_name}
                    )
                )

            if dns_name.count("*") > 1:
                findings.append(
                    self.create_finding(
                        check_id="SUBJECT.MULTIPLE_WILDCARDS",
                        evidence={"dns_name": dns_name}
                    )
                )

            if "*" in dns_name and not dns_name.startswith("*."):
                findings.append(
                    self.create_finding(
                        check_id="SUBJECT.WILDCARD_NOT_LEFTMOST",
                        evidence={"dns_name": dns_name}
                    )
                )

        duplicates = [name for name in set(dns_names) if dns_names.count(name) > 1]
        if duplicates:
            findings.append(
                self.create_finding(
                    check_id="SUBJECT.DUPLICATE_DNS_NAMES",
                    evidence={"duplicates": duplicates}
                )
            )

        return findings

    def _validate_ip_addresses_quality(self, ip_addresses: List[str]) -> List[ValidationFinding]:
        """Validate IP address quality in SAN"""
        findings = []

        for ip_addr in ip_addresses:
            try:
                addr = ipaddress.ip_address(ip_addr)
                if addr.is_private:
                    findings.append(
                        self.create_finding(
                            check_id="SUBJECT.PRIVATE_IP",
                            evidence={"ip_address": ip_addr, "is_private": True}
                        )
                    )

                if addr.is_loopback:
                    findings.append(
                        self.create_finding(
                            check_id="SUBJECT.LOOPBACK_IP",
                            evidence={"ip_address": ip_addr, "is_loopback": True}
                        )
                    )

            except ValueError:
                findings.append(
                    self.create_finding(
                        check_id="SUBJECT.INVALID_IP_ADDRESS",
                        evidence={"invalid_ip": ip_addr}
                    )
                )

        return findings

    def _extract_subject_cn(self, certificate: x509.Certificate) -> str:
        """Extract Common Name from certificate subject"""
        try:
            cn_attributes = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            if cn_attributes:
                return cn_attributes[0].value
        except Exception:
            pass
        return None

    def _extract_san_dns_names(self, certificate: x509.Certificate) -> List[str]:
        """Extract DNS names from SAN extension"""
        names = []
        try:
            san_ext = certificate.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            for name in san_ext.value:
                if isinstance(name, x509.DNSName):
                    names.append(name.value)
        except x509.ExtensionNotFound:
            pass
        except Exception:
            pass
        return names

    def _match_hostname_advanced(self, hostname: str, cert_name: str) -> bool:
        """Advanced hostname matching including wildcard and IP address support"""
        if hostname.lower() == cert_name.lower():
            return True

        if cert_name.startswith("*."):
            domain = cert_name[2:]
            if hostname.lower().endswith("." + domain.lower()):
                hostname_prefix = hostname[: -len(domain) - 1]
                if "." not in hostname_prefix:
                    return True

        try:
            hostname_ip = ipaddress.ip_address(hostname)
            cert_ip = ipaddress.ip_address(cert_name)
            return hostname_ip == cert_ip
        except ValueError:
            pass

        return False

    def _is_valid_dns_name(self, dns_name: str) -> bool:
        """Validate DNS name format"""
        if not dns_name or len(dns_name) > 253:
            return False

        if dns_name.startswith("*."):
            dns_name = "x" + dns_name[1:]

        if dns_name.endswith("."):
            dns_name = dns_name[:-1]

        allowed = re.compile(
            r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
        )
        return bool(allowed.match(dns_name))

    def _validate_rfc5280_subject_requirements(self, certificate: x509.Certificate) -> List[ValidationFinding]:
        """Validate RFC 5280 and CABF subject requirements"""
        findings = []

        # RFC 5280 empty subject validation
        try:
            subject_alt_name_ext = certificate.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            if (
                certificate.subject.rfc4514_string() == ""
                and not subject_alt_name_ext.value
            ):
                findings.append(
                    self.create_finding(
                        check_id="SUBJECT.RFC5280_EMPTY_SUBJECT_AND_SAN",
                        evidence={},
                    )
                )
        except x509.ExtensionNotFound:
            if certificate.subject.rfc4514_string() == "":
                findings.append(
                    self.create_finding(
                        check_id="SUBJECT.RFC5280_EMPTY_SUBJECT_NO_SAN",
                        evidence={},
                    )
                )

        # CABF organizationalUnitName prohibition
        try:
            ou_attributes = certificate.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
            if ou_attributes:
                findings.append(
                    self.create_finding(
                        check_id="SUBJECT.CABF_OU_PROHIBITED",
                        evidence={"ou_values": [attr.value for attr in ou_attributes]},
                    )
                )
        except Exception:
            pass

        # Check for reserved IP addresses and internal names in SAN
        try:
            san_ext = certificate.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            for name in san_ext.value:
                if isinstance(name, x509.IPAddress):
                    ip_str = str(name.value)
                    if self._is_reserved_ip(ip_str):
                        findings.append(
                            self.create_finding(
                                check_id="SUBJECT.RESERVED_IP_ADDRESS",
                                evidence={"ip_address": ip_str},
                            )
                        )
                elif isinstance(name, x509.DNSName):
                    dns_name = name.value
                    if self._is_internal_name(dns_name):
                        findings.append(
                            self.create_finding(
                                check_id="SUBJECT.INTERNAL_NAME",
                                evidence={"dns_name": dns_name},
                            )
                        )
        except x509.ExtensionNotFound:
            pass

        return findings

    def _is_reserved_ip(self, ip_str: str) -> bool:
        """Check if IP address is reserved or internal"""
        try:
            ip = ipaddress.ip_address(ip_str)
            return (
                ip.is_private or 
                ip.is_loopback or 
                ip.is_reserved or 
                ip.is_multicast or
                ip.is_link_local
            )
        except ValueError:
            return False

    def _is_internal_name(self, dns_name: str) -> bool:
        """Check if DNS name is internal"""
        # Common internal name patterns
        internal_patterns = [
            "localhost",
            ".local",
            ".internal", 
            ".corp",
            ".home",
            ".lan",
            ".test"
        ]
        
        dns_lower = dns_name.lower()
        return any(
            dns_lower == pattern.lstrip('.') or dns_lower.endswith(pattern)
            for pattern in internal_patterns
        )