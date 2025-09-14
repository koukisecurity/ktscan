"""
DNS validation checks.

This module contains checks related to DNS validation requirements,
CAA record checking, and domain validation compliance.
"""

import logging
import socket
from typing import List

from cryptography import x509

from ..models import (
    BaseCheck,
    ValidationFinding,
    ValidationSeverity,
    ValidationCheck,
    CheckInfo,
)


class DnsCheck(BaseCheck):
    """DNS validation and CAA record checks"""

    def __init__(self, config: dict = None, timeout: int = 10):
        super().__init__(config)
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
        
    def get_check_info(self) -> CheckInfo:
        return CheckInfo(
            check_id="DNS",
            title="DNS Validation Checks",
            description="Validates DNS requirements including CAA record checking and domain validation compliance"
        )

    def _register_checks(self) -> None:
        """Register all DNS-related checks"""
        
        # HIGH severity checks
        self.register_check(ValidationCheck(
            check_id="DNS.CAA_VIOLATION",
            title="CAA Record Violation",
            description="Domain CAA record prohibits certificate issuance",
            remediation="Update CAA record to allow certificate issuance or verify CA authorization",
        ))
        
        # MEDIUM severity checks
        self.register_check(ValidationCheck(
            check_id="DNS.CAA_CHECK_FAILED",
            title="CAA Record Check Failed",
            description="Unable to check CAA records for domain validation",
            remediation="Ensure DNS resolution is working for CAA record validation",
        ))
        
        self.register_check(ValidationCheck(
            check_id="DNS.DOMAIN_RESOLUTION_FAILED",
            title="Domain Resolution Failed",
            description="Domain name cannot be resolved",
            remediation="Verify domain exists and is properly configured in DNS",
        ))

        # INFO severity checks
        self.register_check(ValidationCheck(
            check_id="DNS.CAA_ALLOWS_ISSUANCE",
            title="CAA Record Allows Issuance",
            description="Domain CAA record permits certificate issuance",
        ))

    def validate(
        self, certificate: x509.Certificate, context: dict = None
    ) -> List[ValidationFinding]:
        """Validate DNS requirements"""
        findings = []

        # Only validate if we have hostname context
        if context and "hostname" in context:
            hostname = context["hostname"]
            findings.extend(self._validate_caa_records(hostname))
            findings.extend(self._validate_domain_resolution(hostname))

        return [f for f in findings if self.is_check_enabled(f.check_id)]

    def _validate_caa_records(self, hostname: str) -> List[ValidationFinding]:
        """Validate CAA record compliance"""
        findings = []
        
        try:
            # This is a placeholder for CAA record checking
            # Full implementation would require DNS library (dnspython)
            # and actual CAA record parsing
            
            # For now, we can only report that CAA checking should be implemented
            findings.append(
                self.create_finding(
                    check_id="DNS.CAA_CHECK_FAILED",
                    evidence={
                        "hostname": hostname,
                        "reason": "CAA record validation not implemented"
                    },
                )
            )
            
        except Exception as e:
            self.logger.debug(f"Error checking CAA records for {hostname}: {e}")
            findings.append(
                self.create_finding(
                    check_id="DNS.CAA_CHECK_FAILED",
                    evidence={"hostname": hostname, "error": str(e)},
                )
            )
            
        return findings

    def _validate_domain_resolution(self, hostname: str) -> List[ValidationFinding]:
        """Validate domain can be resolved"""
        findings = []
        
        try:
            # Basic DNS resolution check
            socket.gethostbyname(hostname)
            # Domain resolves successfully - no findings needed
            
        except socket.gaierror as e:
            findings.append(
                self.create_finding(
                    check_id="DNS.DOMAIN_RESOLUTION_FAILED",
                    evidence={"hostname": hostname, "error": str(e)},
                )
            )
        except Exception as e:
            self.logger.debug(f"Error resolving domain {hostname}: {e}")
            
        return findings