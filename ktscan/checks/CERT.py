"""
Certificate structure and encoding validation checks.

This module contains checks related to certificate structure, 
encoding, required fields, and serial number validation.
"""

import logging
from typing import List

from cryptography import x509

from ..models import (
    BaseCheck,
    ValidationFinding,
    ValidationSeverity,
    ValidationCheck,
    CheckInfo,
)


class CertCheck(BaseCheck):
    """Certificate structure and encoding validation checks"""

    def __init__(self, config: dict = None):
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        
    def get_check_info(self) -> CheckInfo:
        return CheckInfo(
            check_id="CERT",
            title="Certificate Structure Checks",
            description="Validates certificate structure, encoding, required fields, and serial number requirements"
        )

    def _register_checks(self) -> None:
        """Register all certificate structure checks"""
        
        # HIGH severity checks
        self.register_check(ValidationCheck(
            check_id="CERT.INVALID_SERIAL_NUMBER",
            title="Invalid Serial Number",
            description="Certificate serial number must be greater than zero",
            remediation="Ensure serial number is a positive integer",
        ))
        
        # MEDIUM severity checks
        self.register_check(ValidationCheck(
            check_id="CERT.INSUFFICIENT_SERIAL_ENTROPY",
            title="Insufficient Serial Number Entropy",
            description="Serial number may have insufficient entropy (< 64 bits)",
            remediation="Use at least 64 bits of entropy for serial number generation",
        ))

    def validate(
        self, certificate: x509.Certificate, context: dict = None
    ) -> List[ValidationFinding]:
        """Validate certificate structure"""
        findings = []

        findings.extend(self._validate_serial_number(certificate))

        return [f for f in findings if self.is_check_enabled(f.check_id)]

    def _validate_serial_number(self, certificate: x509.Certificate) -> List[ValidationFinding]:
        """Validate certificate serial number"""
        findings = []
        
        try:
            serial_number = certificate.serial_number
            
            # Check if serial number is zero or negative (invalid)
            if serial_number <= 0:
                findings.append(
                    self.create_finding(
                        check_id="CERT.INVALID_SERIAL_NUMBER",
                        evidence={"serial_number": serial_number},
                    )
                )
            else:
                # Check entropy (must have at least 64 bits)
                # Convert to hex and check bit length
                hex_serial = hex(serial_number)[2:]  # Remove '0x' prefix
                bit_length = len(hex_serial) * 4  # 4 bits per hex digit
                
                if bit_length < 64:
                    findings.append(
                        self.create_finding(
                            check_id="CERT.INSUFFICIENT_SERIAL_ENTROPY",
                            evidence={
                                "serial_number": serial_number,
                                "bit_length": bit_length,
                                "minimum_bits": 64
                            },
                        )
                    )
                    
        except Exception as e:
            self.logger.debug(f"Error validating serial number: {e}")
            
        return findings