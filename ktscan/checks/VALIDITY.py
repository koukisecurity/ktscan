"""
Certificate validity period checks.

This module contains checks related to certificate validity periods,
expiration status, and lifetime validation.
"""

import logging
from datetime import datetime, timezone
from typing import List

from cryptography import x509

from ..models import (
    BaseCheck,
    ValidationFinding,
    ValidationSeverity,
    ValidationCheck,
    CheckInfo,
)

# Certificate validity constants
EXPIRY_WARNING_DAYS = 30
MAX_LIFETIME_DAYS_2026 = 200
MAX_LIFETIME_DAYS_2027 = 100
MAX_LIFETIME_DAYS_2029 = 47


class ValidityCheck(BaseCheck):
    """Certificate validity and lifetime validation checks"""

    def __init__(self, config: dict = None):
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        
    def get_check_info(self) -> CheckInfo:
        return CheckInfo(
            check_id="VALIDITY",
            title="Certificate Validity Checks",
            description="Validates certificate validity periods, expiration status, and lifetime requirements"
        )

    def _register_checks(self) -> None:
        """Register all validity-related checks"""
        
        # CRITICAL severity checks
        self.register_check(ValidationCheck(
            check_id="VALIDITY.NOT_YET_VALID",
            title="Certificate Not Yet Valid",
            description="Certificate is not yet valid",
            remediation="Wait until the certificate becomes valid or obtain a new certificate",
        ))
        
        self.register_check(ValidationCheck(
            check_id="VALIDITY.EXPIRED",
            title="Certificate Expired",
            description="Certificate has expired",
            remediation="Renew the certificate immediately",
        ))
        
        # HIGH severity checks
        self.register_check(ValidationCheck(
            check_id="VALIDITY.EXPIRES_VERY_SOON",
            title="Certificate Expires Very Soon",
            description="Certificate expires within 1 day",
            remediation="Renew certificate immediately",
        ))
        
        self.register_check(ValidationCheck(
            check_id="VALIDITY.LIFETIME_TOO_LONG",
            title="Certificate Lifetime Too Long",
            description="Certificate lifetime exceeds 825 days limit",
            remediation="Issue certificate with shorter validity period (≤825 days)",
        ))
        
        self.register_check(ValidationCheck(
            check_id="VALIDITY.LIFETIME_TOO_SHORT",
            title="Certificate Lifetime Too Short",
            description="Certificate lifetime is unusually short",
            remediation="Verify certificate validity period is correct",
        ))
        
        # MEDIUM severity checks
        self.register_check(ValidationCheck(
            check_id="VALIDITY.EXPIRES_SOON",
            title="Certificate Expires Soon",
            description="Certificate expires within 7 days",
            remediation="Plan certificate renewal",
        ))
        
        self.register_check(ValidationCheck(
            check_id="VALIDITY.LIFETIME_EXCEEDS_398_DAYS",
            title="Certificate Lifetime Exceeds 398 Days",
            description="Certificate lifetime exceeds current 398 days recommendation",
            remediation="Consider shorter validity periods for better security",
        ))
        
        # LOW severity checks
        self.register_check(ValidationCheck(
            check_id="VALIDITY.EXPIRES_WITHIN_30_DAYS",
            title=f"Certificate Expires Within {EXPIRY_WARNING_DAYS} Days",
            description=f"Certificate expires within {EXPIRY_WARNING_DAYS} days",
            remediation="Consider planning certificate renewal",
        ))
        
        # Future CABF validity period requirements (LOW severity until effective)
        self.register_check(ValidationCheck(
            check_id="VALIDITY.LIFETIME_EXCEEDS_200_DAYS",
            title="Certificate Lifetime Exceeds 200 Days (Future Requirement)",
            description=f"Certificate lifetime exceeds {MAX_LIFETIME_DAYS_2026} days (effective March 15, 2026)",
            remediation="Prepare for upcoming 200-day validity limit",
        ))
        
        self.register_check(ValidationCheck(
            check_id="VALIDITY.LIFETIME_EXCEEDS_100_DAYS",
            title="Certificate Lifetime Exceeds 100 Days (Future Requirement)",
            description=f"Certificate lifetime exceeds {MAX_LIFETIME_DAYS_2027} days (effective March 15, 2027)",
            remediation="Prepare for upcoming 100-day validity limit",
        ))
        
        self.register_check(ValidationCheck(
            check_id="VALIDITY.LIFETIME_EXCEEDS_47_DAYS",
            title="Certificate Lifetime Exceeds 47 Days (Future Requirement)",
            description=f"Certificate lifetime exceeds {MAX_LIFETIME_DAYS_2029} days (effective March 15, 2029)",
            remediation="Prepare for upcoming 47-day validity limit",
        ))

    def validate(
        self, certificate: x509.Certificate, context: dict = None
    ) -> List[ValidationFinding]:
        """Validate certificate validity periods"""
        findings = []

        findings.extend(self._validate_certificate_validity_period(certificate))
        findings.extend(self._validate_certificate_lifetime(certificate))

        return [f for f in findings if self.is_check_enabled(f.check_id)]

    def _validate_certificate_validity_period(
        self, certificate: x509.Certificate
    ) -> List[ValidationFinding]:
        """Validate certificate is currently valid"""
        findings = []
        now = datetime.now(timezone.utc)

        not_before = certificate.not_valid_before_utc
        not_after = certificate.not_valid_after_utc

        if not_before > now:
            findings.append(
                self.create_finding(
                    check_id="VALIDITY.NOT_YET_VALID",
                    evidence={
                        "not_before": not_before.isoformat(),
                        "current_time": now.isoformat(),
                    },
                )
            )

        if not_after < now:
            findings.append(
                self.create_finding(
                    check_id="VALIDITY.EXPIRED",
                    evidence={
                        "not_after": not_after.isoformat(),
                        "expired_days": (now - not_after).days,
                    },
                )
            )
        else:
            days_until_expiry = (not_after - now).days

            if days_until_expiry <= 1:
                findings.append(
                    self.create_finding(
                        check_id="VALIDITY.EXPIRES_VERY_SOON",
                        evidence={"days_until_expiry": days_until_expiry},
                    )
                )
            elif days_until_expiry <= 7:
                findings.append(
                    self.create_finding(
                        check_id="VALIDITY.EXPIRES_SOON",
                        evidence={"days_until_expiry": days_until_expiry},
                    )
                )
            elif days_until_expiry <= EXPIRY_WARNING_DAYS:
                findings.append(
                    self.create_finding(
                        check_id="VALIDITY.EXPIRES_WITHIN_30_DAYS",
                        evidence={"days_until_expiry": days_until_expiry},
                    )
                )

        return findings


    def _validate_certificate_lifetime(
        self, certificate: x509.Certificate
    ) -> List[ValidationFinding]:
        """Validate certificate lifetime requirements"""
        findings = []

        not_before = certificate.not_valid_before_utc
        not_after = certificate.not_valid_after_utc
        lifetime = not_after - not_before

        if lifetime.days > 825:  # CA/Browser Forum requirement
            findings.append(
                self.create_finding(
                    check_id="VALIDITY.LIFETIME_TOO_LONG",
                    evidence={"lifetime_days": lifetime.days, "max_allowed": 825},
                )
            )
        elif lifetime.days > 398:  # Current CA/B Forum recommendation
            findings.append(
                self.create_finding(
                    check_id="VALIDITY.LIFETIME_EXCEEDS_398_DAYS",
                    evidence={"lifetime_days": lifetime.days, "recommended_max": 398},
                )
            )
            
        # Future CABF validity requirements (LOW severity warnings)
        if lifetime.days > MAX_LIFETIME_DAYS_2026:
            findings.append(
                self.create_finding(
                    check_id="VALIDITY.LIFETIME_EXCEEDS_200_DAYS",
                    evidence={"lifetime_days": lifetime.days, "future_max": MAX_LIFETIME_DAYS_2026, "effective_date": "2026-03-15"},
                )
            )
        elif lifetime.days > MAX_LIFETIME_DAYS_2027:
            findings.append(
                self.create_finding(
                    check_id="VALIDITY.LIFETIME_EXCEEDS_100_DAYS",
                    evidence={"lifetime_days": lifetime.days, "future_max": MAX_LIFETIME_DAYS_2027, "effective_date": "2027-03-15"},
                )
            )
        elif lifetime.days > MAX_LIFETIME_DAYS_2029:
            findings.append(
                self.create_finding(
                    check_id="VALIDITY.LIFETIME_EXCEEDS_47_DAYS",
                    evidence={"lifetime_days": lifetime.days, "future_max": MAX_LIFETIME_DAYS_2029, "effective_date": "2029-03-15"},
                )
            )

        if lifetime.days < 1:
            findings.append(
                self.create_finding(
                    check_id="VALIDITY.LIFETIME_TOO_SHORT",
                    evidence={"lifetime_seconds": lifetime.total_seconds()},
                )
            )

        return findings