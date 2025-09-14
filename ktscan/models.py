"""
Core data models for the certificate scanner.

This module contains all dataclasses and enums used throughout the application.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any, Set, Tuple

from cryptography import x509


class ValidationSeverity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ConfidenceLevel(Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class ScanStatus(Enum):
    CREATED = "CREATED"  # Initial state when ScanResult is created
    SCANNED = "SCANNED"  # Certificate downloaded and parsed (but not validated)
    SUCCESS = "SUCCESS"  # Certificate validated successfully
    FAILED = "FAILED"  # Certificate scan/validation failed


@dataclass
class StandardReference:
    """Reference to a specific standard that defines a check"""
    standard: str  # "CABF_BR", "NIST_800-52r2", etc.
    title: str  # "CA/Browser Forum Baseline Requirements"
    section: str  # "6.3.2"
    url: str  # Full URL to specific section
    severity: ValidationSeverity  # Severity as defined by the standard


@dataclass
class ValidationCheck:
    """Static definition of a validation check"""
    check_id: str
    title: str
    description: str
    remediation: Optional[str] = None
    standard_refs: List[StandardReference] = field(default_factory=list)

    @property
    def severity(self) -> ValidationSeverity:
        """Compute severity as highest from all standard references"""
        if not self.standard_refs:
            return ValidationSeverity.MEDIUM  # Default for checks without standards
        
        # Define severity hierarchy (lower index = lower severity)
        severity_order = [
            ValidationSeverity.INFO,
            ValidationSeverity.LOW, 
            ValidationSeverity.MEDIUM,
            ValidationSeverity.HIGH,
            ValidationSeverity.CRITICAL
        ]
        
        # Return highest severity from all standard references
        return max(
            (ref.severity for ref in self.standard_refs),
            key=lambda s: severity_order.index(s)
        )

    @property
    def standards(self) -> Set[str]:
        """Get all standards referenced by this check"""
        return {ref.standard for ref in self.standard_refs}


@dataclass
class CheckInfo:
    """Information about a check category"""
    check_id: str
    title: str
    description: str


@dataclass
class ValidationFinding:
    """Result of a specific validation check"""
    check_id: str
    severity: ValidationSeverity
    confidence: ConfidenceLevel
    title: str
    description: str
    remediation: Optional[str] = None
    evidence: Optional[dict] = field(default_factory=dict)
    check_category: Optional[str] = None  # Which check file this came from
    standard_ref: Optional[StandardReference] = None


@dataclass
class ScanMetadata:
    """Metadata about a certificate scan"""
    started_at: datetime
    completed_at: Optional[datetime] = None
    profile: Optional[str] = None
    standards: List[str] = field(default_factory=list)
    severity_filter: str = "MEDIUM"
    targets_count: int = 0
    certificates_scanned: int = 0


@dataclass
class CertificateData:
    """Certificate-specific data"""
    subject: str = ""
    san_domains: List[str] = field(default_factory=list)
    issuer: str = ""
    valid: bool = False
    trusted: Optional[bool] = None
    expires: Optional[datetime] = None
    issued: Optional[datetime] = None
    serial_number: str = ""
    signature_algorithm: str = ""
    public_key_algorithm: str = ""
    key_size: Optional[int] = None
    certificate_fingerprint: str = ""
    # Internal certificate object for validation
    _certificate: Optional[x509.Certificate] = None


@dataclass
class SecuritySummary:
    """Summary of security findings and metrics"""
    security_score: Optional[int] = None
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0


@dataclass
class ScanResult:
    """Complete result for a single target"""
    target: str
    original_url: str = ""  # Original URL specification from user input
    endpoints: List[Tuple[str, int]] = field(default_factory=list)
    certificate: Optional[CertificateData] = None
    findings: List[ValidationFinding] = field(default_factory=list)
    summary: Optional[SecuritySummary] = None
    errors: List[str] = field(default_factory=list)
    status: ScanStatus = ScanStatus.CREATED

    @property
    def primary_endpoint(self) -> Optional[Tuple[str, int]]:
        """Return the first/primary endpoint"""
        return self.endpoints[0] if self.endpoints else None

    @property
    def primary_ip(self) -> str:
        """Return primary IP"""
        return self.endpoints[0][0] if self.endpoints else ""

    @property
    def valid(self) -> bool:
        """Return True if the scan was successful (for compatibility with tests)"""
        return self.status == ScanStatus.SUCCESS and not self.errors

    @property
    def primary_port(self) -> int:
        """Return primary port"""
        return self.endpoints[0][1] if self.endpoints else 0

    def add_endpoint(self, ip: str, port: int):
        """Add an endpoint for this result"""
        endpoint = (ip, port)
        if endpoint not in self.endpoints:
            self.endpoints.append(endpoint)


class BaseCheck(ABC):
    """Base class for all certificate checks"""

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.enabled = not self.config.get("disabled", False)
        self.disabled_checks = set(self.config.get("disabled_checks", []))
        self.enabled_standards = set(self.config.get("enabled_standards", []))
        self._registered_checks: Dict[str, ValidationCheck] = {}
        self._register_checks()

    @abstractmethod
    def get_check_info(self) -> CheckInfo:
        """Get check category metadata"""
        pass

    @abstractmethod
    def _register_checks(self) -> None:
        """Register all checks this category can perform"""
        pass

    @abstractmethod
    def validate(
            self, certificate: x509.Certificate, context: dict = None
    ) -> List[ValidationFinding]:
        """Perform validation and return findings"""
        pass

    def register_check(self, check: ValidationCheck) -> None:
        """Register a check with this category and auto-populate standard references"""
        # Auto-populate standard references since ValidationChecks should not contain them
        try:
            from .standards_loader import standards_loader
            check.standard_refs = standards_loader.get_all_standard_references(check.check_id)
        except Exception:
            # If standards loading fails, continue with empty references
            # This ensures the check still gets registered
            check.standard_refs = []

        self._registered_checks[check.check_id] = check

    def get_all_checks(self) -> List[ValidationCheck]:
        """Get all registered checks"""
        return list(self._registered_checks.values())

    def get_check(self, check_id: str) -> Optional[ValidationCheck]:
        """Get a specific check by ID"""
        return self._registered_checks.get(check_id)

    def is_check_enabled(self, check_id: str) -> bool:
        """Check if a specific check is enabled"""
        # If entire check category is disabled, no checks are enabled
        if not self.enabled:
            return False

        # If check is explicitly disabled
        if check_id in self.disabled_checks:
            return False

        # If we have enabled standards filter, check must have at least one enabled standard
        if self.enabled_standards:
            check = self.get_check(check_id)
            if check and check.standards:
                # Check is enabled if it has at least one enabled standard
                return bool(check.standards.intersection(self.enabled_standards))
            else:
                # Checks without standards are disabled when standards filtering is active
                return False

        return True

    def create_finding(
            self,
            check_id: str,
            evidence: Optional[Dict[str, Any]] = None,
            description_override: Optional[str] = None,
            confidence: ConfidenceLevel = ConfidenceLevel.HIGH,
    ) -> ValidationFinding:
        """Create a finding from a registered check"""
        check = self.get_check(check_id)
        if not check:
            raise ValueError(f"Check {check_id} not registered with check category")

        # Get the primary standard reference (first one if multiple)
        standard_ref = None
        if check.standard_refs:
            # Filter enabled standards if filtering is active
            if self.enabled_standards:
                enabled_refs = [ref for ref in check.standard_refs if ref.standard in self.enabled_standards]
                if enabled_refs:
                    standard_ref = enabled_refs[0]
            else:
                standard_ref = check.standard_refs[0]

        return ValidationFinding(
            check_id=check_id,
            severity=check.severity,
            confidence=confidence,
            title=check.title,
            description=description_override or check.description,
            remediation=check.remediation,
            evidence=evidence or {},
            check_category=self.get_check_info().check_id,
            standard_ref=standard_ref,
        )
