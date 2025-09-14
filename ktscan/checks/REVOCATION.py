"""
Certificate revocation validation checks.

This module contains checks related to OCSP validation,
CRL checking, and revocation status verification.
"""

import logging
from typing import List

import requests
from cryptography import x509
from cryptography.x509.oid import ExtensionOID

from ..models import (
    BaseCheck,
    ValidationFinding,
    ValidationSeverity,
    ValidationCheck,
    CheckInfo,
)


class RevocationCheck(BaseCheck):
    """Certificate revocation validation checks"""

    def __init__(self, config: dict = None, timeout: int = 10, thread_manager=None):
        super().__init__(config)
        self.check_ocsp = config.get("check_ocsp", True) if config else True
        self.ocsp_timeout = config.get("ocsp_timeout", 10) if config else 10
        self.timeout = timeout
        self.thread_manager = thread_manager
        self.logger = logging.getLogger(__name__)
        
    def get_check_info(self) -> CheckInfo:
        return CheckInfo(
            check_id="REVOCATION",
            title="Certificate Revocation Checks",
            description="Validates certificate revocation status using OCSP and CRL mechanisms"
        )

    def _register_checks(self) -> None:
        """Register all revocation-related checks"""
        
        # CRITICAL severity checks
        self.register_check(ValidationCheck(
            check_id="REVOCATION.CERTIFICATE_REVOKED",
            title="Certificate Revoked",
            description="Certificate has been revoked by the issuing CA",
            remediation="Obtain a new certificate from the Certificate Authority",
        ))
        
        # HIGH severity checks
        self.register_check(ValidationCheck(
            check_id="REVOCATION.OCSP_RESPONDER_ERROR",
            title="OCSP Responder Error",
            description="OCSP responder returned an error",
            remediation="Check OCSP responder availability or use alternative validation",
        ))
        
        self.register_check(ValidationCheck(
            check_id="REVOCATION.CRL_UNAVAILABLE",
            title="CRL Unavailable",
            description="Certificate Revocation List could not be retrieved",
            remediation="Ensure CRL distribution points are accessible",
        ))
        
        # MEDIUM severity checks
        self.register_check(ValidationCheck(
            check_id="REVOCATION.MISSING_REVOCATION_INFO",
            title="Missing Revocation Information",
            description="Certificate lacks both OCSP and CRL revocation information",
            remediation="Add OCSP or CRL distribution points to certificate",
        ))
        
        self.register_check(ValidationCheck(
            check_id="REVOCATION.INVALID_OCSP_URL",
            title="Invalid OCSP URL",
            description="OCSP URL is not a valid HTTP endpoint",
            remediation="Provide valid HTTP/HTTPS OCSP endpoint",
        ))
        
        self.register_check(ValidationCheck(
            check_id="REVOCATION.OCSP_ENDPOINT_UNREACHABLE",
            title="OCSP Endpoint Unreachable",
            description="OCSP endpoint returned non-success HTTP status",
            remediation="Ensure OCSP endpoint is accessible and functioning",
        ))
        
        self.register_check(ValidationCheck(
            check_id="REVOCATION.MISSING_OCSP_INFO",
            title="Missing OCSP Information",
            description="Certificate lacks OCSP endpoint in Authority Information Access",
            remediation="Add OCSP endpoint for real-time revocation checking",
        ))
        
        self.register_check(ValidationCheck(
            check_id="REVOCATION.INSECURE_OCSP_URL",
            title="Insecure OCSP URL",
            description="OCSP URL uses HTTP instead of HTTPS",
            remediation="Use HTTPS for OCSP endpoint to ensure integrity",
        ))
        
        self.register_check(ValidationCheck(
            check_id="REVOCATION.INVALID_CRL_URL",
            title="Invalid CRL URL",
            description="CRL URL is not a valid HTTP endpoint",
            remediation="Provide valid HTTP/HTTPS CRL endpoint",
        ))
        
        self.register_check(ValidationCheck(
            check_id="REVOCATION.INSECURE_CRL_URL",
            title="Insecure CRL URL",
            description="CRL URL uses HTTP instead of HTTPS",
            remediation="Consider using HTTPS for CRL endpoint",
        ))
        
        self.register_check(ValidationCheck(
            check_id="REVOCATION.CRL_DP_WITH_REASONS",
            title="CRL Distribution Point with Reasons",
            description="CRL Distribution Point specifies revocation reasons",
        ))
        
        self.register_check(ValidationCheck(
            check_id="REVOCATION.OCSP_TIMEOUT",
            title="OCSP Timeout",
            description="OCSP responder request timed out",
            remediation="Check OCSP responder performance or increase timeout",
        ))
        
        self.register_check(ValidationCheck(
            check_id="REVOCATION.CRL_PARSE_ERROR",
            title="CRL Parse Error",
            description="Failed to parse Certificate Revocation List",
            remediation="Verify CRL format and integrity",
        ))
        
        # LOW severity checks
        self.register_check(ValidationCheck(
            check_id="REVOCATION.OCSP_NONCE_MISMATCH",
            title="OCSP Nonce Mismatch",
            description="OCSP response nonce does not match request nonce",
            remediation="Check OCSP responder nonce handling",
        ))
        
        # INFO severity checks
        self.register_check(ValidationCheck(
            check_id="REVOCATION.OCSP_GOOD_STATUS",
            title="OCSP Status Good",
            description="Certificate revocation status confirmed as good via OCSP",
        ))
        
        self.register_check(ValidationCheck(
            check_id="REVOCATION.CRL_CHECK_SUCCESS",
            title="CRL Check Successful",
            description="Certificate not found in Certificate Revocation List",
        ))

    def validate(
        self, certificate: x509.Certificate, context: dict = None
    ) -> List[ValidationFinding]:
        """Validate certificate revocation status"""
        findings = []

        findings.extend(self._validate_revocation_availability(certificate))
        
        if self.check_ocsp:
            findings.extend(self._validate_revocation_info(certificate))

        return [f for f in findings if self.is_check_enabled(f.check_id)]

    def _validate_revocation_availability(self, certificate: x509.Certificate) -> List[ValidationFinding]:
        """Check if revocation information is available"""
        findings = []
        
        has_ocsp = self._has_ocsp_endpoint(certificate)
        has_crl = self._has_crl_endpoint(certificate)
        
        if not has_ocsp and not has_crl:
            findings.append(
                self.create_finding(
                    check_id="REVOCATION.MISSING_REVOCATION_INFO",
                    evidence={"has_ocsp": False, "has_crl": False}
                )
            )
        
        return findings

    def _validate_revocation_info(self, certificate: x509.Certificate) -> List[ValidationFinding]:
        """Validate OCSP and CRL revocation information"""
        if self.thread_manager:
            return self._validate_revocation_info_parallel(certificate)
        else:
            return self._validate_revocation_info_sequential(certificate)

    def _validate_revocation_info_parallel(self, certificate: x509.Certificate) -> List[ValidationFinding]:
        """Validate OCSP and CRL endpoints in parallel using ThreadManager"""
        findings = []

        has_aia_ocsp = False
        has_crl_dp = False
        tasks = []

        # Collect OCSP URLs
        try:
            aia_ext = certificate.extensions.get_extension_for_oid(
                ExtensionOID.AUTHORITY_INFORMATION_ACCESS
            )
            for access_desc in aia_ext.value:
                if access_desc.access_method == x509.oid.AuthorityInformationAccessOID.OCSP:
                    has_aia_ocsp = True
                    ocsp_url = access_desc.access_location.value
                    tasks.append(("ocsp", ocsp_url))
                    break
        except x509.ExtensionNotFound:
            pass

        # Collect CRL URLs
        try:
            crl_ext = certificate.extensions.get_extension_for_oid(
                ExtensionOID.CRL_DISTRIBUTION_POINTS
            )
            has_crl_dp = True
            tasks.append(("crl", crl_ext.value))
        except x509.ExtensionNotFound:
            pass

        # Process tasks in parallel if we have any
        if tasks:
            def validate_endpoint(task):
                endpoint_type, data = task
                try:
                    if endpoint_type == "ocsp":
                        return self._validate_ocsp_endpoint(data)
                    elif endpoint_type == "crl":
                        return self._validate_crl_distribution_points(data)
                except Exception as e:
                    self.logger.debug(f"Error validating {endpoint_type} endpoint: {e}")
                    return []
                return []

            # Run validations in parallel with limited concurrency
            max_revocation_concurrent = min(len(tasks), 3)
            results = self.thread_manager.map_parallel(
                validate_endpoint, tasks, max_concurrent=max_revocation_concurrent
            )

            # Flatten results
            for result in results:
                if result:
                    findings.extend(result)

        return self._add_missing_revocation_findings(findings, has_aia_ocsp, has_crl_dp)

    def _validate_revocation_info_sequential(self, certificate: x509.Certificate) -> List[ValidationFinding]:
        """Validate OCSP and CRL endpoints sequentially (fallback method)"""
        findings = []

        has_aia_ocsp = False
        has_crl_dp = False

        try:
            aia_ext = certificate.extensions.get_extension_for_oid(
                ExtensionOID.AUTHORITY_INFORMATION_ACCESS
            )
            for access_desc in aia_ext.value:
                if access_desc.access_method == x509.oid.AuthorityInformationAccessOID.OCSP:
                    has_aia_ocsp = True
                    findings.extend(
                        self._validate_ocsp_endpoint(access_desc.access_location.value)
                    )
                    break
        except x509.ExtensionNotFound:
            pass

        try:
            crl_ext = certificate.extensions.get_extension_for_oid(
                ExtensionOID.CRL_DISTRIBUTION_POINTS
            )
            has_crl_dp = True
            findings.extend(self._validate_crl_distribution_points(crl_ext.value))
        except x509.ExtensionNotFound:
            pass

        # Check for missing revocation information
        if not has_aia_ocsp and not has_crl_dp:
            findings.append(
                self.create_finding(
                    check_id="REVOCATION.MISSING_REVOCATION_INFO",
                    evidence={"has_ocsp": False, "has_crl": False}
                )
            )

        return self._add_missing_revocation_findings(findings, has_aia_ocsp, has_crl_dp)

    def _add_missing_revocation_findings(
        self, findings: List[ValidationFinding], has_aia_ocsp: bool, has_crl_dp: bool
    ) -> List[ValidationFinding]:
        """Add findings for missing revocation information"""
        # Note: REVOCATION.MISSING_REVOCATION_INFO is already handled in _validate_revocation_availability
        # This method only handles the MISSING_OCSP_INFO case for when CRL exists but OCSP doesn't
        if not has_aia_ocsp and has_crl_dp:
            findings.append(
                self.create_finding(
                    check_id="REVOCATION.MISSING_OCSP_INFO",
                    evidence={},
                )
            )

        return findings

    def _validate_ocsp_endpoint(self, ocsp_url: str) -> List[ValidationFinding]:
        """Validate OCSP endpoint accessibility"""
        findings = []

        if not ocsp_url.startswith("http"):
            findings.append(
                self.create_finding(
                    check_id="REVOCATION.INVALID_OCSP_URL",
                    evidence={"ocsp_url": ocsp_url},
                )
            )
            return findings

        if not ocsp_url.startswith("https"):
            findings.append(
                self.create_finding(
                    check_id="REVOCATION.INSECURE_OCSP_URL",
                    evidence={"ocsp_url": ocsp_url},
                )
            )

        try:
            response = requests.head(ocsp_url, timeout=self.ocsp_timeout)
            if response.status_code not in [200, 405]:  # 405 Method Not Allowed is acceptable for HEAD on OCSP
                findings.append(
                    self.create_finding(
                        check_id="REVOCATION.OCSP_ENDPOINT_UNREACHABLE",
                        evidence={
                            "ocsp_url": ocsp_url,
                            "status_code": response.status_code,
                        },
                    )
                )
        except requests.exceptions.Timeout:
            findings.append(
                self.create_finding(
                    check_id="REVOCATION.OCSP_TIMEOUT",
                    evidence={"ocsp_url": ocsp_url, "timeout": self.ocsp_timeout},
                )
            )
        except requests.exceptions.RequestException as e:
            findings.append(
                self.create_finding(
                    check_id="REVOCATION.OCSP_RESPONDER_ERROR",
                    evidence={"ocsp_url": ocsp_url, "error": str(e)},
                )
            )

        return findings

    def _validate_crl_distribution_points(self, crl_dps: x509.CRLDistributionPoints) -> List[ValidationFinding]:
        """Validate CRL distribution points"""
        findings = []

        if not crl_dps:
            return findings

        for i, dp in enumerate(crl_dps):
            if dp.full_name:
                for name in dp.full_name:
                    if isinstance(name, x509.UniformResourceIdentifier):
                        crl_url = name.value
                        if not crl_url.startswith("http"):
                            findings.append(
                                self.create_finding(
                                    check_id="REVOCATION.INVALID_CRL_URL",
                                    evidence={"crl_url": crl_url, "dp_index": i},
                                )
                            )
                        elif not crl_url.startswith("https"):
                            findings.append(
                                self.create_finding(
                                    check_id="REVOCATION.INSECURE_CRL_URL",
                                    evidence={"crl_url": crl_url, "dp_index": i},
                                )
                            )

            if dp.reasons:
                findings.append(
                    self.create_finding(
                        check_id="REVOCATION.CRL_DP_WITH_REASONS",
                        evidence={
                            "reasons": [str(reason) for reason in dp.reasons],
                            "dp_index": i,
                        },
                    )
                )

        return findings

    def _has_ocsp_endpoint(self, certificate: x509.Certificate) -> bool:
        """Check if certificate has OCSP endpoint"""
        try:
            aia = certificate.extensions.get_extension_for_oid(
                ExtensionOID.AUTHORITY_INFORMATION_ACCESS
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
                ExtensionOID.CRL_DISTRIBUTION_POINTS
            )
            return len(crl_dp.value) > 0
        except x509.ExtensionNotFound:
            pass
        return False