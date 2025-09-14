"""
Cryptographic validation checks.

This module contains checks related to signature algorithms, key parameters, 
key sizes, elliptic curves, and cryptographic strength validation.
"""

import logging
from typing import List

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448, dsa

from ..models import (
    BaseCheck,
    ValidationFinding,
    ValidationSeverity,
    ValidationCheck,
    CheckInfo,
)


class CryptoCheck(BaseCheck):
    """Cryptographic validation checks"""

    MINIMUM_RSA_KEY_SIZE = 2048
    MINIMUM_DSA_KEY_SIZE = 2048

    APPROVED_EC_CURVES = {
        "secp256r1": 256,  # NIST P-256
        "secp384r1": 384,  # NIST P-384
        "secp521r1": 521,  # NIST P-521
    }

    # Weak signature algorithms
    WEAK_SIGNATURE_ALGORITHMS = {
        "md5WithRSAEncryption",
        "sha1WithRSAEncryption", 
        "md5WithRSA",
        "sha1WithRSA",
        "md2WithRSAEncryption",
        "md4WithRSAEncryption",
    }

    # Deprecated signature algorithms
    DEPRECATED_SIGNATURE_ALGORITHMS = {
        "dsaWithSHA1",
        "dsaWithSHA224", 
        "dsaWithSHA256",
        "ecdsa-with-SHA1",
    }

    def __init__(self, config: dict = None):
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        
    def get_check_info(self) -> CheckInfo:
        return CheckInfo(
            check_id="CRYPTO",
            title="Cryptographic Validation Checks",
            description="Validates signature algorithms, key parameters, key sizes, elliptic curves, and cryptographic strength"
        )

    def _register_checks(self) -> None:
        """Register all cryptographic checks"""
        
        # CRITICAL severity checks
        self.register_check(ValidationCheck(
            check_id="CRYPTO.WEAK_RSA_CRITICAL",
            title="Critically Weak RSA Key Size",
            description="RSA key size is critically weak (less than 1024 bits)",
            remediation="Replace with RSA key of at least 2048 bits immediately",
        ))
        
        self.register_check(ValidationCheck(
            check_id="CRYPTO.WEAK_DSA",
            title="Weak DSA Key Size",
            description="DSA key size is below minimum requirements",
            remediation="Replace with RSA (2048+ bits) or ECDSA certificate",
        ))
        
        self.register_check(ValidationCheck(
            check_id="CRYPTO.WEAK_ALGORITHM",
            title="Weak Signature Algorithm",
            description="Certificate uses weak signature algorithm",
            remediation="Replace certificate with stronger signature algorithm (SHA-256 or higher)",
        ))
        
        # HIGH severity checks
        self.register_check(ValidationCheck(
            check_id="CRYPTO.WEAK_RSA",
            title="Weak RSA Key Size",
            description="RSA key size is below recommended minimum of 2048 bits",
            remediation="Replace with RSA key of at least 2048 bits",
        ))
        
        self.register_check(ValidationCheck(
            check_id="CRYPTO.NIST_INSUFFICIENT_RSA",
            title="NIST Insufficient RSA Key Size",
            description="RSA key size below NIST minimum requirements",
            remediation="Use RSA key of at least 2048 bits per NIST SP 800-57",
        ))
        
        self.register_check(ValidationCheck(
            check_id="CRYPTO.INVALID_RSA_EXPONENT",
            title="Invalid RSA Public Exponent",
            description="RSA public exponent must be odd and ≥ 3",
            remediation="Use proper RSA public exponent (typically 65537)",
        ))
        
        self.register_check(ValidationCheck(
            check_id="CRYPTO.UNAPPROVED_EC_CURVE",
            title="Unapproved Elliptic Curve",
            description="Certificate uses non-standard elliptic curve",
            remediation="Use NIST-approved curves: P-256, P-384, or P-521",
        ))
        
        self.register_check(ValidationCheck(
            check_id="CRYPTO.WEAK_EC_CURVE",
            title="Weak Elliptic Curve",
            description="Elliptic curve provides insufficient security strength",
            remediation="Use stronger elliptic curve (P-256, P-384, or P-521)",
        ))
        
        self.register_check(ValidationCheck(
            check_id="CRYPTO.DSA_DEPRECATED",
            title="DSA Algorithm Deprecated",
            description="DSA algorithm is deprecated for new certificates",
            remediation="Use RSA or ECDSA algorithm instead",
        ))
        
        self.register_check(ValidationCheck(
            check_id="CRYPTO.DEPRECATED_ALGORITHM",
            title="Deprecated Signature Algorithm",
            description="Certificate uses deprecated signature algorithm",
            remediation="Replace with modern signature algorithm (SHA-256, SHA-384, or SHA-512)",
        ))
        
        self.register_check(ValidationCheck(
            check_id="CRYPTO.NIST_DSA_DEPRECATED",
            title="NIST DSA Signature Deprecated",
            description="DSA signature algorithm is deprecated by NIST",
            remediation="Use RSA or ECDSA signature algorithm",
        ))
        
        # MEDIUM severity checks
        self.register_check(ValidationCheck(
            check_id="CRYPTO.ENCODING_ERROR",
            title="Key Encoding Error",
            description="Error occurred while parsing public key",
            remediation="Check certificate key encoding and format",
        ))
        
        self.register_check(ValidationCheck(
            check_id="CRYPTO.UNKNOWN_ALGORITHM",
            title="Unknown Algorithm",
            description="Certificate uses unknown or unsupported algorithm",
            remediation="Use standard algorithm (RSA, ECDSA, or EdDSA)",
        ))
        
        self.register_check(ValidationCheck(
            check_id="CRYPTO.RSA_SIZE_WARNING",
            title="RSA Key Size Warning",
            description="RSA key size below future recommendations",
            remediation="Consider upgrading to 3072-bit RSA or ECDSA",
        ))
        
        self.register_check(ValidationCheck(
            check_id="CRYPTO.OVERSIZED",
            title="Oversized Public Key",
            description="Public key size is unusually large",
            remediation="Consider using standard key sizes for better compatibility",
        ))
        
        # INFO severity checks
        self.register_check(ValidationCheck(
            check_id="CRYPTO.MODERN_ALGORITHM",
            title="Modern Signature Algorithm",
            description="Certificate uses modern signature algorithm",
        ))
        
        self.register_check(ValidationCheck(
            check_id="CRYPTO.ED25519_ALGORITHM",
            title="Ed25519 Key Algorithm",
            description="Certificate uses Ed25519, a modern elliptic curve signature algorithm",
        ))
        
        self.register_check(ValidationCheck(
            check_id="CRYPTO.ED448_ALGORITHM",
            title="Ed448 Key Algorithm",
            description="Certificate uses Ed448, a high-security elliptic curve signature algorithm",
        ))

    def validate(
        self, certificate: x509.Certificate, context: dict = None
    ) -> List[ValidationFinding]:
        """Validate cryptographic parameters"""
        findings = []

        findings.extend(self._validate_signature_algorithm(certificate))
        findings.extend(self._validate_public_key(certificate))
        findings.extend(self._validate_key_algorithm(certificate))

        return [f for f in findings if self.is_check_enabled(f.check_id)]

    def _validate_signature_algorithm(self, certificate: x509.Certificate) -> List[ValidationFinding]:
        """Validate signature algorithm"""
        findings = []
        
        try:
            signature_algorithm = certificate.signature_algorithm_oid._name
            
            # Check for weak algorithms (MD5, SHA-1)
            if signature_algorithm in self.WEAK_SIGNATURE_ALGORITHMS:
                if "md5" in signature_algorithm.lower():
                    findings.append(
                        self.create_finding(
                            check_id="CRYPTO.WEAK_ALGORITHM",
                            evidence={"algorithm": signature_algorithm, "weakness": "MD5 hash"},
                            description_override=f"Certificate uses weak MD5-based signature algorithm: {signature_algorithm}"
                        )
                    )
                elif "sha1" in signature_algorithm.lower():
                    findings.append(
                        self.create_finding(
                            check_id="CRYPTO.WEAK_ALGORITHM",
                            evidence={"algorithm": signature_algorithm, "weakness": "SHA-1 hash"},
                            description_override=f"Certificate uses weak SHA-1 signature algorithm: {signature_algorithm}"
                        )
                    )
                else:
                    findings.append(
                        self.create_finding(
                            check_id="CRYPTO.WEAK_ALGORITHM",
                            evidence={"algorithm": signature_algorithm},
                            description_override=f"Certificate uses weak signature algorithm: {signature_algorithm}"
                        )
                    )
            
            # Check for deprecated algorithms
            elif signature_algorithm in self.DEPRECATED_SIGNATURE_ALGORITHMS:
                if "dsa" in signature_algorithm.lower():
                    findings.append(
                        self.create_finding(
                            check_id="CRYPTO.DEPRECATED_ALGORITHM",
                            evidence={"algorithm": signature_algorithm},
                            description_override=f"Certificate uses deprecated DSA signature algorithm: {signature_algorithm}"
                        )
                    )
                else:
                    findings.append(
                        self.create_finding(
                            check_id="CRYPTO.DEPRECATED_ALGORITHM",
                            evidence={"algorithm": signature_algorithm},
                            description_override=f"Certificate uses deprecated signature algorithm: {signature_algorithm}"
                        )
                    )
            
            # Check for modern algorithms (INFO level)
            elif signature_algorithm in ["sha256WithRSAEncryption", "sha384WithRSAEncryption", "sha512WithRSAEncryption",
                                       "ecdsa-with-SHA256", "ecdsa-with-SHA384", "ecdsa-with-SHA512"]:
                findings.append(
                    self.create_finding(
                        check_id="CRYPTO.MODERN_ALGORITHM",
                        evidence={"algorithm": signature_algorithm}
                    )
                )
            
            # Unknown algorithms
            else:
                findings.append(
                    self.create_finding(
                        check_id="CRYPTO.UNKNOWN_ALGORITHM",
                        evidence={"algorithm": signature_algorithm}
                    )
                )
                
            # Additional DSA deprecation check for NIST compliance  
            # Check for DSA but exclude ECDSA
            if "dsa" in signature_algorithm.lower() and "ecdsa" not in signature_algorithm.lower():
                findings.append(
                    self.create_finding(
                        check_id="CRYPTO.NIST_DSA_DEPRECATED",
                        evidence={"algorithm": signature_algorithm, "nist_standard": "SP 800-57"}
                    )
                )
                
        except Exception as e:
            self.logger.debug(f"Error validating signature algorithm: {e}")
            
        return findings

    def _validate_public_key(self, certificate: x509.Certificate) -> List[ValidationFinding]:
        """Validate the certificate's public key parameters"""
        findings = []
        
        try:
            public_key = certificate.public_key()

            if isinstance(public_key, rsa.RSAPublicKey):
                findings.extend(self._validate_rsa_key(public_key))
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                findings.extend(self._validate_ec_key(public_key))
            elif isinstance(public_key, dsa.DSAPublicKey):
                findings.extend(self._validate_dsa_key(public_key))
            elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
                findings.extend(self._validate_edwards_key(public_key))
            else:
                findings.append(
                    self.create_finding(
                        check_id="CRYPTO.UNKNOWN_ALGORITHM",
                        evidence={"key_type": type(public_key).__name__}
                    )
                )
                
        except Exception as e:
            self.logger.debug(f"Error validating public key: {e}")
        
        return findings

    def _validate_rsa_key(self, public_key: rsa.RSAPublicKey) -> List[ValidationFinding]:
        """Validate RSA key parameters"""
        findings = []
        key_size = public_key.key_size

        if key_size < self.MINIMUM_RSA_KEY_SIZE:
            if key_size < 1024:
                findings.append(
                    self.create_finding(
                        check_id="CRYPTO.WEAK_RSA_CRITICAL",
                        evidence={
                            "current_size": key_size,
                            "minimum_size": self.MINIMUM_RSA_KEY_SIZE,
                        },
                        description_override=f"RSA key size {key_size} bits is critically weak (less than 1024 bits)"
                    )
                )
            else:
                findings.append(
                    self.create_finding(
                        check_id="CRYPTO.WEAK_RSA",
                        evidence={
                            "current_size": key_size,
                            "minimum_size": self.MINIMUM_RSA_KEY_SIZE,
                        },
                        description_override=f"RSA key size {key_size} bits is below recommended minimum of {self.MINIMUM_RSA_KEY_SIZE} bits"
                    )
                )
                # Also add NIST-specific finding
                findings.append(
                    self.create_finding(
                        check_id="CRYPTO.NIST_INSUFFICIENT_RSA",
                        evidence={
                            "current_size": key_size,
                            "nist_minimum": 2048,
                            "nist_standard": "SP 800-57"
                        },
                    )
                )
        
        # Validate RSA public exponent (CABF requirement: odd number ≥ 3)
        try:
            exponent = public_key.public_numbers().e
            if exponent < 3 or exponent % 2 == 0:
                findings.append(
                    self.create_finding(
                        check_id="CRYPTO.INVALID_RSA_EXPONENT",
                        evidence={
                            "exponent": exponent,
                            "requirement": "odd number ≥ 3"
                        },
                    )
                )
        except Exception as e:
            self.logger.debug(f"Error validating RSA exponent: {e}")
            
        if key_size < 3072:
            findings.append(
                self.create_finding(
                    check_id="CRYPTO.RSA_SIZE_WARNING",
                    evidence={
                        "current_size": key_size,
                        "future_recommendation": 3072
                    },
                )
            )
        
        return findings

    def _validate_ec_key(self, public_key: ec.EllipticCurvePublicKey) -> List[ValidationFinding]:
        """Validate elliptic curve key parameters"""
        findings = []
        
        try:
            curve_name = public_key.curve.name
            
            if curve_name not in self.APPROVED_EC_CURVES:
                findings.append(
                    self.create_finding(
                        check_id="CRYPTO.UNAPPROVED_EC_CURVE",
                        evidence={
                            "curve": curve_name,
                            "approved_curves": list(self.APPROVED_EC_CURVES.keys())
                        },
                    )
                )
            else:
                # Check if curve provides sufficient security strength
                key_size = self.APPROVED_EC_CURVES[curve_name]
                if key_size < 256:
                    findings.append(
                        self.create_finding(
                            check_id="CRYPTO.WEAK_EC_CURVE",
                            evidence={
                                "curve": curve_name,
                                "security_strength": key_size,
                                "minimum_strength": 256
                            },
                        )
                    )
                    
        except Exception as e:
            self.logger.debug(f"Error validating EC key: {e}")
            
        return findings

    def _validate_dsa_key(self, public_key: dsa.DSAPublicKey) -> List[ValidationFinding]:
        """Validate DSA key parameters"""
        findings = []
        
        # DSA is generally deprecated
        key_size = public_key.key_size
        findings.append(
            self.create_finding(
                check_id="CRYPTO.DSA_DEPRECATED",
                evidence={"algorithm": "DSA", "key_size": key_size},
            )
        )
        
        try:
            key_size = public_key.key_size
            if key_size < self.MINIMUM_DSA_KEY_SIZE:
                findings.append(
                    self.create_finding(
                        check_id="CRYPTO.WEAK_DSA",
                        evidence={
                            "current_size": key_size,
                            "minimum_size": self.MINIMUM_DSA_KEY_SIZE
                        },
                    )
                )
        except Exception as e:
            self.logger.debug(f"Error validating DSA key size: {e}")
            
        return findings

    def _validate_edwards_key(self, public_key) -> List[ValidationFinding]:
        """Validate Edwards curve key parameters"""
        findings = []
        
        if isinstance(public_key, ed25519.Ed25519PublicKey):
            findings.append(
                self.create_finding(
                    check_id="CRYPTO.ED25519_ALGORITHM",
                    evidence={"algorithm": "Ed25519", "security_level": "high"},
                )
            )
        elif isinstance(public_key, ed448.Ed448PublicKey):
            findings.append(
                self.create_finding(
                    check_id="CRYPTO.ED448_ALGORITHM",
                    evidence={"algorithm": "Ed448", "security_level": "high"},
                )
            )
            
        return findings

    def _validate_key_algorithm(self, certificate: x509.Certificate) -> List[ValidationFinding]:
        """Validate key algorithm information"""
        findings = []
        
        try:
            public_key = certificate.public_key()
            
            # Check for oversized keys (could indicate implementation issues)
            if hasattr(public_key, 'key_size'):
                key_size = public_key.key_size
                
                # RSA keys larger than 8192 bits are usually unnecessary
                if isinstance(public_key, rsa.RSAPublicKey) and key_size > 8192:
                    findings.append(
                        self.create_finding(
                            check_id="CRYPTO.OVERSIZED",
                            evidence={
                                "key_type": "RSA",
                                "key_size": key_size,
                                "recommended_max": 8192
                            },
                        )
                    )
                    
        except Exception as e:
            findings.append(
                self.create_finding(
                    check_id="CRYPTO.ENCODING_ERROR",
                    evidence={"error": str(e)},
                )
            )
            
        return findings