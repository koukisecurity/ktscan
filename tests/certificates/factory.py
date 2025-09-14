"""
Test certificate factory for generating certificates with specific characteristics.
"""

import ipaddress
from datetime import datetime, timedelta
from typing import List, Optional, Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, dsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID


class TestCertificateFactory:
    """Factory for generating test certificates with specific characteristics."""

    def __init__(self):
        self.serial_counter = 1000

    def _get_next_serial(self) -> int:
        """Get next unique serial number"""
        self.serial_counter += 1
        return self.serial_counter

    def _generate_rsa_key(self, key_size: int = 2048) -> rsa.RSAPrivateKey:
        """Generate RSA private key"""
        return rsa.generate_private_key(public_exponent=65537, key_size=key_size)

    def _generate_ecdsa_key(
        self, curve_name: str = "secp256r1"
    ) -> ec.EllipticCurvePrivateKey:
        """Generate ECDSA private key"""
        if curve_name == "secp256r1":
            curve = ec.SECP256R1()
        elif curve_name == "secp384r1":
            curve = ec.SECP384R1()
        elif curve_name == "secp521r1":
            curve = ec.SECP521R1()
        else:
            raise ValueError(f"Unsupported curve: {curve_name}")
        return ec.generate_private_key(curve)

    def _generate_ed25519_key(self) -> ed25519.Ed25519PrivateKey:
        """Generate Ed25519 private key"""
        return ed25519.Ed25519PrivateKey.generate()

    def _generate_dsa_key(self, key_size: int = 1024) -> dsa.DSAPrivateKey:
        """Generate DSA private key (for legacy testing)"""
        return dsa.generate_private_key(key_size=key_size)

    def create_certificate(
        self,
        subject_name: str = "example.com",
        issuer_name: Optional[str] = None,
        not_before: Optional[datetime] = None,
        not_after: Optional[datetime] = None,
        key_type: str = "rsa",
        key_size: int = 2048,
        curve_name: str = "secp256r1",
        signature_algorithm: str = "sha256",
        san_domains: Optional[List[str]] = None,
        san_ips: Optional[List[str]] = None,
        key_usage: Optional[List[str]] = None,
        extended_key_usage: Optional[List[str]] = None,
        basic_constraints_ca: Optional[bool] = None,
        basic_constraints_path_len: Optional[int] = None,
        ocsp_urls: Optional[List[str]] = None,
        crl_urls: Optional[List[str]] = None,
        issuer_key: Optional[Any] = None,
        self_signed: bool = False,
        **kwargs,
    ) -> tuple[x509.Certificate, Any]:
        """
        Create a test certificate with specified characteristics.

        Args:
            subject_name: Subject common name
            issuer_name: Issuer common name (if different from subject)
            not_before: Certificate validity start
            not_after: Certificate validity end
            key_type: Key type (rsa, ecdsa, ed25519, dsa)
            key_size: RSA/DSA key size in bits
            curve_name: ECDSA curve name
            signature_algorithm: Signature algorithm (sha1, sha256, sha384, sha512)
            san_domains: Subject Alternative Names (DNS)
            san_ips: Subject Alternative Names (IP addresses)
            key_usage: Key usage extensions
            extended_key_usage: Extended key usage extensions
            basic_constraints_ca: CA flag for basic constraints
            basic_constraints_path_len: Path length constraint
            ocsp_urls: OCSP responder URLs
            crl_urls: CRL distribution point URLs
            issuer_key: Private key for signing (if not self-signed)
            self_signed: Whether to create self-signed certificate

        Returns:
            Tuple of (certificate, private_key)
        """
        # Set defaults
        if not_before is None:
            not_before = datetime(2024, 1, 1)
        if not_after is None:
            not_after = datetime(2024, 12, 31)
        if issuer_name is None:
            issuer_name = subject_name if self_signed else "Test CA"

        # Generate key pair
        if key_type == "rsa":
            private_key = self._generate_rsa_key(key_size)
        elif key_type == "ecdsa":
            private_key = self._generate_ecdsa_key(curve_name)
        elif key_type == "ed25519":
            private_key = self._generate_ed25519_key()
        elif key_type == "dsa":
            private_key = self._generate_dsa_key(key_size)
        else:
            raise ValueError(f"Unsupported key type: {key_type}")

        # Choose signature algorithm
        if signature_algorithm == "sha1":
            sig_alg = hashes.SHA1()
        elif signature_algorithm == "sha256":
            sig_alg = hashes.SHA256()
        elif signature_algorithm == "sha384":
            sig_alg = hashes.SHA384()
        elif signature_algorithm == "sha512":
            sig_alg = hashes.SHA512()
        else:
            raise ValueError(f"Unsupported signature algorithm: {signature_algorithm}")

        # Ed25519 and Ed448 keys require algorithm to be None
        if key_type in ["ed25519", "ed448"]:
            sig_alg = None

        # Build certificate
        builder = x509.CertificateBuilder()

        # Subject and issuer
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_name)])
        issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)])

        builder = builder.subject_name(subject)
        builder = builder.issuer_name(issuer)
        builder = builder.public_key(private_key.public_key())
        builder = builder.serial_number(self._get_next_serial())
        builder = builder.not_valid_before(not_before)
        builder = builder.not_valid_after(not_after)

        # Subject Alternative Names
        san_list = []
        if san_domains:
            for domain in san_domains:
                san_list.append(x509.DNSName(domain))
        if san_ips:
            for ip in san_ips:
                san_list.append(x509.IPAddress(ipaddress.ip_address(ip)))

        # Only add SAN extension if we have SAN entries
        if san_list:
            builder = builder.add_extension(
                x509.SubjectAlternativeName(san_list), critical=False
            )

        # Key Usage
        if key_usage:
            ku_map = {
                "digital_signature": "digital_signature",
                "content_commitment": "content_commitment",
                "key_encipherment": "key_encipherment",
                "data_encipherment": "data_encipherment",
                "key_agreement": "key_agreement",
                "key_cert_sign": "key_cert_sign",
                "crl_sign": "crl_sign",
                "encipher_only": "encipher_only",
                "decipher_only": "decipher_only",
            }
            ku_kwargs = {attr: (name in key_usage) for name, attr in ku_map.items()}
            builder = builder.add_extension(x509.KeyUsage(**ku_kwargs), critical=True)

        # Extended Key Usage
        if extended_key_usage:
            eku_map = {
                "server_auth": ExtendedKeyUsageOID.SERVER_AUTH,
                "client_auth": ExtendedKeyUsageOID.CLIENT_AUTH,
                "code_signing": ExtendedKeyUsageOID.CODE_SIGNING,
                "email_protection": ExtendedKeyUsageOID.EMAIL_PROTECTION,
                "time_stamping": ExtendedKeyUsageOID.TIME_STAMPING,
                "ocsp_signing": ExtendedKeyUsageOID.OCSP_SIGNING,
            }
            eku_list = [eku_map[name] for name in extended_key_usage if name in eku_map]
            if eku_list:
                builder = builder.add_extension(
                    x509.ExtendedKeyUsage(eku_list), critical=False
                )

        # Basic Constraints
        if basic_constraints_ca is not None:
            builder = builder.add_extension(
                x509.BasicConstraints(
                    ca=basic_constraints_ca, path_length=basic_constraints_path_len
                ),
                critical=True,
            )

        # OCSP URLs (Authority Information Access)
        if ocsp_urls:
            aia_list = []
            for url in ocsp_urls:
                aia_list.append(
                    x509.AccessDescription(
                        access_method=x509.AuthorityInformationAccessOID.OCSP,
                        access_location=x509.UniformResourceIdentifier(url),
                    )
                )
            if aia_list:
                builder = builder.add_extension(
                    x509.AuthorityInformationAccess(aia_list), critical=False
                )

        # CRL URLs (CRL Distribution Points)
        if crl_urls:
            crl_list = []
            for url in crl_urls:
                crl_list.append(
                    x509.DistributionPoint(
                        full_name=[x509.UniformResourceIdentifier(url)],
                        relative_name=None,
                        crl_issuer=None,
                        reasons=None,
                    )
                )
            builder = builder.add_extension(
                x509.CRLDistributionPoints(crl_list), critical=False
            )

        # Sign the certificate
        signing_key = private_key if (self_signed or issuer_key is None) else issuer_key
        certificate = builder.sign(signing_key, sig_alg)

        return certificate, private_key

    # Convenience methods for common certificate types

    def create_valid_cert(self, **kwargs) -> tuple[x509.Certificate, Any]:
        """Create a standard valid certificate"""
        defaults = {
            "not_before": datetime(2024, 1, 1),
            "not_after": datetime(2024, 12, 31),
            "key_usage": ["digital_signature", "key_encipherment"],
            "extended_key_usage": ["server_auth"],
        }
        defaults.update(kwargs)
        return self.create_certificate(**defaults)

    def create_expired_cert(
        self, days_ago: int = 30, **kwargs
    ) -> tuple[x509.Certificate, Any]:
        """Create an expired certificate"""
        end_date = datetime.now() - timedelta(days=days_ago)
        start_date = end_date - timedelta(days=365)
        defaults = {"not_before": start_date, "not_after": end_date}
        defaults.update(kwargs)
        return self.create_certificate(**defaults)

    def create_future_cert(
        self, days_future: int = 30, **kwargs
    ) -> tuple[x509.Certificate, Any]:
        """Create a certificate valid only in the future"""
        start_date = datetime.now() + timedelta(days=days_future)
        end_date = start_date + timedelta(days=365)
        defaults = {"not_before": start_date, "not_after": end_date}
        defaults.update(kwargs)
        return self.create_certificate(**defaults)

    def create_weak_rsa_cert(
        self, key_size: int = 1024, **kwargs
    ) -> tuple[x509.Certificate, Any]:
        """Create certificate with weak RSA key"""
        defaults = {"key_type": "rsa", "key_size": key_size}
        defaults.update(kwargs)
        return self.create_certificate(**defaults)

    def create_sha1_cert(self, **kwargs) -> tuple[x509.Certificate, Any]:
        """Create certificate that appears to use SHA-1 - for testing weak signature detection"""
        # Since modern cryptography doesn't support SHA-1 signatures in new certificates,
        # this creates a SHA-256 certificate. Tests should mock the signature algorithm OID
        # to simulate SHA-1 for validation testing.
        defaults = {"signature_algorithm": "sha256"}
        defaults.update(kwargs)
        return self.create_certificate(**defaults)

    def create_self_signed_cert(self, **kwargs) -> tuple[x509.Certificate, Any]:
        """Create self-signed certificate (root CA)"""
        defaults = {
            "self_signed": True,
            "basic_constraints_ca": True,
            "key_usage": ["key_cert_sign", "crl_sign"],
        }
        defaults.update(kwargs)
        return self.create_certificate(**defaults)

    def create_hostname_mismatch_cert(
        self, actual_hostname: str = "wrong.example.com", **kwargs
    ) -> tuple[x509.Certificate, Any]:
        """Create certificate with hostname mismatch"""
        defaults = {"subject_name": actual_hostname}
        defaults.update(kwargs)
        return self.create_certificate(**defaults)

    def create_no_extensions_cert(self, **kwargs) -> tuple[x509.Certificate, Any]:
        """Create certificate without key usage extensions"""
        # Explicitly set extension-related parameters to None/empty
        defaults = {
            "key_usage": None,
            "extended_key_usage": None,
            "basic_constraints_ca": None,
            "san_domains": None,
            "san_ips": None,
        }
        defaults.update(kwargs)
        return self.create_certificate(**defaults)

    def create_cert_without_san(self, **kwargs) -> tuple[x509.Certificate, Any]:
        """Create certificate without SAN extension"""
        defaults = {"san_domains": None, "san_ips": None}
        defaults.update(kwargs)
        return self.create_certificate(**defaults)

    def create_cert_with_revocation_info(
        self, **kwargs
    ) -> tuple[x509.Certificate, Any]:
        """Create certificate with OCSP and CRL information"""
        defaults = {
            "ocsp_urls": ["http://ocsp.example.com"],
            "crl_urls": ["http://crl.example.com/cert.crl"],
        }
        defaults.update(kwargs)
        return self.create_certificate(**defaults)

    def create_cert_chain(self, levels: int = 3) -> List[tuple[x509.Certificate, Any]]:
        """
        Create a certificate chain with specified levels.

        Args:
            levels: Number of certificates in chain (root CA, intermediates, end-entity)

        Returns:
            List of (certificate, private_key) tuples, ordered from end-entity to root
        """
        chain = []

        # Create root CA
        root_cert, root_key = self.create_self_signed_cert(
            subject_name="Root CA",
            basic_constraints_ca=True,
            basic_constraints_path_len=levels - 1 if levels > 1 else None,
        )

        current_cert = root_cert
        current_key = root_key

        # Create intermediate CAs
        for i in range(levels - 2):
            intermediate_cert, intermediate_key = self.create_certificate(
                subject_name=f"Intermediate CA {i+1}",
                issuer_name=current_cert.subject.get_attributes_for_oid(
                    NameOID.COMMON_NAME
                )[0].value,
                basic_constraints_ca=True,
                basic_constraints_path_len=(
                    levels - i - 2 if levels - i - 2 > 0 else None
                ),
                key_usage=["key_cert_sign", "crl_sign"],
                issuer_key=current_key,
            )
            chain.insert(0, (intermediate_cert, intermediate_key))
            current_cert = intermediate_cert
            current_key = intermediate_key

        # Create end-entity certificate
        if levels > 1:
            end_entity_cert, end_entity_key = self.create_certificate(
                subject_name="example.com",
                issuer_name=current_cert.subject.get_attributes_for_oid(
                    NameOID.COMMON_NAME
                )[0].value,
                key_usage=["digital_signature", "key_encipherment"],
                extended_key_usage=["server_auth"],
                issuer_key=current_key,
            )
            chain.insert(0, (end_entity_cert, end_entity_key))

        # Add root CA at the end
        chain.append((root_cert, root_key))

        return chain
