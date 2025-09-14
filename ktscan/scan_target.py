import re
from dataclasses import dataclass
from typing import List
from urllib.parse import urlparse


@dataclass
class ScanTarget:
    original_url: str  # Original URL spec for grouping/display
    hostname: str  # Extracted hostname
    ports: List[int]  # Resolved ports for this target

    @classmethod
    def from_url_spec(
        cls, url_spec: str, global_ports: List[int] = None
    ) -> "ScanTarget":
        """
        Parse URL specification and resolve ports

        Examples:
        - "https://example.com" + global_ports=[443,8443] -> ports=[443,8443]
        - "https://example.com:8080" + global_ports=[443] -> ports=[8080]
        - "https://example.com:443,8443,9000" -> ports=[443,8443,9000]
        """
        # First try to match comma-separated ports at the end (custom format)
        comma_port_pattern = r":(\d+(?:\s*,\s*\d+)*)$"
        comma_match = re.search(comma_port_pattern, url_spec)
        
        if comma_match:
            # URL contains comma-separated port specification at the end
            base_url = url_spec[:comma_match.start()]
            port_spec = comma_match.group(1)
            try:
                ports = [int(p.strip()) for p in port_spec.split(",")]
            except ValueError:
                raise ValueError(f"Invalid port specification in URL: {url_spec}")
        else:
            # Check for single invalid port pattern (like :invalid) at the end
            # But exclude authentication patterns (user:pass@host)
            invalid_port_pattern = r":([^/?\s@]+)$"
            invalid_match = re.search(invalid_port_pattern, url_spec)
            if invalid_match:
                port_str = invalid_match.group(1)
                if not port_str.isdigit():
                    raise ValueError(f"Invalid port specification in URL: {url_spec}")
            
            # Try to parse as standard URL and extract port from it
            if not url_spec.startswith(("http://", "https://")):
                test_url = "https://" + url_spec
            else:
                test_url = url_spec
                
            try:
                parsed = urlparse(test_url)
                if parsed.port:
                    # Found a standard port in URL
                    ports = [parsed.port]
                    base_url = url_spec
                else:
                    # No port found, use global ports
                    ports = global_ports or []
                    base_url = url_spec
            except ValueError as e:
                # URL parsing failed - if it's due to invalid port, re-raise
                if "invalid literal for int()" in str(e):
                    raise ValueError(f"Invalid port specification in URL: {url_spec}")
                # Otherwise, fall back to global ports
                ports = global_ports or []
                base_url = url_spec

        hostname = cls._extract_hostname(base_url)
        return cls(original_url=url_spec, hostname=hostname, ports=ports)

    @staticmethod
    def _extract_hostname(url: str) -> str:
        """Extract hostname from URL"""
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        parsed = urlparse(url)
        hostname = parsed.hostname or parsed.netloc

        if not hostname:
            raise ValueError(f"Cannot extract hostname from URL: {url}")

        return hostname

    def __str__(self) -> str:
        """String representation for logging/debugging"""
        ports_str = ",".join(map(str, self.ports))
        return f"{self.hostname}:{ports_str}"


def resolve_scan_targets(
    config_urls: List[str], global_ports: List[int] = None
) -> List[ScanTarget]:
    """
    Resolve a list of URL specifications into ScanTarget objects

    Args:
        config_urls: List of URL specifications (may include embedded ports)
        global_ports: Default ports to use for URLs without port specifications

    Returns:
        List of ScanTarget objects with resolved hostnames and ports

    Raises:
        ValueError: If no ports can be resolved for any URL
    """
    targets = []

    for url_spec in config_urls:
        try:
            target = ScanTarget.from_url_spec(url_spec, global_ports)

            # Validate that we have ports for this target
            if not target.ports:
                raise ValueError(
                    f"No ports specified for URL '{url_spec}' and no global ports available"
                )

            targets.append(target)

        except Exception as e:
            raise ValueError(f"Failed to parse URL specification '{url_spec}': {e}")

    return targets
