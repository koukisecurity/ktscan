"""Simple input validation for better user experience"""
import ipaddress
import re
from typing import Tuple, Optional
from urllib.parse import urlparse

class ValidationError(ValueError):
    """Friendly validation error"""
    pass

def validate_url_basic(url: str) -> Tuple[str, str, int]:
    """
    Basic URL validation for better error messages.
    Returns: (cleaned_url, hostname, port)
    """
    if not url or not url.strip():
        raise ValidationError("URL cannot be empty")
    
    url = url.strip()
    
    # Check for unsupported schemes before adding https://
    if '://' in url:
        scheme = url.split('://')[0].lower()
        if scheme not in ('http', 'https'):
            raise ValidationError(f"Only http and https URLs supported, got: {scheme}")
    
    # Add https:// if missing protocol
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    try:
        parsed = urlparse(url)
    except ValueError as e:
        # Handle port parsing errors specifically
        if "Port out of range" in str(e):
            raise ValidationError(f"Port out of valid range (1-65535)")
        raise ValidationError(f"Could not parse URL: {url}")
    except Exception:
        raise ValidationError(f"Could not parse URL: {url}")
    
    # Basic scheme check (redundant but safe)
    if parsed.scheme not in ('http', 'https'):
        raise ValidationError(f"Only http and https URLs supported, got: {parsed.scheme}")
    
    # Must have hostname
    if not parsed.hostname:
        raise ValidationError(f"URL missing hostname: {url}")
    
    # Validate hostname format (especially for IP addresses)
    if not _is_valid_hostname_or_ip(parsed.hostname):
        raise ValidationError(f"Invalid hostname or IP address: {parsed.hostname}")
    
    # Get port (handle port access errors)
    try:
        if parsed.port is not None:
            port = parsed.port
        else:
            port = 443 if parsed.scheme == 'https' else 80
    except ValueError as e:
        if "Port out of range" in str(e):
            raise ValidationError(f"Port out of valid range (1-65535)")
        raise ValidationError(f"Invalid port in URL: {e}")
    
    # Basic port check
    if not (1 <= port <= 65535):
        raise ValidationError(f"Port {port} out of valid range (1-65535)")
    
    return url, parsed.hostname, port

def validate_port_list(ports: list) -> None:
    """Basic port validation"""
    if not ports:
        raise ValidationError("At least one port required")
    
    for port in ports:
        if not isinstance(port, int) or not (1 <= port <= 65535):
            raise ValidationError(f"Invalid port: {port} (must be 1-65535)")

def _is_valid_hostname_or_ip(hostname: str) -> bool:
    """Validate hostname or IP address format"""
    # Try to parse as IP address first
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        pass
    
    # If it looks like an IP address but failed parsing, it's invalid
    if _looks_like_ip_address(hostname):
        return False
    
    # Validate as domain name
    # Basic domain name validation (RFC 1123 compliant)
    if len(hostname) > 253:
        return False
    
    # Check for valid domain format
    domain_pattern = re.compile(
        r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$'
    )
    
    return bool(domain_pattern.match(hostname))

def _looks_like_ip_address(hostname: str) -> bool:
    """Check if hostname looks like an IP address (but might be malformed)"""
    # Basic check for IP-like patterns
    parts = hostname.split('.')
    
    # IPv4 should have exactly 4 parts
    if 3 <= len(parts) <= 5:
        # Check if all parts are numeric
        try:
            for part in parts:
                int(part)
            return True
        except ValueError:
            pass
    
    return False

def validate_basic_params(threads: int, timeout: int) -> None:
    """Basic parameter validation"""
    if threads <= 0:
        raise ValidationError("Thread count must be positive")
    if threads > 100:  # Reasonable limit
        raise ValidationError("Thread count too high (max 100)")
    
    if timeout <= 0:
        raise ValidationError("Timeout must be positive")
    if timeout > 300:  # 5 minute max
        raise ValidationError("Timeout too high (max 300 seconds)")