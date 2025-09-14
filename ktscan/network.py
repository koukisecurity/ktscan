import ipaddress
import logging
import socket
from typing import List, Tuple, Set, Dict, Optional
from urllib.parse import urlparse

import dns.resolver


class NetworkResolver:
    def __init__(self, timeout: int = 5, thread_manager=None):
        self.timeout = timeout
        self.thread_manager = thread_manager
        self.logger = logging.getLogger(__name__)
        self.ipv6_supported = self._test_ipv6_support()
        if not self.ipv6_supported:
            self.logger.debug("IPv6 not supported on this system")

    def resolve_url_to_targets(
        self, url: str, ports: List[int]
    ) -> List[Tuple[str, int]]:
        parsed = urlparse(url)
        hostname = parsed.hostname or parsed.netloc

        if not hostname:
            raise ValueError(f"Cannot extract hostname from URL: {url}")

        ips = self._resolve_hostname_to_ips(hostname)
        targets = []

        for ip in ips:
            for port in ports:
                targets.append((ip, port))

        self.logger.info(
            f"Resolved {hostname} to {len(ips)} IPs, generating {len(targets)} targets"
        )
        return targets

    def _resolve_hostname_to_ips(self, hostname: str) -> Set[str]:
        ips = set()

        try:
            if self._is_ip_address(hostname):
                ips.add(hostname)
                return ips
        except ValueError:
            pass

        try:
            answers = dns.resolver.resolve(hostname, "A")
            for answer in answers:
                ips.add(str(answer))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            self.logger.warning(f"Failed to resolve A record for {hostname}")

        try:
            answers = dns.resolver.resolve(hostname, "AAAA")
            for answer in answers:
                ips.add(str(answer))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            self.logger.debug(f"No AAAA record for {hostname}")

        if not ips:
            try:
                result = socket.getaddrinfo(
                    hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM
                )
                for family, type_, proto, canonname, sockaddr in result:
                    ip = sockaddr[0]
                    if self._is_ip_address(ip):
                        ips.add(ip)
            except socket.gaierror as e:
                self.logger.error(f"Failed to resolve {hostname}: {e}")
                raise ValueError(f"Could not resolve hostname: {hostname}")

        return ips

    def _is_ip_address(self, address: str) -> bool:
        try:
            ipaddress.ip_address(address)
            return True
        except ValueError:
            return False

    def _is_ipv6_address(self, address: str) -> bool:
        try:
            ip = ipaddress.ip_address(address)
            return isinstance(ip, ipaddress.IPv6Address)
        except ValueError:
            return False

    def _test_ipv6_support(self) -> bool:
        try:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            sock.close()
            return True
        except (socket.error, OSError):
            return False

    def is_port_open(self, ip: str, port: int) -> Tuple[bool, str]:
        is_ipv6 = self._is_ipv6_address(ip)

        if is_ipv6:
            if not self.ipv6_supported:
                return False, "IPv6 not supported"

        try:
            addr_info = socket.getaddrinfo(
                ip, port, socket.AF_UNSPEC, socket.SOCK_STREAM
            )
            if not addr_info:
                return False, "No address info available"

            family, socktype, proto, canonname, sockaddr = addr_info[0]
            sock = socket.socket(family, socktype)
            sock.settimeout(self.timeout)

            try:
                result = sock.connect_ex(sockaddr)
                if result == 0:
                    return True, "Connected"
                else:
                    # Check if this is specifically an IPv6 connectivity issue
                    if is_ipv6 and result in [
                        101,
                        111,
                    ]:  # Network unreachable, Connection refused
                        return False, "IPv6 connectivity issue"
                    return False, f"Connection failed (errno {result})"
            finally:
                sock.close()

        except (socket.error, OSError) as e:
            error_msg = str(e)
            if "Address family" in error_msg and "not supported" in error_msg:
                return False, "IPv6 not supported"
            # Check for IPv6-specific socket creation errors
            if is_ipv6 and (
                "Network is unreachable" in error_msg
                or "Cannot assign requested address" in error_msg
            ):
                return False, "IPv6 connectivity issue"
            return False, error_msg

    def filter_open_ports(
        self, targets: List[Tuple[str, int]]
    ) -> List[Tuple[str, int]]:
        open_targets = []
        ipv6_skipped = 0
        ipv6_targets = []

        for ip, port in targets:
            is_open, reason = self.is_port_open(ip, port)

            if is_open:
                open_targets.append((ip, port))
                self.logger.debug(f"Port {port} is open on {ip}")
            elif reason in ["IPv6 not supported", "IPv6 connectivity issue"]:
                ipv6_skipped += 1
                ipv6_targets.append((ip, port))
                self.logger.debug(f"Skipping IPv6 target {ip}:{port} - {reason}")
            else:
                self.logger.debug(f"Port {port} is closed on {ip} - {reason}")

        if ipv6_skipped > 0:
            if self.ipv6_supported:
                self.logger.info(
                    f"Unable to scan {ipv6_skipped} IPv6 targets, skipping (IPv6 connectivity issues)"
                )
            else:
                self.logger.info(
                    f"Unable to scan {ipv6_skipped} IPv6 targets, skipping (IPv6 not supported on local machine)"
                )

        return open_targets

    def resolve_multiple_hostnames_parallel(
        self, hostnames: List[str]
    ) -> Dict[str, Set[str]]:
        """Resolve multiple hostnames using ThreadManager for parallel processing"""
        if not self.thread_manager:
            # Fallback to sequential processing
            return {
                hostname: self._resolve_hostname_to_ips(hostname)
                for hostname in hostnames
            }

        def resolve_single(hostname: str) -> Tuple[str, Set[str]]:
            try:
                ips = self._resolve_hostname_to_ips(hostname)
                return hostname, ips
            except Exception as e:
                self.logger.error(f"DNS resolution failed for {hostname}: {e}")
                return hostname, set()

        # Use ThreadManager with limited concurrency for DNS (reasonable for DNS servers)
        max_dns_concurrent = min(len(hostnames), 8)
        results = self.thread_manager.map_parallel(
            resolve_single, hostnames, max_concurrent=max_dns_concurrent
        )

        return {hostname: ips for hostname, ips in results if hostname and ips}

    def filter_open_ports_parallel(
        self, targets: List[Tuple[str, int]]
    ) -> List[Tuple[str, int]]:
        """Check port connectivity using ThreadManager for parallel processing"""
        if not self.thread_manager:
            return self.filter_open_ports(targets)  # Fallback to sequential

        def check_single_port(
            target: Tuple[str, int],
        ) -> Optional[Tuple[str, int, bool, str]]:
            ip, port = target
            try:
                is_open, reason = self.is_port_open(ip, port)
                return ip, port, is_open, reason
            except Exception as e:
                self.logger.error(f"Port check failed for {ip}:{port}: {e}")
                return ip, port, False, str(e)

        # Use more threads for port scanning as it's mostly waiting
        max_port_concurrent = min(len(targets), self.thread_manager.max_workers)
        results = self.thread_manager.map_parallel(
            check_single_port, targets, max_concurrent=max_port_concurrent
        )

        # Process results
        open_targets = []
        ipv6_skipped = 0

        for result in results:
            if result is None:
                continue
            ip, port, is_open, reason = result

            if is_open:
                open_targets.append((ip, port))
                self.logger.debug(f"Port {port} is open on {ip}")
            elif reason in ["IPv6 not supported", "IPv6 connectivity issue"]:
                ipv6_skipped += 1
                self.logger.debug(f"Skipping IPv6 target {ip}:{port} - {reason}")
            else:
                self.logger.debug(f"Port {port} is closed on {ip} - {reason}")

        if ipv6_skipped > 0:
            if self.ipv6_supported:
                self.logger.info(
                    f"Unable to scan {ipv6_skipped} IPv6 targets, skipping (IPv6 connectivity issues)"
                )
            else:
                self.logger.info(
                    f"Unable to scan {ipv6_skipped} IPv6 targets, skipping (IPv6 not supported on local machine)"
                )

        return open_targets
