import logging
import threading
from typing import List, Optional, Any

from .cert_analyzer import CertAnalyzer
from .config import ScanConfig
from .models import ScanResult, ScanStatus
from .network import NetworkResolver
from .progress import ThreeStageProgress
from .threading_manager import ThreadManager


class KTScan:
    def __init__(self, config: ScanConfig, thread_manager: ThreadManager, console: Optional[Any] = None) -> None:
        self.config = config
        self.console = console
        self.thread_manager = thread_manager
        self.network = NetworkResolver(
            timeout=config.timeout, thread_manager=thread_manager
        )
        self.analyzer = CertAnalyzer(
            timeout=config.timeout,
            validation_config=config.validation,
            thread_manager=thread_manager,
        )
        self.logger = logging.getLogger(__name__)

        self._setup_logging()

    def _setup_logging(self):
        # For machine-readable formats, suppress all logging to stdout/stderr unless it's an error
        if self.config.output_format in ["json", "csv", "ndjson"]:
            log_level = logging.ERROR  # Only show errors for JSON/CSV/NDJSON output
        else:
            log_level = logging.DEBUG if self.config.verbose else logging.WARNING

        logging.basicConfig(
            level=log_level,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        )

    def scan(self) -> List[ScanResult]:
        self.logger.info(
            f"Starting certificate scan for {len(self.config.targets)} targets"
        )

        try:
            if not self.config.targets:
                self.logger.warning("No targets found to scan")
                return []

            # Determine if we should show progress
            show_progress = (
                not self.config.verbose
                and self.config.output_format not in ["json", "csv", "ndjson"]
                and self.console is not None
            )

            with ThreeStageProgress(self.console, show_progress) as progress:
                return self._scan_with_progress(progress)

        except Exception as e:
            self.logger.error(f"Scan failed: {e}")
            raise

    def _scan_with_progress(self, progress: ThreeStageProgress) -> List[ScanResult]:
        """Execute scan with three-stage progress tracking using ThreadManager for parallel operations"""

        # STAGE 1: Parallel DNS Resolution and Port Scanning
        self.logger.info(
            f"Starting DNS resolution for {len(self.config.targets)} targets"
        )

        # Use parallel processing for DNS resolution
        all_network_targets = self._stage1_parallel_dns_and_ports(progress)

        # STAGE 2: Download certificates with ThreadManager
        self.logger.info(
            f"Downloading certificates from {len(all_network_targets)} endpoints"
        )
        raw_results = self._stage2_parallel_certificate_download(
            all_network_targets, progress
        )

        # Deduplicate certificates
        deduplicated_results = self._deduplicate_certificates(raw_results)

        # Complete stage 2 and start stage 3
        progress.complete_stage2_start_stage3(len(deduplicated_results))

        # STAGE 3: Validate certificates
        self.logger.info(f"Validating {len(deduplicated_results)} unique certificates")
        validated_results = self._validate_certificates_with_progress(
            deduplicated_results, progress
        )

        progress.complete_stage3()

        self.logger.info(
            f"Scan completed. Found {len(validated_results)} results across {len(self.config.targets)} targets"
        )
        
        # Results are already ScanResult format
        scan_results = validated_results
        return scan_results


    def _validate_certificates_with_progress(
        self, deduplicated_results: List[ScanResult], progress: ThreeStageProgress
    ) -> List[ScanResult]:
        """Validate certificates with progress tracking - now uses parallel processing"""
        return self._validate_certificates_parallel(deduplicated_results, progress)

    def _validate_single_certificate_with_progress(
        self, result: ScanResult, completed_counter: threading.Lock, 
        completed_count: List[int], progress: ThreeStageProgress
    ) -> ScanResult:
        """Validate a single certificate and update progress"""
        try:
            # Only validate certificates that were successfully scanned
            if result.status == ScanStatus.SCANNED and result.certificate:
                hostname = result.target
                validated_result = self.analyzer.validate_scan_result(result, hostname)
                validated_result.status = ScanStatus.SUCCESS
            else:
                # Keep original result for failed scans or missing certificates
                validated_result = result

            # Thread-safe progress update
            with completed_counter:
                completed_count[0] += 1
                progress.update_stage3(completed_count[0])

            return validated_result
            
        except Exception as e:
            result.errors.append(f"Certificate validation failed: {str(e)}")
            result.status = ScanStatus.FAILED
            if result.certificate:
                result.certificate.valid = False
            self.logger.error(
                f"Validation error for certificate {result.certificate.certificate_fingerprint[:16] if result.certificate else 'unknown'}...: {e}"
            )

            # Still update progress on error
            with completed_counter:
                completed_count[0] += 1
                progress.update_stage3(completed_count[0])

            return result

    def _calculate_validation_concurrency(self, num_certificates: int) -> int:
        """Calculate optimal concurrency for certificate validation.
        
        Use strategic concurrency: Reserve some threads for validator sub-operations (OCSP, AIA, etc.)
        This prevents thread pool saturation when validators spawn their own parallel operations.
        """
        if num_certificates == 1:
            # Single certificate: use full thread pool for sub-operations
            return 1
        else:
            # Multiple certificates: balance main validation vs sub-operations
            # Use at most half the threads for main validation, reserve rest for sub-operations
            return min(num_certificates, max(2, self.thread_manager.max_workers // 2))

    def _validate_certificates_parallel(
        self, deduplicated_results: List[ScanResult], progress: ThreeStageProgress
    ) -> List[ScanResult]:
        """Parallel certificate validation using ThreadManager"""
        if not deduplicated_results:
            return []

        # Thread-safe counter for progress tracking
        completed_counter = threading.Lock()
        completed_count = [0]

        def validate_with_progress(result: ScanResult) -> ScanResult:
            return self._validate_single_certificate_with_progress(
                result, completed_counter, completed_count, progress
            )

        # Calculate optimal concurrency level for validation
        max_validation_concurrent = self._calculate_validation_concurrency(len(deduplicated_results))
        validated_results = self.thread_manager.map_parallel(
            validate_with_progress,
            deduplicated_results,
            max_concurrent=max_validation_concurrent,
        )

        self.logger.debug(
            f"Validated {len(validated_results)} certificates using {max_validation_concurrent} concurrent validation threads"
        )

        # Filter out None results (shouldn't happen, but be safe)
        return [r for r in validated_results if r is not None]


    def _resolve_network_targets(self, scan_target) -> List[tuple]:
        """Resolve a ScanTarget into network targets (IP, port) tuples"""
        self.logger.info(f"Resolving {scan_target.hostname} to IP addresses")

        try:
            # Create a fake URL for the network resolver (it needs a full URL)
            url_for_resolver = f"https://{scan_target.hostname}"
            network_targets = self.network.resolve_url_to_targets(
                url_for_resolver, scan_target.ports
            )

            if not network_targets:
                self.logger.warning(
                    f"No IP addresses resolved for {scan_target.hostname}"
                )
                return []

            self.logger.info(
                f"Resolved {scan_target.hostname} to {len(network_targets)} targets"
            )

            if self.config.verbose:
                for ip, port in network_targets:
                    self.logger.debug(f"Target: {ip}:{port}")

            open_targets = self.network.filter_open_ports(network_targets)

            if not open_targets:
                self.logger.warning(f"No open ports found for {scan_target.hostname}")
                return []

            self.logger.info(
                f"Found {len(open_targets)} open ports for {scan_target.hostname}"
            )
            return open_targets

        except Exception as e:
            self.logger.error(
                f"Target resolution failed for {scan_target.hostname}: {e}"
            )
            raise



    def _deduplicate_certificates(self, results: List[ScanResult]) -> List[ScanResult]:
        """Deduplicate certificates based on fingerprint AND original URL, consolidating endpoints"""
        if not results:
            return results

        # Group results by composite key: (certificate_fingerprint, original_url)
        # This ensures we only deduplicate certificates from the same original URL
        composite_key_map = {}

        for result in results:
            # Skip deduplication for results without certificates (failed scans)
            if not result.certificate or not result.certificate.certificate_fingerprint:
                # Add failed scans directly to the result set with a unique key
                unique_key = f"failed|{result.primary_ip}:{result.primary_port}|{getattr(result, 'original_url', '')}"
                composite_key_map[unique_key] = result
                continue

            # Create composite key using both fingerprint and original URL
            fingerprint = result.certificate.certificate_fingerprint
            original_url = getattr(result, 'original_url', '')
            composite_key = f"{fingerprint}|{original_url}"

            if composite_key in composite_key_map:
                # Same certificate from same URL found - add this endpoint to existing result
                existing_result = composite_key_map[composite_key]
                # Add all endpoints from this result to the existing one
                for ip, port in result.endpoints:
                    existing_result.add_endpoint(ip, port)

                # Merge any errors from this endpoint
                if result.errors:
                    existing_result.errors.extend(result.errors)

                self.logger.debug(
                    f"Deduplicated certificate {fingerprint[:16]}... from {original_url} found on {result.primary_ip}:{result.primary_port}"
                )
            else:
                # New certificate or same certificate from different URL
                composite_key_map[composite_key] = result

        deduplicated_count = len(results) - len(composite_key_map)
        if deduplicated_count > 0:
            self.logger.info(
                f"Deduplicated {deduplicated_count} certificate-URL combinations ({len(composite_key_map)} unique certificate-URL pairs found)"
            )

        return list(composite_key_map.values())

    def _validate_deduplicated_certificates(
        self, results: List[ScanResult], hostname: str
    ) -> List[ScanResult]:
        """Perform validation on deduplicated certificates"""
        validated_results = []

        for result in results:
            # Only validate certificates that were successfully scanned
            if result.status == ScanStatus.SCANNED and result.certificate:
                try:
                    # Perform comprehensive validation
                    validated_result = self.analyzer.validate_scan_result(result, hostname)
                    validated_result.status = ScanStatus.SUCCESS
                    validated_results.append(validated_result)
                except Exception as e:
                    result.errors.append(f"Certificate validation failed: {str(e)}")
                    result.status = ScanStatus.FAILED
                    if result.certificate:
                        result.certificate.valid = False
                    validated_results.append(result)
                    self.logger.error(
                        f"Validation error for certificate {result.certificate.certificate_fingerprint[:16] if result.certificate else 'unknown'}...: {e}"
                    )
            else:
                # Keep failed scans and missing certificates as-is
                validated_results.append(result)

        return validated_results



    def _stage1_parallel_dns_and_ports(
        self, progress: ThreeStageProgress
    ) -> List[tuple]:
        """Stage 1: Parallel DNS resolution and port scanning using ThreadManager"""

        # First, resolve all hostnames in parallel
        hostnames = [target.hostname for target in self.config.targets]
        hostname_results = self.network.resolve_multiple_hostnames_parallel(hostnames)

        # Build potential targets from DNS results
        all_potential_targets = []
        for scan_target in self.config.targets:
            ips = hostname_results.get(scan_target.hostname, set())
            for ip in ips:
                for port in scan_target.ports:
                    all_potential_targets.append(
                        (ip, port, scan_target.original_url, scan_target.hostname)
                    )

        progress.start_stage1(len(all_potential_targets))

        # Use thread-safe counter for progress tracking
        completed_counter = threading.Lock()
        completed_count = [0]  # Use list for mutable reference

        def check_port_with_progress(target_data):
            ip, port, original_url, hostname = target_data
            is_open, reason = self.network.is_port_open(ip, port)

            # Thread-safe progress update
            with completed_counter:
                completed_count[0] += 1
                progress.update_stage1(completed_count[0])

            if self.config.verbose:
                status = "open" if is_open else "closed"
                self.logger.debug(f"Target {ip}:{port} - {status}")

            if is_open:
                return (ip, port, original_url, hostname)
            return None

        # Check all ports in parallel
        results = self.thread_manager.map_parallel(
            check_port_with_progress,
            all_potential_targets,
            max_concurrent=self.thread_manager.max_workers,
        )

        # Filter out None results (closed ports)
        all_network_targets = [r for r in results if r is not None]

        progress.complete_stage1_start_stage2(len(all_network_targets))
        return all_network_targets


    def _stage2_parallel_certificate_download(
        self, all_network_targets: List[tuple], progress: ThreeStageProgress
    ) -> List[ScanResult]:
        """Stage 2: Parallel certificate download using ThreadManager"""

        # Use thread-safe counter for progress tracking
        completed_counter = threading.Lock()
        completed_count = [0]  # Use list for mutable reference

        def download_with_progress(target_data):
            ip, port, original_url, hostname = target_data
            try:
                # Use the analyzer's scan method to parse certificates
                result = self.analyzer.scan_certificate(ip, port, hostname)
                result.original_url = original_url

                # Thread-safe progress update
                with completed_counter:
                    completed_count[0] += 1
                    progress.update_stage2(completed_count[0])

                return result
            except Exception as e:
                self.logger.error(f"Certificate download failed for {ip}:{port}: {e}")

                # Still update progress even on failure
                with completed_counter:
                    completed_count[0] += 1
                    progress.update_stage2(completed_count[0])

                return None

        # Download all certificates in parallel using full thread pool
        results = self.thread_manager.map_parallel(
            download_with_progress,
            all_network_targets,
            max_concurrent=self.thread_manager.max_workers,
        )

        # Filter out None results
        raw_results = [r for r in results if r is not None]
        return raw_results

