import csv
import json
from datetime import datetime, timezone
from io import StringIO
from typing import List, Optional, Dict, Any

from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box
from rich.markup import escape

from .config import ScanConfig
from .models import ScanResult, ValidationFinding
from .models import ValidationSeverity, ScanStatus


class OutputFormatter:
    def __init__(self, console: Optional[Console] = None, results: List[ScanResult] = None,
                 output_format: str = "brief", verbose: bool = False, scan_config: Optional[ScanConfig] = None) -> None:
        self.console = console or Console()
        self.results = results or []
        self.output_format = output_format
        self.verbose = verbose
        self.scan_config = scan_config

    # ============================================================================
    # PUBLIC API
    # ============================================================================

    def print_results(self) -> None:
        if self.output_format == "table":
            self._print_table()
        else:
            formatted = self.format_results()
            # For JSON/CSV/NDJSON/BRIEF output, disable Rich formatting to prevent line wrapping and unwanted colors
            if self.output_format in ["json", "csv", "ndjson", "brief"]:
                print(formatted)
            else:
                self.console.print(formatted)

    def format_results(self) -> str:
        if self.output_format == "table":
            return self._format_table()
        elif self.output_format == "json":
            return self._format_json()
        elif self.output_format == "ndjson":
            return self._format_ndjson()
        elif self.output_format == "csv":
            return self._format_csv()
        elif self.output_format == "brief":
            return self._format_brief()
        else:
            raise ValueError(f"Unsupported output format: {self.output_format}")

    # ============================================================================
    # STATIC UTILITIES
    # ============================================================================

    @staticmethod
    def _json_default(obj: Any) -> str:
        """Custom JSON serializer for non-serializable objects"""
        str_repr = str(obj)
        # Replace problematic characters that break JSON
        return str_repr.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ')

    @staticmethod
    def _get_subjects(result: ScanResult, max_domains: int = 15) -> List[str]:
        """Get deduplicated list of subjects from Subject and SANs"""
        domains = []

        # Add subject if it exists and is not empty
        subject = result.certificate.subject if result.certificate else ""
        if subject and subject.strip():
            domains.append(subject.strip())

        # Add SAN domains, de-duplicating
        san_domains = result.certificate.san_domains if result.certificate else []
        if san_domains:
            for san_domain in san_domains:
                if san_domain.strip() and san_domain.strip() not in domains:
                    domains.append(san_domain.strip())

        if not domains:
            return ["-"]

        # Limit display to max_domains, showing "+ X more" if needed
        if len(domains) > max_domains:
            displayed_domains = domains[:max_domains - 1]  # Leave room for "+ X more"
            remaining_count = len(domains) - (max_domains - 1)
            displayed_domains.append(f"+ {remaining_count} more")
            return displayed_domains

        return domains

    @staticmethod
    def _calculate_severity_counts(result: ScanResult) -> Dict[ValidationSeverity, int]:
        """Calculate severity counts for a single result"""
        if result.summary:
            return {
                ValidationSeverity.CRITICAL: result.summary.critical_count,
                ValidationSeverity.HIGH: result.summary.high_count,
                ValidationSeverity.MEDIUM: result.summary.medium_count,
                ValidationSeverity.LOW: result.summary.low_count,
                ValidationSeverity.INFO: result.summary.info_count,
            }
        else:
            # Fallback: count from findings
            counts = {severity: 0 for severity in ValidationSeverity}
            for finding in result.findings or []:
                if finding.severity in counts:
                    counts[finding.severity] += 1
            return counts

    @staticmethod
    def _format_certificate_data(result: ScanResult) -> Optional[Dict[str, Any]]:
        """Unified certificate data formatting with standardized field names"""
        if not result.certificate:
            return None

        return {
            "subject": result.certificate.subject,
            "issuer": result.certificate.issuer,
            "serial_number": result.certificate.serial_number,
            "signature_algorithm": result.certificate.signature_algorithm,
            "public_key_algorithm": result.certificate.public_key_algorithm,
            "key_size": result.certificate.key_size,
            "san_domains": result.certificate.san_domains,
            "valid": result.certificate.valid,
            "trusted": result.certificate.trusted,
            "issued": result.certificate.issued.isoformat() if result.certificate.issued else None,
            "expires": result.certificate.expires.isoformat() if result.certificate.expires else None,
            "certificate_fingerprint": result.certificate.certificate_fingerprint,
        }

    @staticmethod
    def _format_finding_data(finding: Any) -> Dict[str, Any]:
        """Unified finding data formatting with standardized structure"""
        finding_data = {
            "check_id": finding.check_id,
            "severity": finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
            "title": finding.title,
            "description": finding.description,
            "confidence": finding.confidence.value if hasattr(finding.confidence, 'value') else str(finding.confidence),
        }

        # Add optional fields if present
        if finding.remediation:
            finding_data["remediation"] = finding.remediation
        if finding.evidence:
            finding_data["evidence"] = finding.evidence
        if finding.check_category:
            finding_data["category"] = finding.check_category

        if finding.standard_ref:
            finding_data["standard_ref"] = {
                "standard": finding.standard_ref.standard,
                "title": finding.standard_ref.title,
                "section": finding.standard_ref.section,
                "url": finding.standard_ref.url,
                "severity": finding.standard_ref.severity.value if hasattr(finding.standard_ref.severity,
                                                                           'value') else str(
                    finding.standard_ref.severity)
            }

        return finding_data

    # ============================================================================
    # PRIVATE METHODS
    # ============================================================================

    def _calculate_total_severity_counts(self, results: List[ScanResult]) -> Dict[ValidationSeverity, int]:
        """Calculate total severity counts across all results"""
        totals = {severity: 0 for severity in ValidationSeverity}
        for result in results:
            counts = self._calculate_severity_counts(result)
            for severity, count in counts.items():
                totals[severity] += count
        return totals

    def _format_result_data(self, result: ScanResult) -> Dict[str, Any]:
        """Unified result formatting for JSON and NDJSON output"""
        severity_counts = self._calculate_severity_counts(result)

        return {
            "target": result.target,
            "scan_status": result.status.value,
            "endpoints": [
                {"ip": ip, "port": port} for ip, port in result.endpoints
            ],
            "certificate": self._format_certificate_data(result),
            "findings": [
                self._format_finding_data(f) for f in result.findings
            ],
            "summary": {
                "security_score": result.summary.security_score if result.summary else None,
                "critical_count": severity_counts[ValidationSeverity.CRITICAL],
                "high_count": severity_counts[ValidationSeverity.HIGH],
                "medium_count": severity_counts[ValidationSeverity.MEDIUM],
                "low_count": severity_counts[ValidationSeverity.LOW],
                "info_count": severity_counts[ValidationSeverity.INFO],
            },
            "errors": result.errors,
        }

    def _format_table(self) -> str:
        with StringIO() as buffer:
            console = Console(file=buffer, force_terminal=False)
            self._print_table_to_console(console)
            return buffer.getvalue()

    def _print_table(self):
        self._print_table_to_console(self.console)

    def _print_table_to_console(self, console: Console):
        if not self.results:
            console.print("[yellow]No results to display[/yellow]")
            return

        # Create single consolidated table
        console.print()  # Add spacing
        table = Table(show_lines=True)  # Enable row dividers
        table.add_column("URL", style="cyan", no_wrap=False)
        table.add_column("IP:Port", style="cyan", no_wrap=False)
        table.add_column("Status", justify="center")
        table.add_column("Subject / SAN", style="green")
        table.add_column("Issuer", style="blue")
        table.add_column("Public Key Alg", style="magenta")
        table.add_column("Key Size", justify="right")
        table.add_column("Trusted", justify="center")
        table.add_column("Valid", justify="center")
        table.add_column("Security Score", justify="center")
        table.add_column("Issues", style="red")

        # Process results directly
        for result in self.results:
            # Scan status
            if result.status == ScanStatus.SUCCESS:
                status_text = Text("✓ Success", style="green")
            elif result.status == ScanStatus.FAILED:
                status_text = Text("✗ No Cert Found", style="red")
            elif result.status == ScanStatus.SCANNED:
                status_text = Text("⚠ Scanned only", style="yellow")
            else:
                status_text = Text("⚡ Error", style="dim")

            # Valid status
            is_valid = result.certificate.valid if result.certificate else False
            valid_color = "green" if is_valid else "red"
            valid_symbol = "✓" if is_valid else "✗"
            valid_status = Text(valid_symbol, style=valid_color)

            # Trusted status
            trusted_status = result.certificate.trusted if result.certificate else None
            if trusted_status is None:
                trusted_status = Text("-", style="dim")
            else:
                trusted_color = "green" if trusted_status else "red"
                trusted_symbol = "✓" if trusted_status else "✗"
                trusted_status = Text(trusted_symbol, style=trusted_color)

            # Key size
            key_size_str = ""
            key_size = result.certificate.key_size if result.certificate else None
            if key_size:
                key_size_str = str(key_size)

            # Public key algorithm
            public_key_alg = result.certificate.public_key_algorithm if result.certificate else "Unknown"

            # Format security score with color coding
            security_score = (
                result.summary.security_score if result.summary else 0
            )
            if security_score >= 90:
                score_color = "green"
            elif security_score >= 70:
                score_color = "yellow"
            elif security_score >= 50:
                score_color = "orange1"
            else:
                score_color = "red"

            score_text = Text(f"{security_score}/100", style=score_color)

            # Summarize issues by severity
            issue_summary = self._get_issue_summary(result)

            # Format endpoints - show all endpoints for this certificate
            all_endpoint_strs = []
            for ip, port in result.endpoints:
                all_endpoint_strs.append(f"{ip}:{port}")
            endpoints_str = "\n".join(all_endpoint_strs)

            # Get subject and SAN domains for display
            subject_domains = OutputFormatter._get_subjects(result)
            subject_display = "\n".join(subject_domains)

            # Use the number of lines from endpoints (the primary multi-line column)
            num_lines = len(all_endpoint_strs)

            # Don't pad subject domains - let them display naturally
            # The table will handle the alignment automatically

            # Pad single-line content to match the height
            def pad_content(content, lines_needed):
                if lines_needed <= 1:
                    return content
                # For Rich Text objects, create new Text with padding
                if isinstance(content, Text):
                    padded_text = Text(str(content))
                    padded_text.stylize(content.style)
                    padded_text.append("\n" * (lines_needed - 1))
                    return padded_text
                # For strings, add newlines
                return str(content) + "\n" * (lines_needed - 1)

            # Show URL only in first line, empty for continuation lines
            url_display = result.target + "\n" * (num_lines - 1) if num_lines > 1 else result.target

            table.add_row(
                url_display,
                endpoints_str,
                pad_content(status_text, num_lines),
                subject_display,  # Don't pad subject display - let it be natural
                pad_content(result.certificate.issuer if result.certificate else "-", num_lines),
                pad_content(public_key_alg, num_lines),
                pad_content(key_size_str, num_lines),
                pad_content(trusted_status, num_lines),
                pad_content(valid_status, num_lines),
                pad_content(score_text, num_lines),
                pad_content(issue_summary, num_lines),
            )

        console.print(table)

        # Print detailed findings
        self._print_detailed_findings_to_console(console)

        # Print summary statistics
        self._print_security_summary_to_console(console)

    def _format_json(self) -> str:
        """Format results as JSON with metadata"""
        # Extract metadata from scan config if available
        if self.scan_config and self.scan_config.validation:
            validation_config = self.scan_config.validation
            profile = validation_config.get("profile")
            standards = validation_config.get("standards", [])
            severity_filter = validation_config.get("severity_filter", "MEDIUM")
        else:
            profile = None
            standards = []
            severity_filter = "MEDIUM"
        
        json_data = {
            "metadata": {
                "started_at": datetime.now(timezone.utc).isoformat(),
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "profile": profile,
                "standards": standards,
                "severity_filter": severity_filter,
                "targets_count": len(set(r.target for r in self.results)),
                "certificates_scanned": len(self.results)
            },
            "results": [self._format_result_data(result) for result in self.results]
        }

        return json.dumps(json_data, indent=2, default=OutputFormatter._json_default)

    def _format_ndjson(self) -> str:
        """Format results as newline-delimited JSON (NDJSON) - one line per result"""
        if not self.results:
            return ""

        ndjson_lines = []
        for result in self.results:
            result_data = self._format_result_data(result)
            ndjson_lines.append(json.dumps(result_data, default=OutputFormatter._json_default))

        return '\n'.join(ndjson_lines)

    def _format_csv(self) -> str:
        if not self.results:
            return ""

        output = StringIO()

        fieldnames = [
            "original_url",
            "endpoints",
            "hostname",
            "subject",
            "issuer",
            "valid",
            "trusted",
            "security_score",
            "expires",
            "issued",
            "serial_number",
            "signature_algorithm",
            "public_key_algorithm",
            "key_size",
            "san_domains",
            "certificate_fingerprint",
            "critical_findings",
            "high_findings",
            "medium_findings",
            "low_findings",
            "info_findings",
            "findings_with_references",
            "errors",
        ]

        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()

        for result in self.results:
            # Count findings by severity using shared utility
            severity_counts = self._calculate_severity_counts(result)

            # Create findings with references summary for CSV
            findings_with_refs = []
            for finding in result.findings or []:
                validator_prefix = f"{finding.check_category}:" if finding.check_category else ""
                check_display = f"{validator_prefix}{finding.check_id}"

                if finding.standard_ref:
                    refs_display = ", ".join([
                        f"{ref.title.replace('CA/Browser Forum Baseline Requirements', 'CA/B Forum BR')} §{ref.section}"
                        for ref in [finding.standard_ref]
                    ])
                    severity_str = finding.severity.value if hasattr(finding.severity, 'value') else str(
                        finding.severity)
                    findings_with_refs.append(f"{severity_str}: {finding.title} [{check_display}] ({refs_display})")
                else:
                    severity_str = finding.severity.value if hasattr(finding.severity, 'value') else str(
                        finding.severity)
                    findings_with_refs.append(f"{severity_str}: {finding.title} [{check_display}]")

            findings_with_refs_str = "; ".join(findings_with_refs)

            endpoints_str = "; ".join(
                [f"{ip}:{port}" for ip, port in result.endpoints]
            )

            # Use shared result data formatting and add CSV-specific fields
            result_data = self._format_result_data(result)
            certificate_data = result_data.get("certificate", {})

            row = {
                "original_url": result.original_url,  # Use actual original_url field
                "endpoints": endpoints_str,
                "hostname": result.target,  # Use target consistently
                "subject": certificate_data.get("subject", ""),
                "issuer": certificate_data.get("issuer", ""),
                "valid": certificate_data.get("valid", False),
                "trusted": certificate_data.get("trusted", None),
                "security_score": result_data.get("summary", {}).get("security_score", 0),
                "expires": certificate_data.get("expires", ""),
                "issued": certificate_data.get("issued", ""),
                "serial_number": certificate_data.get("serial_number", ""),
                "signature_algorithm": certificate_data.get("signature_algorithm", ""),
                "public_key_algorithm": certificate_data.get("public_key_algorithm", ""),
                "key_size": certificate_data.get("key_size", ""),
                "san_domains": (
                    "; ".join(certificate_data.get("san_domains", [])) if certificate_data.get("san_domains") else ""
                ),
                "certificate_fingerprint": certificate_data.get("certificate_fingerprint", ""),
                "critical_findings": severity_counts[ValidationSeverity.CRITICAL],
                "high_findings": severity_counts[ValidationSeverity.HIGH],
                "medium_findings": severity_counts[ValidationSeverity.MEDIUM],
                "low_findings": severity_counts[ValidationSeverity.LOW],
                "info_findings": severity_counts[ValidationSeverity.INFO],
                "findings_with_references": findings_with_refs_str,
                "errors": "; ".join(result.errors) if result.errors else "",
            }
            writer.writerow(row)

        return output.getvalue()

    def _format_brief(self) -> str:
        """Format results in brief format with minimal extraneous information"""
        if not self.results:
            return "No findings were found.\n"

        output = StringIO()
        console = Console(file=output, width=120, force_terminal=False, legacy_windows=False, no_color=True)

        # Header with scan completion time and profiles/standards
        self._print_brief_header(console, output)
        
        # Group results and show findings for each target
        targets_with_findings = []
        for result in self.results:
            # Filter findings based on severity filter
            filtered_findings = self._filter_findings_by_severity(result.findings or [])
            if filtered_findings:
                targets_with_findings.append((result, filtered_findings))
        
        if not targets_with_findings:
            console.print()
            console.print(Text("No findings were found matching the severity filter."))
            console.print()
            return output.getvalue()
        
        # Display each target with its findings
        for result, findings in targets_with_findings:
            self._print_brief_target_section(console, output, result, findings)
        
        return output.getvalue()

    def _print_brief_header(self, console: Console, output: StringIO) -> None:
        """Print the header with scan completion time and profiles/standards"""
        # Scan completion time
        if self.scan_config and hasattr(self.scan_config, 'completed_at') and self.scan_config.completed_at:
            completed_time = self.scan_config.completed_at
        else:
            # Fallback to current time if scan completion time not available
            completed_time = datetime.now(timezone.utc)
        
        # Format as human readable: "September 8, 2025 2:05PM EST"
        # Create each component separately to avoid any color interpretation
        month = completed_time.strftime("%B")
        day = completed_time.strftime("%d").lstrip('0')  # Remove leading zero
        year = completed_time.strftime("%Y")
        time_part = completed_time.strftime("%I:%M%p").lstrip('0')  # Remove leading zero from hour
        timezone_part = completed_time.strftime("%Z")
        
        formatted_time = f"{month} {day}, {year} {time_part} {timezone_part}"
        # Write directly to the console's file to bypass all Rich formatting
        output.write(f"\nScan Complete: {formatted_time}\n\n")
        
        # Profiles/Standards used
        if self.scan_config and self.scan_config.validation:
            validation_config = self.scan_config.validation
            profile = validation_config.get("profile")
            standards = validation_config.get("standards", [])
            
            if profile and standards:
                display_items = [profile] + standards
            elif profile:
                display_items = [profile]
            elif standards:
                display_items = standards
            else:
                display_items = ["None specified"]
                
            profiles_str = ", ".join(display_items)
            output.write(f"Profile(s): {profiles_str}\n\n")
        else:
            output.write("Profile(s): None specified\n\n")

    def _print_brief_target_section(self, console: Console, output: StringIO, result: ScanResult, findings: List[ValidationFinding]) -> None:
        """Print a target section with its findings table"""
        # Target info line
        target_url = result.original_url or result.target
        all_ports = sorted(set(port for _, port in result.endpoints))
        ports_str = ", ".join(map(str, all_ports))
        endpoints_count = len(result.endpoints)
        
        # Write target info directly to output to avoid color interpretation
        output.write(f"URL: {target_url}     Ports: {ports_str}      Endpoints: {endpoints_count}\n")
        
        # Create table for findings
        table = Table(
            show_header=True,
            header_style="bold blue",
            border_style="white",
            box=box.ROUNDED  # Use Rich's rounded box style
        )
        
        table.add_column("Check ID", style="cyan", no_wrap=True)
        table.add_column("Title", style="white")
        table.add_column("Severity", justify="center", style="yellow")
        table.add_column("Confidence", justify="center", style="green")
        
        # Add findings to table
        for finding in findings:
            # Color code severity
            severity_style = {
                ValidationSeverity.CRITICAL: "red",
                ValidationSeverity.HIGH: "orange1", 
                ValidationSeverity.MEDIUM: "yellow",
                ValidationSeverity.LOW: "cyan",
                ValidationSeverity.INFO: "dim white"
            }.get(finding.severity, "white")
            
            confidence_style = {
                "HIGH": "green",
                "MEDIUM": "yellow", 
                "LOW": "red"
            }.get(str(finding.confidence), "white")
            
            table.add_row(
                finding.check_id,
                finding.title,
                f"[{severity_style}]{finding.severity.value}[/{severity_style}]",
                f"[{confidence_style}]{finding.confidence.value}[/{confidence_style}]"
            )
        
        console.print(table)
        console.print()  # Add blank line after each target

    def _filter_findings_by_severity(self, findings: List[ValidationFinding]) -> List[ValidationFinding]:
        """Filter findings based on the severity filter from scan config"""
        if not findings or not self.scan_config or not self.scan_config.validation:
            return findings
            
        severity_filter = self.scan_config.validation.get("severity_filter", "MEDIUM")
        
        # Define severity hierarchy (lower index = lower severity)
        severity_order = [
            ValidationSeverity.INFO,
            ValidationSeverity.LOW,
            ValidationSeverity.MEDIUM, 
            ValidationSeverity.HIGH,
            ValidationSeverity.CRITICAL
        ]
        
        try:
            min_severity = ValidationSeverity(severity_filter)
            min_index = severity_order.index(min_severity)
            
            return [
                finding for finding in findings
                if severity_order.index(finding.severity) >= min_index
            ]
        except (ValueError, AttributeError):
            # If severity filter is invalid or finding doesn't have severity, return all findings
            return findings

    def _get_issue_summary(self, result: ScanResult) -> str:
        """Generate a concise summary of security issues"""
        if not result.findings:
            return "None"

        # Use shared severity counting utility
        severity_counts = self._calculate_severity_counts(result)

        summary_parts = []
        if severity_counts[ValidationSeverity.CRITICAL] > 0:
            summary_parts.append(
                f"[red]{severity_counts[ValidationSeverity.CRITICAL]} Critical[/red]"
            )
        if severity_counts[ValidationSeverity.HIGH] > 0:
            summary_parts.append(
                f"[orange1]{severity_counts[ValidationSeverity.HIGH]} High[/orange1]"
            )
        if severity_counts[ValidationSeverity.MEDIUM] > 0:
            summary_parts.append(
                f"[yellow]{severity_counts[ValidationSeverity.MEDIUM]} Med[/yellow]"
            )
        if severity_counts[ValidationSeverity.LOW] > 0:
            summary_parts.append(
                f"[blue]{severity_counts[ValidationSeverity.LOW]} Low[/blue]"
            )

        return ", ".join(summary_parts) if summary_parts else "None"

    def _print_detailed_findings(self):
        """Print detailed security findings for certificates with issues"""
        self._print_detailed_findings_to_console(self.console)

    def _print_detailed_findings_to_console(self, console: Console):
        """Print detailed security findings for certificates with issues to specific console"""
        results_with_findings = [r for r in self.results if r.findings]

        if not results_with_findings:
            return

        console.print("\n[bold]Security Findings[/bold]")

        for result in results_with_findings:
            console.print(f"\n[bold cyan]### {result.target}[/bold cyan]")
            self._print_result_findings_to_console(result, console)

    def _print_result_findings(self, result: ScanResult):
        """Print findings for a single result"""
        self._print_result_findings_to_console(result, self.console)

    def _print_result_findings_to_console(self, result: ScanResult, console: Console):
        """Print findings for a single result to specific console"""
        # Define severity colors and order
        severity_colors = {
            ValidationSeverity.CRITICAL: "red",
            ValidationSeverity.HIGH: "orange1",
            ValidationSeverity.MEDIUM: "yellow",
            ValidationSeverity.LOW: "blue",
            ValidationSeverity.INFO: "dim",
        }

        # Group findings by severity and display in order
        for severity in [
            ValidationSeverity.CRITICAL,
            ValidationSeverity.HIGH,
            ValidationSeverity.MEDIUM,
            ValidationSeverity.LOW,
            ValidationSeverity.INFO,
        ]:
            findings_for_severity = [
                f for f in result.findings if f.severity == severity
            ]

            for finding in findings_for_severity:
                color = severity_colors.get(severity, "white")
                # Create Check ID format: validator:check_id
                check_id_display = f"{finding.check_category}:{finding.check_id}" if finding.check_category else finding.check_id

                # Create references display for compact format (abbreviations only)
                refs_display = ""
                if finding.standard_ref:
                    ref_strs = [
                        f"{ref.title.replace('CA/Browser Forum Baseline Requirements', 'CA/B Forum BR')} §{ref.section}"
                        for ref in [finding.standard_ref]]
                    refs_display = f" [{', '.join(ref_strs)}]"

                console.print(
                    f"  [{color}]{severity.value}[/{color}] {finding.title} ({check_id_display}){refs_display}"
                )
                console.print(f"    {finding.description}")

                # Show evidence in verbose mode
                if self.verbose and finding.evidence:
                    # Format evidence nicely instead of raw JSON
                    console.print(f"    [dim]Evidence:[/dim]")
                    for key, value in finding.evidence.items():
                        console.print(f"    [dim]  {key}: {value}[/dim]")

                # Show detailed references in verbose mode
                if self.verbose and finding.standard_ref:
                    ref = finding.standard_ref
                    console.print(f"    [dim]References:[/dim]")
                    console.print(f"    [dim]  • {ref.title} §{ref.section}[/dim]")
                    console.print(f"    [dim]    {ref.url}[/dim]")

                if finding.remediation:
                    console.print(f"    [dim]→ {finding.remediation}[/dim]")

    def _print_security_summary(self):
        """Print comprehensive security summary with statistics"""
        self._print_security_summary_to_console(self.console)

    def _print_security_summary_to_console(self, console: Console):
        """Print comprehensive security summary with statistics to specific console"""
        total_count = len(self.results)
        valid_count = sum(1 for r in self.results if r.certificate and r.certificate.valid)
        invalid_count = total_count - valid_count

        # Calculate security score statistics
        scores = [r.summary.security_score for r in self.results if r.summary and r.summary.security_score is not None]
        avg_score = sum(scores) / len(scores) if scores else 0

        # Count findings by severity
        severity_totals = {
            ValidationSeverity.CRITICAL: 0,
            ValidationSeverity.HIGH: 0,
            ValidationSeverity.MEDIUM: 0,
            ValidationSeverity.LOW: 0,
            ValidationSeverity.INFO: 0,
        }

        for result in self.results:
            if result.summary:
                severity_totals[ValidationSeverity.CRITICAL] += result.summary.critical_count
                severity_totals[ValidationSeverity.HIGH] += result.summary.high_count
                severity_totals[ValidationSeverity.MEDIUM] += result.summary.medium_count
                severity_totals[ValidationSeverity.LOW] += result.summary.low_count
                severity_totals[ValidationSeverity.INFO] += result.summary.info_count
            else:
                # Fallback for ScanResult without summary
                for finding in result.findings or []:
                    if finding.severity in severity_totals:
                        severity_totals[finding.severity] += 1

        # Create summary panels
        cert_panel = Panel(
            f"Total: {total_count}\nValid: [green]{valid_count}[/green]\nInvalid: [red]{invalid_count}[/red]",
            title="Certificates",
            expand=False,
        )

        score_color = (
            "green" if avg_score >= 90 else "yellow" if avg_score >= 70 else "red"
        )
        score_panel = Panel(
            f"Average: [{score_color}]{avg_score:.1f}/100[/{score_color}]",
            title="Security Score",
            expand=False,
        )

        findings_text = "\n".join(
            [
                f"[red]Critical: {severity_totals[ValidationSeverity.CRITICAL]}[/red]",
                f"[orange1]High: {severity_totals[ValidationSeverity.HIGH]}[/orange1]",
                f"[yellow]Medium: {severity_totals[ValidationSeverity.MEDIUM]}[/yellow]",
                f"[blue]Low: {severity_totals[ValidationSeverity.LOW]}[/blue]",
                f"[dim]Info: {severity_totals[ValidationSeverity.INFO]}[/dim]",
            ]
        )

        findings_panel = Panel(findings_text, title="Security Findings", expand=False)

        console.print("\n[bold]Security Assessment Summary[/bold]")
        console.print(Columns([cert_panel, score_panel, findings_panel]))
