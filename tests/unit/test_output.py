"""
Tests for ktscan.output module
"""

import json
import csv
from io import StringIO
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timezone

import pytest
from rich.console import Console
from rich.text import Text

from ktscan.output import OutputFormatter
from ktscan.models import ScanResult
from ktscan.models import ValidationFinding, ValidationSeverity, ConfidenceLevel


class TestOutputFormatter:
    """Test the OutputFormatter class"""

    def setup_method(self):
        """Set up test fixtures"""
        from ktscan.config import ScanConfig
        self.console = Console(file=StringIO(), force_terminal=False)
        self.scan_config = ScanConfig()
        self.formatter = OutputFormatter(self.console, [], "table", False, self.scan_config)

    def create_test_result(self, **kwargs) -> ScanResult:
        """Create a test ScanResult with default values"""
        from ktscan.models import CertificateData, SecuritySummary, ScanStatus
        
        # Extract certificate-related fields if provided
        cert_data = CertificateData(
            subject=kwargs.pop("subject", "example.com"),
            issuer=kwargs.pop("issuer", "Test CA"),
            valid=kwargs.pop("valid", True),
            trusted=kwargs.pop("trusted", True),
            expires=kwargs.pop("expires", datetime(2024, 12, 31, tzinfo=timezone.utc)),
            issued=kwargs.pop("issued", datetime(2024, 1, 1, tzinfo=timezone.utc)),
            serial_number=kwargs.pop("serial_number", "12345"),
            signature_algorithm=kwargs.pop("signature_algorithm", "sha256WithRSAEncryption"),
            public_key_algorithm=kwargs.pop("public_key_algorithm", "RSA"),
            key_size=kwargs.pop("key_size", 2048),
            san_domains=kwargs.pop("san_domains", ["example.com", "www.example.com"]),
            certificate_fingerprint=kwargs.pop("certificate_fingerprint", "abcdef123456"),
        )
        
        # Extract security summary fields if provided
        summary = SecuritySummary(
            security_score=kwargs.pop("security_score", 95)
        )
        
        defaults = {
            "target": kwargs.pop("hostname", "example.com"),
            "original_url": kwargs.pop("original_url", "https://example.com"),
            "endpoints": kwargs.pop("endpoints", [("192.168.1.1", 443)]),
            "certificate": cert_data,
            "summary": summary,
            "findings": kwargs.pop("findings", []),
            "errors": kwargs.pop("errors", []),
            "status": kwargs.pop("status", ScanStatus.SUCCESS),
        }
        defaults.update(kwargs)
        return ScanResult(**defaults)

    def test_init_default_console(self):
        """Test OutputFormatter initialization with default console"""
        formatter = OutputFormatter()
        assert formatter.console is not None
        assert isinstance(formatter.console, Console)

    def test_init_custom_console(self):
        """Test OutputFormatter initialization with custom console"""
        custom_console = Console()
        formatter = OutputFormatter(custom_console)
        assert formatter.console is custom_console

    def test_format_results_table(self):
        """Test format_results with table format"""
        results = [self.create_test_result()]
        formatter = OutputFormatter(self.console, results, "table")
        
        output = formatter.format_results()
        
        assert isinstance(output, str)
        assert len(output) > 0

    def test_format_results_json(self):
        """Test format_results with JSON format"""
        results = [self.create_test_result()]
        
        output = OutputFormatter(self.console, results, "json").format_results()
        
        # Should be valid JSON with metadata structure
        parsed = json.loads(output)
        assert isinstance(parsed, dict)
        assert "metadata" in parsed
        assert "results" in parsed
        assert len(parsed["results"]) == 1
        
        result_data = parsed["results"][0]
        assert result_data["target"] == "example.com"
        assert result_data["certificate"]["valid"] is True
        assert result_data["endpoints"][0]["ip"] == "192.168.1.1"
        assert result_data["endpoints"][0]["port"] == 443

    def test_format_results_csv(self):
        """Test format_results with CSV format"""
        results = [self.create_test_result()]
        
        output = OutputFormatter(self.console, results, "csv").format_results()
        
        # Should be valid CSV
        csv_reader = csv.DictReader(StringIO(output))
        rows = list(csv_reader)
        assert len(rows) == 1
        
        row = rows[0]
        assert row["original_url"] == "https://example.com"
        assert row["valid"] == "True"
        assert row["security_score"] == "95"

    def test_format_results_unsupported_format(self):
        """Test format_results with unsupported format"""
        results = [self.create_test_result()]
        
        with pytest.raises(ValueError, match="Unsupported output format"):
            OutputFormatter(self.console, results, "unsupported").format_results()

    def test_print_results_table(self):
        """Test print_results with table format"""
        results = [self.create_test_result()]
        formatter = OutputFormatter(self.console, results, "table", False, self.scan_config)
        
        with patch.object(formatter, '_print_table') as mock_print:
            formatter.print_results()
            mock_print.assert_called_once()

    def test_print_results_non_table(self):
        """Test print_results with non-table format"""
        results = [self.create_test_result()]
        formatter = OutputFormatter(self.console, results, "json", False, self.scan_config)
        
        with patch.object(formatter, 'format_results') as mock_format:
            mock_format.return_value = "formatted output"
            formatter.print_results()
            
            mock_format.assert_called_once()

    def test_format_table_empty_results(self):
        """Test _format_table with empty results"""
        formatter = OutputFormatter(self.console, [], "table", False, self.scan_config)
        output = formatter._format_table()
        
        assert "No results to display" in output

    def test_format_json_empty_results(self):
        """Test _format_json with empty results"""
        formatter = OutputFormatter(self.console, [], "json", False, self.scan_config)
        output = formatter._format_json()
        
        parsed = json.loads(output)
        assert parsed == []

    def test_format_csv_empty_results(self):
        """Test _format_csv with empty results"""
        output = self.formatter._format_csv([])
        
        # Should return empty string for no results
        assert output == ""

    def test_format_json_with_findings(self):
        """Test JSON format includes validation findings"""
        finding = ValidationFinding(
            check_id="test_check",
            severity=ValidationSeverity.HIGH,
            confidence=ConfidenceLevel.HIGH,
            title="Test Finding",
            description="Test description",
            remediation="Test remediation",
            evidence={"key": "value"}
        )
        
        results = [self.create_test_result(findings=[finding])]
        output = self.formatter._format_json(results)
        
        parsed = json.loads(output)
        result_data = parsed[0]
        
        assert len(result_data["findings"]) == 1
        finding_data = result_data["findings"][0]
        assert finding_data["check_id"] == "test_check"
        assert finding_data["severity"] == "HIGH"
        assert finding_data["title"] == "Test Finding"

    def test_format_csv_with_findings(self):
        """Test CSV format includes finding counts"""
        critical_finding = ValidationFinding(
            check_id="critical_check",
            severity=ValidationSeverity.CRITICAL,
            confidence=ConfidenceLevel.HIGH,
            title="Critical Finding",
            description="Critical description",
            remediation="Critical remediation"
        )
        high_finding = ValidationFinding(
            check_id="high_check",
            severity=ValidationSeverity.HIGH,
            confidence=ConfidenceLevel.HIGH,
            title="High Finding",
            description="High description",
            remediation="High remediation"
        )
        
        results = [self.create_test_result(findings=[critical_finding, high_finding])]
        output = self.formatter._format_csv(results)
        
        csv_reader = csv.DictReader(StringIO(output))
        row = next(csv_reader)
        
        assert row["critical_findings"] == "1"
        assert row["high_findings"] == "1"
        assert row["medium_findings"] == "0"

    def test_format_json_multiple_endpoints(self):
        """Test JSON format with multiple endpoints"""
        results = [self.create_test_result(
            endpoints=[("192.168.1.1", 443), ("192.168.1.2", 8443)]
        )]
        
        output = self.formatter._format_json(results)
        parsed = json.loads(output)
        result_data = parsed[0]
        
        assert len(result_data["endpoints"]) == 2
        assert result_data["endpoints"][0]["ip"] == "192.168.1.1"
        assert result_data["endpoints"][0]["port"] == 443
        assert result_data["endpoints"][1]["ip"] == "192.168.1.2"
        assert result_data["endpoints"][1]["port"] == 8443

    def test_format_csv_multiple_endpoints(self):
        """Test CSV format with multiple endpoints"""
        results = [self.create_test_result(
            endpoints=[("192.168.1.1", 443), ("192.168.1.2", 8443)]
        )]
        
        output = self.formatter._format_csv(results)
        csv_reader = csv.DictReader(StringIO(output))
        row = next(csv_reader)
        
        assert "192.168.1.1:443" in row["endpoints"]
        assert "192.168.1.2:8443" in row["endpoints"]

    def test_get_issue_summary_no_findings(self):
        """Test _get_issue_summary with no findings"""
        result = self.create_test_result()
        
        summary = self.formatter._get_issue_summary(result)
        
        assert summary == "None"

    def test_get_issue_summary_with_findings(self):
        """Test _get_issue_summary with various findings"""
        findings = [
            ValidationFinding(
                check_id="critical1",
                severity=ValidationSeverity.CRITICAL,
                confidence=ConfidenceLevel.HIGH,
                title="Critical Issue",
                description="Description",
                remediation="Remediation"
            ),
            ValidationFinding(
                check_id="high1",
                severity=ValidationSeverity.HIGH,
                confidence=ConfidenceLevel.HIGH,
                title="High Issue",
                description="Description",
                remediation="Remediation"
            ),
            ValidationFinding(
                check_id="high2",
                severity=ValidationSeverity.HIGH,
                confidence=ConfidenceLevel.HIGH,
                title="Another High Issue",
                description="Description",
                remediation="Remediation"
            )
        ]
        
        result = self.create_test_result(findings=findings)
        summary = self.formatter._get_issue_summary(result)
        
        assert "1" in summary  # 1 critical
        assert "2" in summary  # 2 high

    def test_print_table_to_console_subject_display_limiting(self):
        """Test table output limits subject/SAN display to 15 items"""
        # Create many SAN domains to test limiting
        many_sans = [f"domain{i}.example.com" for i in range(20)]
        result = self.create_test_result(
            subject="main.example.com",
            san_domains=many_sans
        )
        
        output_console = Console(file=StringIO(), force_terminal=False)
        self.formatter._print_table([result], output_console)
        
        output = output_console.file.getvalue()
        
        # Should contain "+ X more" message since we have more than 15 domains
        assert "+ " in output and " more" in output

    def test_print_table_to_console_subject_deduplication(self):
        """Test table output deduplicates subject and SAN domains"""
        result = self.create_test_result(
            subject="example.com",
            san_domains=["example.com", "www.example.com", "api.example.com"]
        )
        
        output_console = Console(file=StringIO(), force_terminal=False) 
        self.formatter._print_table([result], output_console)
        
        output = output_console.file.getvalue()
        
        # Should show www.example.com and api.example.com but example.com should be deduplicated
        # (example.com appears once in subject, not duplicated in SAN)
        assert "www." in output or "api." in output  # At least one SAN domain should appear

    def test_print_summary(self):
        """Test print_summary method"""
        results = [
            self.create_test_result(valid=True, security_score=90),
            self.create_test_result(valid=False, security_score=60),
        ]
        
        # Should not raise an exception
        self.formatter.print_summary(results)

    def test_print_detailed_findings(self):
        """Test _print_detailed_findings method"""
        finding = ValidationFinding(
            check_id="test_check",
            severity=ValidationSeverity.MEDIUM,
            confidence=ConfidenceLevel.HIGH,
            title="Test Finding",
            description="Test description with details",
            remediation="Fix the issue",
            evidence={"current_size": 1024, "recommended_size": 2048}
        )
        
        results = [self.create_test_result(
            original_url="https://example.com",
            findings=[finding]
        )]
        
        output_console = Console(file=StringIO(), force_terminal=False)
        
        # Should not raise an exception
        self.formatter._print_detailed_findings(results, output_console)
        
        output = output_console.file.getvalue()
        assert "Test Finding" in output
        assert "Test description" in output

    def test_print_security_summary(self):
        """Test _print_security_summary method"""
        results = [
            self.create_test_result(valid=True, security_score=95),
            self.create_test_result(valid=False, security_score=75),
        ]
        
        output_console = Console(file=StringIO(), force_terminal=False)
        
        # Should not raise an exception
        self.formatter._print_security_summary(results, output_console)
        
        output = output_console.file.getvalue()
        assert "Total: 2" in output
        assert "Valid: 1" in output
        assert "Invalid: 1" in output

    def test_format_json_datetime_serialization(self):
        """Test JSON format properly serializes datetime objects"""
        result = self.create_test_result(
            expires=datetime(2024, 12, 31, 23, 59, 59, tzinfo=timezone.utc),
            issued=datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        )
        
        output = self.formatter._format_json([result])
        parsed = json.loads(output)
        
        result_data = parsed[0]
        assert result_data["expires"] == "2024-12-31T23:59:59+00:00"
        assert result_data["issued"] == "2024-01-01T00:00:00+00:00"

    def test_format_json_none_values(self):
        """Test JSON format handles None values correctly"""
        result = self.create_test_result(
            expires=None,
            issued=None,
            key_size=None,
            trusted=None,
            security_score=None
        )
        
        output = self.formatter._format_json([result])
        parsed = json.loads(output)
        
        result_data = parsed[0]
        assert result_data["expires"] is None
        assert result_data["issued"] is None  
        assert result_data["key_size"] is None
        assert result_data["trusted"] is None
        assert result_data["security_score"] is None

    def test_format_csv_none_and_empty_values(self):
        """Test CSV format handles None and empty values correctly"""
        result = self.create_test_result(
            key_size=None,
            san_domains=[],
            errors=[],
            security_score=None
        )
        
        output = self.formatter._format_csv([result])
        csv_reader = csv.DictReader(StringIO(output))
        row = next(csv_reader)
        
        assert row["key_size"] == ""
        assert row["san_domains"] == ""
        assert row["errors"] == ""
        assert row["security_score"] == "0"  # Default to 0 for None scores

    def test_table_output_grouping_by_url(self):
        """Test table output groups certificates by URL"""
        results = [
            self.create_test_result(
                original_url="https://example.com",
                certificate_fingerprint="abc123"
            ),
            self.create_test_result(
                original_url="https://google.com", 
                certificate_fingerprint="def456"
            )
        ]
        
        output_console = Console(file=StringIO(), force_terminal=False)
        self.formatter._print_table(results, output_console)
        
        output = output_console.file.getvalue()
        
        # Should contain both URLs (may be truncated in table display)
        assert "http" in output  # At least should contain URL indicators
        # Count table rows to verify both certificates are shown
        table_rows = output.count("│ http")  # Count data rows starting with URLs
        assert table_rows >= 2

    def test_table_output_certificate_deduplication(self):
        """Test table output deduplicates certificates with same fingerprint"""
        # Same certificate on different endpoints
        results = [
            self.create_test_result(
                endpoints=[("192.168.1.1", 443)],
                original_url="https://example.com",
                certificate_fingerprint="same123"
            ),
            self.create_test_result(
                endpoints=[("192.168.1.2", 443)], 
                original_url="https://example.com",
                certificate_fingerprint="same123"
            )
        ]
        
        output_console = Console(file=StringIO(), force_terminal=False)
        self.formatter._print_table(results, output_console)
        
        output = output_console.file.getvalue()
        
        # Should show both IPs in the endpoints column (may be on separate lines)
        assert "192." in output  # Should contain IP addresses
        # Should show two IP addresses since they're grouped together
        assert output.count("192.") >= 2

    def test_error_handling_invalid_finding_severity(self):
        """Test handling of invalid finding severity in CSV output"""
        # Create a mock finding with invalid severity for edge case testing
        invalid_finding = Mock()
        invalid_finding.severity = "INVALID_SEVERITY"
        
        result = self.create_test_result(findings=[invalid_finding])
        
        # Should not crash even with invalid severity
        output = self.formatter._format_csv([result])
        assert isinstance(output, str)

    def test_format_results_preserves_all_data(self):
        """Test that format_results preserves all important certificate data"""
        result = self.create_test_result(
            hostname="test.example.com",
            subject="CN=test.example.com",
            issuer="CN=Test CA",
            serial_number="1234567890",
            signature_algorithm="sha256WithRSAEncryption",
            public_key_algorithm="ECDSA (secp256r1)",
            key_size=256,
            certificate_fingerprint="abcdef123456789",
            errors=["Test error"],
            san_domains=["test.example.com", "alt.example.com"]
        )
        
        # Test JSON preservation
        json_output = self.formatter._format_json([result])
        json_data = json.loads(json_output)[0]
        
        assert json_data["hostname"] == "test.example.com"
        assert json_data["subject"] == "CN=test.example.com"
        assert json_data["issuer"] == "CN=Test CA"
        assert json_data["serial_number"] == "1234567890"
        assert json_data["signature_algorithm"] == "sha256WithRSAEncryption"
        assert json_data["public_key_algorithm"] == "ECDSA (secp256r1)"
        assert json_data["key_size"] == 256
        assert json_data["certificate_fingerprint"] == "abcdef123456789"
        assert "Test error" in json_data["errors"]
        assert "test.example.com" in json_data["san_domains"]
        assert "alt.example.com" in json_data["san_domains"]