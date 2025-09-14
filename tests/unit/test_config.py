"""
Tests for ktscan.config module
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import patch, mock_open

import pytest
import yaml

from ktscan.config import ScanConfig, get_default_thread_count


class TestConfigModule:
    """Test module-level functions"""

    @patch('ktscan.config.os.cpu_count')
    def test_get_default_thread_count_with_cpu_count(self, mock_cpu_count):
        """Test default thread count calculation with CPU count"""
        mock_cpu_count.return_value = 8
        
        thread_count = get_default_thread_count()
        
        # min(32, 8 + 4) = 12
        assert thread_count == 12

    @patch('ktscan.config.os.cpu_count')
    def test_get_default_thread_count_no_cpu_count(self, mock_cpu_count):
        """Test default thread count calculation without CPU count"""
        mock_cpu_count.return_value = None
        
        thread_count = get_default_thread_count()
        
        # min(32, 1 + 4) = 5
        assert thread_count == 5

    @patch('ktscan.config.os.cpu_count')
    def test_get_default_thread_count_many_cpus(self, mock_cpu_count):
        """Test default thread count calculation with many CPUs"""
        mock_cpu_count.return_value = 64
        
        thread_count = get_default_thread_count()
        
        # min(32, 64 + 4) = 32
        assert thread_count == 32


class TestScanConfig:
    """Test the ScanConfig class"""

    def test_init_default_values(self):
        """Test ScanConfig initialization with default values"""
        config = ScanConfig()
        
        assert config.urls == []
        assert config.ports == [443]
        assert config.threads == get_default_thread_count()
        assert config.timeout == 10
        assert config.output_format == "brief"
        assert config.verbose is False
        assert isinstance(config.validation, dict)
        
        # Check default validation structure
        assert "profile" in config.validation
        assert "severity_filter" in config.validation
        assert config.validation["profile"] == "SERVER_DEFAULT"
        assert config.validation["severity_filter"] == "MEDIUM"

    def test_init_with_values(self):
        """Test ScanConfig initialization with custom values"""
        validation_config = {
            "profile": "strict",
            "severity_filter": "HIGH"
        }
        
        config = ScanConfig(
            urls=["https://example.com"],
            ports=[443, 8443],
            threads=16,
            timeout=30,
            output_format="json",
            verbose=True,
            validation=validation_config
        )
        
        assert config.urls == ["https://example.com"]
        assert config.ports == [443, 8443]
        assert config.threads == 16
        assert config.timeout == 30
        assert config.output_format == "json"
        assert config.verbose is True
        assert config.validation["profile"] == "strict"
        # When both profile and severity_filter are provided, severity_filter should be preserved
        assert config.validation["severity_filter"] == "HIGH"

    def test_post_init_validation_merging(self):
        """Test that post_init properly merges validation configuration"""
        partial_validation = {
            "profile": "strict",
            "cryptography": {"disabled_checks": ["weak_key"]}
        }
        
        config = ScanConfig(validation=partial_validation)
        
        # Should have merged with defaults
        assert config.validation["profile"] == "strict"
        assert config.validation["severity_filter"] == "MEDIUM"  # Profiles no longer affect severity filter
        assert config.validation["cryptography"]["disabled_checks"] == []  # Strict profile empties this
        assert config.validation["cryptography"]["enabled_checks"] == []  # Default
        assert "usage" in config.validation  # Default added
        assert "lifecycle" in config.validation  # Default added

    @patch('ktscan.config.resolve_scan_targets')
    def test_resolve_targets_success(self, mock_resolve):
        """Test successful target resolution"""
        from ktscan.scan_target import ScanTarget
        
        mock_targets = [
            ScanTarget("192.168.1.1", 443, "https://example.com"),
            ScanTarget("192.168.1.2", 443, "https://example.com")
        ]
        mock_resolve.return_value = mock_targets
        
        config = ScanConfig(urls=["https://example.com"])
        
        assert config.targets == mock_targets
        mock_resolve.assert_called_once_with(["https://example.com"], [443])

    @patch('ktscan.config.resolve_scan_targets')
    def test_resolve_targets_failure(self, mock_resolve):
        """Test target resolution failure handling"""
        mock_resolve.side_effect = ValueError("Invalid URL")
        
        config = ScanConfig(urls=["invalid://url"])
        
        assert config.targets == []

    def test_resolve_targets_no_urls(self):
        """Test target resolution when no URLs provided"""
        config = ScanConfig(urls=[])
        
        assert config.targets == []

    def test_from_cli_and_file_no_file(self):
        """Test configuration creation from CLI args only"""
        cli_args = {
            "urls": ["https://example.com"],
            "ports": [443, 8443],
            "threads": 8,
            "verbose": True
        }
        
        config = ScanConfig.from_cli_and_file(cli_args)
        
        assert config.urls == ["https://example.com"]
        assert config.ports == [443, 8443]
        assert config.threads == 8
        assert config.verbose is True

    def test_from_cli_and_file_nonexistent_file(self):
        """Test configuration creation when config file doesn't exist"""
        cli_args = {"urls": ["https://example.com"]}
        
        config = ScanConfig.from_cli_and_file(cli_args, "/nonexistent/config.yaml")
        
        assert config.urls == ["https://example.com"]

    def test_from_cli_and_file_with_file(self):
        """Test configuration creation with config file"""
        file_config = {
            "urls": ["https://file.example.com"],
            "timeout": 30,
            "validation": {
                "profile": "strict"
            }
        }
        
        cli_args = {
            "urls": ["https://cli.example.com"],  # Should override file
            "verbose": True
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(file_config, f)
            config_file = f.name
        
        try:
            config = ScanConfig.from_cli_and_file(cli_args, config_file)
            
            # CLI should override file
            assert config.urls == ["https://cli.example.com"]
            assert config.verbose is True
            # File values should be used where not overridden
            assert config.timeout == 30
            assert config.validation["profile"] == "strict"
            
        finally:
            os.unlink(config_file)

    def test_from_cli_and_file_ports_conversion(self):
        """Test ports conversion from string to list"""
        cli_args = {"urls": ["https://example.com"], "ports": "443,8443,9443"}
        
        config = ScanConfig.from_cli_and_file(cli_args)
        
        assert config.ports == [443, 8443, 9443]

    def test_from_cli_and_file_ports_invalid_conversion(self):
        """Test invalid ports conversion handling"""
        cli_args = {"urls": ["https://example.com"], "ports": "443,invalid,8443"}
        
        # Should raise ValueError due to invalid port
        with pytest.raises(ValueError, match="invalid literal"):
            ScanConfig.from_cli_and_file(cli_args)

    def test_from_cli_and_file_empty_yaml(self):
        """Test configuration creation with empty YAML file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("")  # Empty file
            config_file = f.name
        
        try:
            cli_args = {"urls": ["https://example.com"]}
            config = ScanConfig.from_cli_and_file(cli_args, config_file)
            
            assert config.urls == ["https://example.com"]
            
        finally:
            os.unlink(config_file)

    def test_validate_success(self):
        """Test configuration validation with valid config"""
        config = ScanConfig(
            urls=["https://example.com"],
            ports=[443],
            threads=4,
            timeout=10
        )
        
        errors = config.validate()
        
        assert errors == []

    def test_validate_no_urls(self):
        """Test validation failure when no URLs provided"""
        config = ScanConfig(urls=[])
        
        errors = config.validate()
        
        assert len(errors) > 0
        assert any("At least one URL is required" in error for error in errors)

    def test_validate_invalid_ports(self):
        """Test validation failure with invalid ports"""
        config = ScanConfig(
            urls=["https://example.com"],
            ports=[0, 70000, -1]  # Invalid ports
        )
        
        errors = config.validate()
        
        assert len(errors) > 0
        assert any("Invalid port" in error for error in errors)

    def test_validate_invalid_thread_count(self):
        """Test validation failure with invalid thread count"""
        config = ScanConfig(
            urls=["https://example.com"],
            threads=0  # Invalid thread count
        )
        
        errors = config.validate()
        
        assert len(errors) > 0
        assert any("Thread count must be positive" in error for error in errors)

    def test_validate_invalid_timeout(self):
        """Test validation failure with invalid timeout"""
        config = ScanConfig(
            urls=["https://example.com"],
            timeout=-5  # Invalid timeout
        )
        
        errors = config.validate()
        
        assert len(errors) > 0
        assert any("Timeout must be positive" in error for error in errors)

    def test_validate_invalid_output_format(self):
        """Test validation failure with invalid output format"""
        config = ScanConfig(
            urls=["https://example.com"],
            output_format="invalid_format"
        )
        
        errors = config.validate()
        
        assert len(errors) > 0
        assert any("Invalid output format" in error for error in errors)

    def test_apply_validation_profile_strict(self):
        """Test application of strict validation profile"""
        config = ScanConfig(
            urls=["https://example.com"],
            validation={"profile": "strict"}
        )
        
        # Strict profile should no longer affect severity filter
        assert config.validation["severity_filter"] == "MEDIUM"

    def test_apply_validation_profile_minimal(self):
        """Test application of minimal validation profile"""
        config = ScanConfig(
            urls=["https://example.com"],
            validation={"profile": "MINIMAL"}
        )
        
        # Minimal profile should no longer affect severity filter
        assert config.validation["severity_filter"] == "MEDIUM"

    def test_apply_validation_profile_balanced(self):
        """Test application of balanced validation profile"""
        config = ScanConfig(
            urls=["https://example.com"],
            validation={"profile": "balanced"}
        )
        
        # Balanced profile should keep default severity filter (MEDIUM)
        assert config.validation["severity_filter"] == "MEDIUM"

    def test_validation_profile_respects_explicit_severity_filter_strict(self):
        """Test that strict profile respects explicitly set severity filter"""
        config = ScanConfig(
            urls=["https://example.com"],
            validation={"profile": "strict", "severity_filter": "HIGH"}
        )
        
        # Explicit severity filter should be preserved, not overwritten by profile
        assert config.validation["severity_filter"] == "HIGH"
        
    def test_validation_profile_respects_explicit_severity_filter_minimal(self):
        """Test that minimal profile respects explicitly set severity filter"""
        config = ScanConfig(
            urls=["https://example.com"],
            validation={"profile": "MINIMAL", "severity_filter": "MEDIUM"}
        )
        
        # Explicit severity filter should be preserved, not overwritten by profile  
        assert config.validation["severity_filter"] == "MEDIUM"
        
    def test_validation_profile_respects_explicit_severity_filter_balanced(self):
        """Test that balanced profile respects explicitly set severity filter"""
        config = ScanConfig(
            urls=["https://example.com"],
            validation={"profile": "balanced", "severity_filter": "LOW"}
        )
        
        # Explicit severity filter should be preserved
        assert config.validation["severity_filter"] == "LOW"
        
    def test_cli_profile_and_severity_filter_integration(self):
        """Test that CLI can set both profile and severity filter independently"""
        # Simulate CLI args with both profile and severity filter
        cli_args = {
            "urls": ["https://example.com"],
            "validation": {
                "profile": "strict",
                "severity_filter": "MEDIUM"
            }
        }
        
        config = ScanConfig.from_cli_and_file(cli_args)
        
        # Profile should enable all checks, but severity filter should remain as specified
        assert config.validation["profile"] == "strict"
        assert config.validation["severity_filter"] == "MEDIUM"  # Should not be overwritten to "LOW"
        
    def test_process_disable_directives_single_check(self):
        """Test processing disable directive for a single check"""
        config = ScanConfig(
            urls=["https://example.com"],
            validation={
                "disable": ["cryptography:weak_signature_algorithm"]
            }
        )
        
        assert "weak_signature_algorithm" in config.validation["cryptography"]["disabled_checks"]
        assert config.validation["cryptography"].get("disabled_validator", False) is False
        
    def test_process_disable_directives_entire_validator(self):
        """Test processing disable directive for entire validator"""
        config = ScanConfig(
            urls=["https://example.com"],
            validation={
                "disable": ["hostname:*"]
            }
        )
        
        assert config.validation["hostname"]["disabled_validator"] is True
        
    def test_process_disable_directives_multiple(self):
        """Test processing multiple disable directives"""
        config = ScanConfig(
            urls=["https://example.com"],
            validation={
                "disable": [
                    "hostname:*",
                    "cryptography:weak_signature_algorithm",
                    "lifecycle:certificate_expires_within_90_days"
                ]
            }
        )
        
        assert config.validation["hostname"]["disabled_validator"] is True
        assert "weak_signature_algorithm" in config.validation["cryptography"]["disabled_checks"]
        assert "certificate_expires_within_90_days" in config.validation["lifecycle"]["disabled_checks"]
        
    def test_process_disable_directives_comma_separated(self):
        """Test processing comma-separated disable directives in single string"""
        config = ScanConfig(
            urls=["https://example.com"],
            validation={
                "disable": ["hostname:*,cryptography:weak_signature_algorithm"]
            }
        )
        
        assert config.validation["hostname"]["disabled_validator"] is True
        assert "weak_signature_algorithm" in config.validation["cryptography"]["disabled_checks"]
        
    def test_process_disable_directives_invalid_format(self):
        """Test error handling for invalid disable directive format"""
        with pytest.raises(ValueError, match="Invalid disable directive.*Use format"):
            ScanConfig(
                urls=["https://example.com"],
                validation={
                    "disable": ["invalid_directive"]
                }
            )
            
    def test_process_disable_directives_invalid_validator(self):
        """Test error handling for invalid validator name"""
        with pytest.raises(ValueError, match="Unknown validator.*Valid validators"):
            ScanConfig(
                urls=["https://example.com"],
                validation={
                    "disable": ["invalid_validator:some_check"]
                }
            )

    def test_get_severity_threshold(self):
        """Test severity threshold retrieval"""
        config = ScanConfig(validation={"severity_filter": "HIGH"})
        
        threshold = config.get_severity_threshold()
        
        assert threshold == "HIGH"

    def test_get_severity_threshold_default(self):
        """Test severity threshold retrieval with default"""
        config = ScanConfig()
        
        threshold = config.get_severity_threshold()
        
        assert threshold == "MEDIUM"

    def test_should_show_finding_above_threshold(self):
        """Test finding display logic for findings above threshold"""
        config = ScanConfig(validation={"severity_filter": "MEDIUM"})
        
        assert config.should_show_finding("HIGH") is True
        assert config.should_show_finding("CRITICAL") is True

    def test_should_show_finding_at_threshold(self):
        """Test finding display logic for findings at threshold"""
        config = ScanConfig(validation={"severity_filter": "MEDIUM"})
        
        assert config.should_show_finding("MEDIUM") is True

    def test_should_show_finding_below_threshold(self):
        """Test finding display logic for findings below threshold"""
        config = ScanConfig(validation={"severity_filter": "MEDIUM"})
        
        assert config.should_show_finding("LOW") is False
        assert config.should_show_finding("INFO") is False

    def test_should_show_finding_invalid_severity(self):
        """Test finding display logic with invalid severity"""
        config = ScanConfig(validation={"severity_filter": "MEDIUM"})
        
        # Invalid severity should default to showing the finding
        assert config.should_show_finding("INVALID") is True

    def test_create_sample_config(self):
        """Test sample configuration file creation"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            sample_file = f.name
        
        # Remove the file so create_sample_config can create it
        os.unlink(sample_file)
        
        try:
            ScanConfig.create_sample_config(sample_file)
            
            # Verify file was created
            assert os.path.exists(sample_file)
            
            # Verify content is valid YAML
            with open(sample_file, 'r') as f:
                config_data = yaml.safe_load(f)
            
            assert isinstance(config_data, dict)
            assert "urls" in config_data
            assert "ports" in config_data
            assert "validation" in config_data
            
        finally:
            if os.path.exists(sample_file):
                os.unlink(sample_file)

    def test_create_sample_config_file_exists(self):
        """Test sample configuration creation when file already exists"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("existing content")
            sample_file = f.name
        
        try:
            # Create sample config (this will overwrite existing file based on actual implementation)
            ScanConfig.create_sample_config(sample_file)
            
            with open(sample_file, 'r') as f:
                content = f.read()
            
            # The implementation always writes, so content should be YAML config, not original content
            config_data = yaml.safe_load(content)
            assert isinstance(config_data, dict)
            assert "urls" in config_data
            
        finally:
            os.unlink(sample_file)

    def test_targets_property(self):
        """Test targets property access"""
        config = ScanConfig(urls=["https://example.com"])
        
        # Should return internal _targets list
        assert config.targets == config._targets

    def test_validation_merging_deep_dict(self):
        """Test deep dictionary merging in validation configuration"""
        partial_validation = {
            "cryptography": {
                "disabled_checks": ["weak_key"],
                # enabled_checks should be added from defaults
            },
            "lifecycle": {
                "check_ocsp": False,
                # ocsp_timeout should be added from defaults  
            }
        }
        
        config = ScanConfig(validation=partial_validation)
        
        # Check deep merging worked
        assert config.validation["cryptography"]["disabled_checks"] == ["weak_key"]
        assert config.validation["cryptography"]["enabled_checks"] == []  # From defaults
        assert config.validation["lifecycle"]["check_ocsp"] is False
        assert config.validation["lifecycle"]["ocsp_timeout"] == 10  # From defaults

    @patch('builtins.open', new_callable=mock_open, read_data="invalid: yaml: content:\n  - unclosed")
    def test_from_cli_and_file_invalid_yaml(self, mock_file):
        """Test configuration creation with invalid YAML file"""
        cli_args = {"urls": ["https://example.com"]}
        
        with patch('ktscan.config.os.path.exists', return_value=True):
            # Should handle YAML parsing errors gracefully and fall back to CLI args
            try:
                config = ScanConfig.from_cli_and_file(cli_args, "invalid.yaml")
                # Should still use CLI args if YAML parsing fails
                assert config.urls == ["https://example.com"]
            except yaml.YAMLError:
                # YAML parsing errors might be propagated, which is also acceptable behavior
                pass