"""
Tests for ktscan.cli module
"""

import sys
from unittest.mock import patch, MagicMock, Mock
from click.testing import CliRunner
import pytest
from rich.console import Console

from ktscan.cli import main, init_config_cmd, cli
from ktscan.config import ScanConfig
from ktscan.cert_analyzer import CertResult


class TestMainCommand:
    """Test the main scan command"""

    def setup_method(self):
        """Set up test fixtures"""
        self.runner = CliRunner()
        
    @patch('ktscan.cli.KTScan')
    @patch('ktscan.cli.ThreadManager')
    @patch('ktscan.cli.OutputFormatter')
    @patch('ktscan.cli.ScanConfig')
    def test_main_basic_scan(self, mock_scan_config, mock_formatter, mock_thread_manager, mock_scanner):
        """Test basic scan with minimal args"""
        # Mock configuration
        mock_config = Mock()
        mock_config.validate.return_value = []
        mock_config.urls = ["https://example.com"]
        mock_config.ports = [443]
        mock_config.threads = 4
        mock_config.timeout = 10
        mock_config.output_format = "table"
        mock_scan_config.from_cli_and_file.return_value = mock_config
        
        # Mock scanner results
        mock_result = Mock()
        mock_result.valid = True
        mock_scanner_instance = Mock()
        mock_scanner_instance.scan.return_value = [mock_result]
        mock_scanner.return_value = mock_scanner_instance
        
        # Mock thread manager
        mock_thread_manager_instance = Mock()
        mock_thread_manager_instance.__enter__ = Mock(return_value=mock_thread_manager_instance)
        mock_thread_manager_instance.__exit__ = Mock(return_value=None)
        mock_thread_manager.return_value = mock_thread_manager_instance
        
        # Mock formatter
        mock_formatter_instance = Mock()
        mock_formatter.return_value = mock_formatter_instance
        
        result = self.runner.invoke(main, ['--url', 'https://example.com'])
        
        assert result.exit_code == 0
        mock_scan_config.from_cli_and_file.assert_called_once()
        mock_scanner_instance.scan.assert_called_once()
        mock_formatter_instance.print_results.assert_called_once()

    @patch('ktscan.cli.ScanConfig')
    def test_main_validation_errors(self, mock_scan_config):
        """Test main command with validation errors"""
        mock_config = Mock()
        mock_config.validate.return_value = ["Error 1", "Error 2"]
        mock_scan_config.from_cli_and_file.return_value = mock_config
        
        result = self.runner.invoke(main, ['--url', 'https://example.com'])
        
        assert result.exit_code == 1
        assert "Configuration errors:" in result.output

    @patch('ktscan.cli.KTScan')
    @patch('ktscan.cli.ThreadManager')
    @patch('ktscan.cli.OutputFormatter')
    @patch('ktscan.cli.ScanConfig')
    def test_main_with_all_options(self, mock_scan_config, mock_formatter, mock_thread_manager, mock_scanner):
        """Test main command with all CLI options"""
        mock_config = Mock()
        mock_config.validate.return_value = []
        mock_config.urls = ["https://example.com"]
        mock_config.ports = [443, 8443]
        mock_config.threads = 8
        mock_config.timeout = 30
        mock_config.output_format = "json"
        mock_scan_config.from_cli_and_file.return_value = mock_config
        
        mock_result = Mock()
        mock_result.valid = True
        mock_scanner_instance = Mock()
        mock_scanner_instance.scan.return_value = [mock_result]
        mock_scanner.return_value = mock_scanner_instance
        
        mock_thread_manager_instance = Mock()
        mock_thread_manager_instance.__enter__ = Mock(return_value=mock_thread_manager_instance)
        mock_thread_manager_instance.__exit__ = Mock(return_value=None)
        mock_thread_manager.return_value = mock_thread_manager_instance
        
        mock_formatter_instance = Mock()
        mock_formatter.return_value = mock_formatter_instance
        
        result = self.runner.invoke(main, [
            '--url', 'https://example.com',
            '--ports', '443,8443',
            '--threads', '8',
            '--no-validate',
            '--timeout', '30',
            '--output-format', 'json',
            '--verbose',
            '--profile', 'SERVER_DEFAULT',
            '--severity', 'HIGH'
        ])
        
        assert result.exit_code == 0
        
        # Check CLI args were processed correctly
        call_args = mock_scan_config.from_cli_and_file.call_args
        cli_args = call_args[0][0]
        
        assert cli_args["urls"] == ["https://example.com"]
        assert cli_args["ports"] == "443,8443"
        assert cli_args["threads"] == 8
        assert cli_args["timeout"] == 30
        assert cli_args["output_format"] == "json"
        assert cli_args["verbose"] is True
        
        # Check validation config
        validation_config = cli_args["validation"]
        assert validation_config["profile"] == "server_default"
        assert validation_config["severity_filter"] == "HIGH"

    @patch('ktscan.cli.KTScan')
    @patch('ktscan.cli.ThreadManager')
    @patch('ktscan.cli.OutputFormatter')
    @patch('ktscan.cli.ScanConfig')
    def test_main_with_config_file(self, mock_scan_config, mock_formatter, mock_thread_manager, mock_scanner):
        """Test main command with config file"""
        mock_config = Mock()
        mock_config.validate.return_value = []
        mock_config.urls = ["https://example.com"]
        mock_config.output_format = "table"
        mock_scan_config.from_cli_and_file.return_value = mock_config
        
        mock_result = Mock()
        mock_result.valid = True
        mock_scanner_instance = Mock()
        mock_scanner_instance.scan.return_value = [mock_result]
        mock_scanner.return_value = mock_scanner_instance
        
        mock_thread_manager_instance = Mock()
        mock_thread_manager_instance.__enter__ = Mock(return_value=mock_thread_manager_instance)
        mock_thread_manager_instance.__exit__ = Mock(return_value=None)
        mock_thread_manager.return_value = mock_thread_manager_instance
        
        mock_formatter_instance = Mock()
        mock_formatter.return_value = mock_formatter_instance
        
        # Create a temporary config file for testing
        with self.runner.isolated_filesystem():
            with open('config.yaml', 'w') as f:
                f.write('urls: ["https://example.com"]')
                
            result = self.runner.invoke(main, ['--config', 'config.yaml'])
            
            assert result.exit_code == 0
            call_args = mock_scan_config.from_cli_and_file.call_args
            assert call_args[0][1] == 'config.yaml'  # Config file path

    @patch('ktscan.cli.KTScan')
    @patch('ktscan.cli.ThreadManager')  
    @patch('ktscan.cli.OutputFormatter')
    @patch('ktscan.cli.ScanConfig')
    def test_main_invalid_results_exit_code(self, mock_scan_config, mock_formatter, mock_thread_manager, mock_scanner):
        """Test exit code when scan results contain invalid certificates"""
        mock_config = Mock()
        mock_config.validate.return_value = []
        mock_config.output_format = "table"
        mock_scan_config.from_cli_and_file.return_value = mock_config
        
        # Create results with invalid certificates
        valid_result = Mock()
        valid_result.valid = True
        invalid_result = Mock()
        invalid_result.valid = False
        
        mock_scanner_instance = Mock()
        mock_scanner_instance.scan.return_value = [valid_result, invalid_result]
        mock_scanner.return_value = mock_scanner_instance
        
        mock_thread_manager_instance = Mock()
        mock_thread_manager_instance.__enter__ = Mock(return_value=mock_thread_manager_instance)
        mock_thread_manager_instance.__exit__ = Mock(return_value=None)
        mock_thread_manager.return_value = mock_thread_manager_instance
        
        mock_formatter_instance = Mock()
        mock_formatter.return_value = mock_formatter_instance
        
        result = self.runner.invoke(main, ['--url', 'https://example.com'])
        
        # Should exit with code 1 due to invalid certificate
        assert result.exit_code == 1

    @patch('ktscan.cli.ScanConfig')
    def test_main_keyboard_interrupt(self, mock_scan_config):
        """Test handling of keyboard interrupt"""
        mock_config = Mock()
        mock_config.validate.return_value = []
        mock_scan_config.from_cli_and_file.side_effect = KeyboardInterrupt()
        
        result = self.runner.invoke(main, ['--url', 'https://example.com'])
        
        assert result.exit_code == 130
        assert "interrupted by user" in result.output

    @patch('ktscan.cli.ScanConfig')
    def test_main_general_exception(self, mock_scan_config):
        """Test handling of general exceptions"""
        mock_scan_config.from_cli_and_file.side_effect = Exception("Test error")
        
        result = self.runner.invoke(main, ['--url', 'https://example.com'])
        
        assert result.exit_code == 1
        assert "Error: Test error" in result.output

    @patch('ktscan.cli.KTScan')
    @patch('ktscan.cli.ThreadManager')
    @patch('ktscan.cli.OutputFormatter') 
    @patch('ktscan.cli.ScanConfig')
    def test_main_verbose_output(self, mock_scan_config, mock_formatter, mock_thread_manager, mock_scanner):
        """Test verbose output shows configuration details"""
        mock_config = Mock()
        mock_config.validate.return_value = []
        mock_config.urls = ["https://example.com"]
        mock_config.ports = [443]
        mock_config.threads = 4
        mock_config.timeout = 10
        mock_config.output_format = "table"
        mock_scan_config.from_cli_and_file.return_value = mock_config
        
        mock_result = Mock()
        mock_result.valid = True
        mock_scanner_instance = Mock()
        mock_scanner_instance.scan.return_value = [mock_result]
        mock_scanner.return_value = mock_scanner_instance
        
        mock_thread_manager_instance = Mock()
        mock_thread_manager_instance.__enter__ = Mock(return_value=mock_thread_manager_instance)
        mock_thread_manager_instance.__exit__ = Mock(return_value=None)
        mock_thread_manager.return_value = mock_thread_manager_instance
        
        mock_formatter_instance = Mock()
        mock_formatter.return_value = mock_formatter_instance
        
        result = self.runner.invoke(main, ['--url', 'https://example.com', '--verbose'])
        
        assert result.exit_code == 0
        assert "Configuration:" in result.output
        assert "URLs: https://example.com" in result.output
        assert "Threads: 4" in result.output

    def test_main_multiple_urls(self):
        """Test main command with multiple URLs"""
        with patch('ktscan.cli.ScanConfig') as mock_scan_config:
            mock_config = Mock()
            mock_config.validate.return_value = []
            mock_scan_config.from_cli_and_file.return_value = mock_config
            
            with patch('ktscan.cli.KTScan'):
                with patch('ktscan.cli.ThreadManager'):
                    with patch('ktscan.cli.OutputFormatter'):
                        result = self.runner.invoke(main, [
                            '--url', 'https://example.com',
                            '--url', 'https://google.com'
                        ])
                        
                        # Check that multiple URLs were processed
                        call_args = mock_scan_config.from_cli_and_file.call_args
                        cli_args = call_args[0][0]
                        assert cli_args["urls"] == ["https://example.com", "https://google.com"]

    def test_main_disable_multiple_checks(self):
        """Test disabling multiple validation checks"""
        with patch('ktscan.cli.ScanConfig') as mock_scan_config:
            mock_config = Mock()
            mock_config.validate.return_value = []
            mock_scan_config.from_cli_and_file.return_value = mock_config
            
            with patch('ktscan.cli.KTScan') as mock_scanner:
                mock_scanner_instance = Mock()
                mock_scanner_instance.scan.return_value = []
                mock_scanner.return_value = mock_scanner_instance
                
                with patch('ktscan.cli.ThreadManager'):
                    with patch('ktscan.cli.OutputFormatter'):
                        result = self.runner.invoke(main, [
                            '--url', 'https://example.com',
                            '--profile', 'MINIMAL'
                        ])
                        
                        assert result.exit_code == 0


class TestInitConfigCommand:
    """Test the init-config command"""

    def setup_method(self):
        """Set up test fixtures"""
        self.runner = CliRunner()

    @patch('ktscan.cli.ScanConfig.create_sample_config')
    def test_init_config_success(self, mock_create_sample):
        """Test successful config file creation"""
        result = self.runner.invoke(init_config_cmd, ['test-config.yaml'])
        
        assert result.exit_code == 0
        assert "Sample configuration created: test-config.yaml" in result.output
        mock_create_sample.assert_called_once_with('test-config.yaml')

    @patch('ktscan.cli.ScanConfig.create_sample_config')
    def test_init_config_error(self, mock_create_sample):
        """Test config file creation with error"""
        mock_create_sample.side_effect = Exception("Permission denied")
        
        result = self.runner.invoke(init_config_cmd, ['test-config.yaml'])
        
        assert result.exit_code == 1
        assert "Error creating config file: Permission denied" in result.output


class TestCliGroup:
    """Test the CLI group and command registration"""

    def setup_method(self):
        """Set up test fixtures"""
        self.runner = CliRunner()

    def test_cli_group_help(self):
        """Test CLI group help output"""
        result = self.runner.invoke(cli, ['--help'])
        
        assert result.exit_code == 0
        assert "Certificate Scanner CLI" in result.output
        assert "scan" in result.output
        assert "init-config" in result.output

    def test_scan_command_help(self):
        """Test scan command help output"""
        result = self.runner.invoke(cli, ['scan', '--help'])
        
        assert result.exit_code == 0
        assert "Certificate Scanner" in result.output
        assert "--url" in result.output
        assert "--config" in result.output
        assert "--threads" in result.output

    def test_init_config_help(self):
        """Test init-config command help output"""
        result = self.runner.invoke(cli, ['init-config', '--help'])
        
        assert result.exit_code == 0
        assert "Generate a sample configuration file" in result.output


class TestOptionValidation:
    """Test CLI option validation"""

    def setup_method(self):
        """Set up test fixtures"""
        self.runner = CliRunner()

    def test_invalid_output_format(self):
        """Test invalid output format option"""
        result = self.runner.invoke(main, ['--url', 'https://example.com', '--output-format', 'invalid'])
        
        assert result.exit_code != 0
        assert "Invalid value for '--output-format'" in result.output

    def test_invalid_validation_profile(self):
        """Test invalid validation profile option"""
        result = self.runner.invoke(main, ['--url', 'https://example.com', '--profile', 'invalid'])
        
        assert result.exit_code != 0
        assert "Unknown profile 'invalid'" in result.output

    def test_invalid_severity_filter(self):
        """Test invalid severity filter option"""  
        result = self.runner.invoke(main, ['--url', 'https://example.com', '--severity', 'invalid'])
        
        assert result.exit_code != 0
        assert "Invalid value for '--severity'" in result.output
        
    def test_validation_profile_and_severity_filter_combination(self):
        """Test that validation profile and severity filter can be used together"""
        with patch('ktscan.cli.KTScan') as mock_scanner_class, \
             patch('ktscan.cli.OutputFormatter') as mock_formatter:
            
            mock_scanner = Mock()
            mock_scanner.scan.return_value = []
            mock_scanner_class.return_value = mock_scanner
            
            # Test strict profile with explicit MEDIUM severity filter
            result = self.runner.invoke(main, [
                '--url', 'https://example.com',
                '--profile', 'SERVER_DEFAULT',
                '--severity', 'MEDIUM'
            ])
            
            assert result.exit_code == 0
            
            # Verify the scanner was created with correct config
            mock_scanner_class.assert_called_once()
            args, kwargs = mock_scanner_class.call_args
            config = args[0]  # First argument is the config
            
            assert config.validation["profile"] == "server_default"
            assert config.validation["severity_filter"] == "MEDIUM"  # Should be preserved, not overwritten to "LOW"
            
    def test_profile_option(self):
        """Test the --profile option"""
        with patch('ktscan.cli.KTScan') as mock_scanner_class, \
             patch('ktscan.cli.OutputFormatter') as mock_formatter:
            
            mock_scanner = Mock()
            mock_scanner.scan.return_value = []
            mock_scanner_class.return_value = mock_scanner
            
            result = self.runner.invoke(main, [
                '--url', 'https://example.com',
                '--profile', 'MINIMAL'
            ])
            
            assert result.exit_code == 0
            
            # Verify the scanner was created with correct config
            mock_scanner_class.assert_called_once()
            args, kwargs = mock_scanner_class.call_args
            config = args[0]  # First argument is the config
            
            assert config.validation["profile"] == "minimal"
            
    def test_severity_option(self):
        """Test --severity option"""
        with patch('ktscan.cli.KTScan') as mock_scanner_class, \
             patch('ktscan.cli.OutputFormatter') as mock_formatter:
            
            mock_scanner = Mock()
            mock_scanner.scan.return_value = []
            mock_scanner_class.return_value = mock_scanner
            
            result = self.runner.invoke(main, [
                '--url', 'https://example.com',
                '--severity', 'HIGH'
            ])
            
            assert result.exit_code == 0
            
            # Verify the config
            mock_scanner_class.assert_called_once()
            args, kwargs = mock_scanner_class.call_args
            config = args[0]  # First argument is the config
            
            assert config.validation["severity_filter"] == "HIGH"

    def test_nonexistent_config_file(self):
        """Test nonexistent config file"""
        result = self.runner.invoke(main, ['--config', 'nonexistent.yaml'])
        
        assert result.exit_code != 0
        assert "does not exist" in result.output


class TestEdgeCases:
    """Test edge cases and error conditions"""

    def setup_method(self):
        """Set up test fixtures"""
        self.runner = CliRunner()

    @patch('ktscan.cli.ScanConfig')
    def test_no_arguments(self, mock_scan_config):
        """Test command with no arguments at all"""
        mock_config = Mock()
        mock_config.validate.return_value = ["At least one URL is required"]
        mock_scan_config.from_cli_and_file.return_value = mock_config
        
        result = self.runner.invoke(main, [])
        
        assert result.exit_code == 1

    @patch('ktscan.cli.ScanConfig')  
    def test_empty_url_list(self, mock_scan_config):
        """Test command with empty URL list"""
        # This tests the case where url tuple is empty
        mock_config = Mock()
        mock_config.validate.return_value = ["At least one URL is required"]
        mock_scan_config.from_cli_and_file.return_value = mock_config
        
        result = self.runner.invoke(main, [])
        
        assert result.exit_code == 1
        # Verify that URLs were not included in CLI args when empty
        call_args = mock_scan_config.from_cli_and_file.call_args
        cli_args = call_args[0][0]
        assert "urls" not in cli_args or not cli_args.get("urls")