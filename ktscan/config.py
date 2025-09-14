import os
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

import yaml

from .scan_target import ScanTarget, resolve_scan_targets
from .validation import validate_url_basic, validate_port_list, validate_basic_params, ValidationError

# Default configuration constants
DEFAULT_HTTPS_PORT = 443
DEFAULT_HTTPS_ALT_PORT = 8443
DEFAULT_TIMEOUT = 10
DEFAULT_OCSP_TIMEOUT = 10


def get_default_thread_count() -> int:
    """Get the default thread count used by ThreadPoolExecutor"""
    # This matches the default used by concurrent.futures.ThreadPoolExecutor
    return min(32, (os.cpu_count() or 1) + 4)


@dataclass
class ScanConfig:
    urls: List[str] = field(default_factory=list)
    ports: List[int] = field(default_factory=lambda: [DEFAULT_HTTPS_PORT])
    threads: int = field(default_factory=get_default_thread_count)
    timeout: int = DEFAULT_TIMEOUT
    output_format: str = "brief"
    verbose: bool = False
    validation: Dict[str, Any] = field(default_factory=dict)

    # Computed property for resolved targets
    _targets: List[ScanTarget] = field(default_factory=list, init=False)

    def __post_init__(self):

        # Set default validation configuration
        # Only set default profile if standards are not explicitly specified
        default_validation = {
            "severity_filter": "MEDIUM",  # Show MEDIUM and above findings
            "cryptography": {
                "enabled_checks": [],  # Empty means all enabled
                "disabled_checks": [],
            },
            "usage": {"enabled_checks": [], "disabled_checks": []},
            "lifecycle": {
                "enabled_checks": [],
                "disabled_checks": [],
                "check_ocsp": True,
                "ocsp_timeout": DEFAULT_OCSP_TIMEOUT,
            },
            "compliance": {"enabled_checks": [], "disabled_checks": []},
            "hostname": {"enabled_checks": [], "disabled_checks": []},
            "chain": {"enabled_checks": [], "disabled_checks": []},
        }

        # Apply profile-based defaults
        if not self.validation:
            self.validation = default_validation
            # Set default profile when no validation config is provided
            self.validation["profile"] = "SERVER_DEFAULT"
        else:
            # Merge with defaults
            for key, value in default_validation.items():
                if key not in self.validation:
                    self.validation[key] = value
                elif isinstance(value, dict) and isinstance(self.validation[key], dict):
                    for sub_key, sub_value in value.items():
                        if sub_key not in self.validation[key]:
                            self.validation[key][sub_key] = sub_value
            
            # Only set default profile if standards are not explicitly specified
            if "standards" not in self.validation and "profile" not in self.validation:
                self.validation["profile"] = "SERVER_DEFAULT"

        self._apply_validation_profile()

        # Process disable directives
        self._process_disable_directives()

        # Resolve scan targets after configuration is complete
        self._resolve_targets()

    def _resolve_targets(self):
        """Resolve URL specifications into ScanTarget objects"""
        if not self.urls:
            return

        try:
            self._targets = resolve_scan_targets(self.urls, self.ports)
        except ValueError as e:
            # Let validation catch this error later
            self._targets = []

    @property
    def targets(self) -> List[ScanTarget]:
        """Get resolved scan targets"""
        return self._targets

    @classmethod
    def from_cli_and_file(
            cls, cli_args: Dict[str, Any], config_file_path: Optional[str] = None
    ) -> "ScanConfig":
        config_data = {}

        # Load config file first (if provided)
        if config_file_path and os.path.exists(config_file_path):
            with open(config_file_path, "r") as f:
                config_data = yaml.safe_load(f) or {}

        # Override with CLI args (only those explicitly provided)
        config_data.update(cli_args)

        # Handle ports conversion from string to list
        if "ports" in config_data and isinstance(config_data["ports"], str):
            config_data["ports"] = [
                int(p.strip()) for p in config_data["ports"].split(",")
            ]

        # Apply defaults for missing required fields
        if not config_data.get("urls"):
            raise ValueError("URLs are required (provide via --url or config file)")

        # Set field defaults if not provided by config file or CLI
        defaults = {
            "urls": [],
            "ports": [DEFAULT_HTTPS_PORT],
            "threads": get_default_thread_count(),
            "timeout": DEFAULT_TIMEOUT,
            "output_format": "brief",
            "verbose": False,
            "validation": {},
        }

        for key, default_value in defaults.items():
            if key not in config_data:
                config_data[key] = default_value

        # Only pass valid fields to the constructor
        valid_fields = {
            k: v
            for k, v in config_data.items()
            if k in cls.__annotations__ or k == "validation"
        }
        return cls(**valid_fields)

    def validate(self) -> List[str]:
        """Validate configuration with helpful error messages"""
        errors = []

        # Validate URLs with better error messages
        if not self.urls:
            errors.append("At least one URL is required")
        else:
            validated_urls = []
            for url in self.urls:
                try:
                    cleaned_url, hostname, port = validate_url_basic(url)
                    validated_urls.append(cleaned_url)
                except ValidationError as e:
                    errors.append(f"URL '{url}': {e}")
            
            # Update URLs with cleaned versions if validation passed
            if not errors:
                self.urls = validated_urls

        # Validate ports
        try:
            validate_port_list(self.ports)
        except ValidationError as e:
            errors.append(str(e))

        # Validate threads and timeout
        try:
            validate_basic_params(self.threads, self.timeout)
        except ValidationError as e:
            errors.append(str(e))

        # Validate output format
        if self.output_format not in ["brief", "table", "json", "csv", "ndjson"]:
            errors.append(f"Invalid output format: {self.output_format}")

        # Validate that we have resolved targets (only if URLs are valid)
        if not errors and not self._targets and self.urls:
            errors.append("Failed to resolve any valid scan targets from provided URLs")

        return errors

    def _apply_validation_profile(self):
        """Apply validation profile settings"""
        profile = self.validation.get("profile", "balanced")

        if profile == "strict":
            # Enable all checks (empty disabled_checks lists)
            for validator_type in [
                "cryptography",
                "usage",
                "lifecycle",
                "compliance",
                "hostname",
                "chain",
            ]:
                if validator_type in self.validation:
                    self.validation[validator_type]["disabled_checks"] = []

        elif profile == "MINIMAL":
            # Disable some less critical checks
            disabled_checks = {
                "cryptography": [
                    "rsa_key_size_warning",
                    "ed25519_key_info",
                    "ed448_key_info",
                ],
                "usage": ["key_usage_not_critical"],
                "lifecycle": ["certificate_expires_within_90_days"],
                "compliance": ["nist_excessive_validity_period"],
                "hostname": ["san_other_name_types"],
            }

            for validator_type, checks in disabled_checks.items():
                if validator_type in self.validation:
                    existing_disabled = self.validation[validator_type].get(
                        "disabled_checks", []
                    )
                    self.validation[validator_type]["disabled_checks"] = list(
                        set(existing_disabled + checks)
                    )

        # 'balanced' profile uses defaults as-is

    def _process_disable_directives(self):
        """Process disable directives and apply them to validator configurations"""
        disable_list = self.validation.get("disable", [])
        if not disable_list:
            return

        validator_types = [
            "cryptography",
            "usage",
            "lifecycle",
            "compliance",
            "hostname",
            "chain",
        ]

        for disable_directive in disable_list:
            # Handle comma-separated values in a single directive
            for single_directive in disable_directive.split(','):
                single_directive = single_directive.strip()

                if ':' not in single_directive:
                    raise ValueError(
                        f"Invalid disable directive '{single_directive}'. Use format 'validator:check' or 'validator:*'")

                validator, check = single_directive.split(':', 1)
                validator = validator.strip()
                check = check.strip()

                if validator not in validator_types:
                    raise ValueError(f"Unknown validator '{validator}'. Valid validators: {', '.join(validator_types)}")

                # Ensure validator config exists
                self.validation.setdefault(validator, {}).setdefault("disabled_checks", [])

                if check == '*':
                    # Disable entire validator by adding a special marker
                    self.validation[validator]["disabled_validator"] = True
                else:
                    # Disable specific check
                    if check not in self.validation[validator]["disabled_checks"]:
                        self.validation[validator]["disabled_checks"].append(check)

    def get_severity_threshold(self) -> str:
        """Get the severity threshold for filtering findings"""
        return self.validation.get("severity_filter", "MEDIUM")

    def should_show_finding(self, finding_severity: str) -> bool:
        """Determine if a finding should be shown based on severity filter"""
        severity_order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        threshold = self.get_severity_threshold()

        if finding_severity not in severity_order or threshold not in severity_order:
            return True

        return severity_order.index(finding_severity) >= severity_order.index(threshold)

    @classmethod
    def create_sample_config(cls, file_path: str):
        """Create a sample configuration file with all validation options"""
        sample_config = {
            "urls": ["https://example.com"],
            "ports": [DEFAULT_HTTPS_PORT, DEFAULT_HTTPS_ALT_PORT],
            "threads": get_default_thread_count(),
            "timeout": DEFAULT_TIMEOUT,
            "output_format": "brief",
            "verbose": False,
            "validation": {
                "profile": "balanced",  # strict, balanced, minimal
                "severity_filter": "MEDIUM",  # CRITICAL, HIGH, MEDIUM, LOW, INFO

                # Disable specific validators or checks
                # Use 'validator:check' format for specific checks or 'validator:*' for entire validators
                "disable": [],
                # Examples:
                # "disable": [
                #     "hostname:*",  # Disable entire hostname validator
                #     "cryptography:weak_signature_algorithm",  # Disable specific check
                #     "lifecycle:certificate_expires_within_90_days",  # Disable 90-day warnings
                #     "chain:*",  # Disable chain validation for faster scans
                # ],

                # Lifecycle validator settings
                "lifecycle": {
                    "check_ocsp": True,  # Check OCSP endpoints for accessibility
                    "ocsp_timeout": DEFAULT_OCSP_TIMEOUT,  # OCSP endpoint timeout in seconds
                },
            },
        }

        with open(file_path, "w") as f:
            yaml.dump(sample_config, f, default_flow_style=False, indent=2)

        return sample_config
