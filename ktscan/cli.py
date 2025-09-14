import sys
from typing import Optional, Tuple

import click
from rich.console import Console
from rich.table import Table

from .check_registry import check_registry
from .config import ScanConfig
from .output import OutputFormatter
from .scanner import KTScan
from .standards_loader import standards_loader
from .threading_manager import ThreadManager


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "--url",
    "-u",
    "urls",
    multiple=True,
    help="Target URL to scan (can be used multiple times)",
)
@click.option(
    "--config", "-c", type=click.Path(exists=True), help="Path to YAML config file"
)
@click.option(
    "--threads", "-t", type=int, help="Number of threads (default: system default)"
)
@click.option("--ports", "-p", help="Comma-separated ports (default: 443)")
@click.option("--timeout", type=int, help="Connection timeout in seconds (default: 10)")
@click.option(
    "--output-format",
    "-o",
    type=click.Choice(["brief", "table", "json", "csv", "ndjson"]),
    help="Output format (default: brief)",
)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging")
@click.option(
    "--profile",
    "-P",
    help="Validation profile to use (e.g., SERVER_DEFAULT, CABF_ONLY, NIST_ONLY)",
)
@click.option(
    "--standard",
    "-s",
    multiple=True,
    help="Specific standards to include (can be used multiple times)",
)
@click.option(
    "--severity",
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]),
    help="Minimum severity to show (default: MEDIUM)",
)
@click.option(
    "--no-color",
    is_flag=True,
    help="Disable color in output text",
)
@click.version_option(version="1.0.0")
def scan_cmd(
    urls: Tuple[str, ...],
    config: Optional[str],
    threads: Optional[int],
    ports: Optional[str],
    timeout: Optional[int],
    output_format: Optional[str],
    verbose: bool,
    profile: Optional[str],
    standard: Tuple[str, ...],
    severity: Optional[str],
    no_color: bool,
) -> None:
    """
    Certificate Scanner - A multi-threaded tool for scanning SSL/TLS certificates.

    Scan certificates for a given URL across multiple IPs and ports.

    Examples:
    
    ktscan scan --url https://example.com
    
    ktscan scan --config config.yaml
    """
    console = Console()

    # Validate that either URL or config is provided
    if not urls and not config:
        console.print("[red]Error: Must specify either --url/-u or --config/-c[/red]")
        console.print("Use --help for usage information")
        sys.exit(1)

    try:
        # Build validation config from CLI args
        validation_config = {}
        
        # Handle profile vs individual standards (mutually exclusive)
        if profile and standard:
            console.print("[red]Error: Cannot specify both --profile and --standard options[/red]")
            sys.exit(1)
            
        if profile:
            validation_config["profile"] = profile
        elif standard:
            validation_config["standards"] = list(standard)
        else:
            # Default to SERVER_DEFAULT profile
            validation_config["profile"] = "SERVER_DEFAULT"
            
        if severity:
            validation_config["severity_filter"] = severity

        # Only include CLI args that were explicitly provided (not None)
        cli_args = {}
        
        # Use URLs from --url options
        if urls:
            cli_args["urls"] = list(urls)
        if ports is not None:
            cli_args["ports"] = ports
        if threads is not None:
            cli_args["threads"] = threads
        if timeout is not None:
            cli_args["timeout"] = timeout
        if output_format is not None:
            cli_args["output_format"] = output_format
        if verbose:  # verbose is a flag, so it's either True or False
            cli_args["verbose"] = verbose
        if no_color:
            cli_args["no_color"] = no_color
        # Validate profile and standards options
        if profile:
            available_profiles = standards_loader.get_available_profiles()
            if profile not in available_profiles:
                console.print(f"[red]Error: Unknown profile '{profile}'. Available profiles: {', '.join(available_profiles)}[/red]")
                sys.exit(1)
                
        if standard:
            available_standards = standards_loader.get_available_standards()
            for std in standard:
                if std not in available_standards:
                    console.print(f"[red]Error: Unknown standard '{std}'. Available standards: {', '.join(available_standards)}[/red]")
                    sys.exit(1)

        if validation_config:
            cli_args["validation"] = validation_config

        scan_config = ScanConfig.from_cli_and_file(cli_args, config)

        validation_errors = scan_config.validate()
        if validation_errors:
            console.print("[red]Configuration errors:[/red]")
            for error in validation_errors:
                console.print(f"  • {error}")
            sys.exit(1)

        if verbose:
            console.print("[blue]Configuration:[/blue]")
            console.print(f"  URLs: {', '.join(scan_config.urls)}")
            console.print(f"  Ports: {scan_config.ports}")
            console.print(f"  Threads: {scan_config.threads}")
            console.print(f"  Timeout: {scan_config.timeout}s")
            console.print(f"  Output: {scan_config.output_format}")
            console.print()

        # Create ThreadManager with user-specified thread count
        with ThreadManager(max_workers=scan_config.threads) as thread_manager:
            scanner = KTScan(scan_config, thread_manager, console)
            results = scanner.scan()

        formatter = OutputFormatter(console, results, scan_config.output_format, scan_config.verbose, scan_config)
        formatter.print_results()

        invalid_count = sum(1 for r in results if not (r.valid if hasattr(r, 'valid') else (r.certificate.valid if r.certificate else False)))
        if invalid_count > 0:
            sys.exit(1)

    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        sys.exit(130)

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        if verbose:
            console.print_exception()
        sys.exit(1)


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("config_file", type=click.Path())
def init_config_cmd(config_file: str) -> None:
    """Generate a sample configuration file with all validation options."""
    console = Console()

    try:
        ScanConfig.create_sample_config(config_file)
        console.print(f"[green]Sample configuration created: {config_file}[/green]")
        console.print("Edit this file to customize validation settings for your needs.")
    except Exception as e:
        console.print(f"[red]Error creating config file: {e}[/red]")
        sys.exit(1)


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
def get_cmd() -> None:
    """Get check categories, standards, profiles, or checks"""
    pass


@get_cmd.command("categories")
def get_categories() -> None:
    """Get all available check categories"""
    console = Console()
    
    categories = check_registry.get_all_check_categories()
    if not categories:
        console.print("[yellow]No check categories available[/yellow]")
        return
    
    table = Table(title="Available Check Categories")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Title", style="green")
    table.add_column("Description", style="blue")
    
    for category_info in categories:
        table.add_row(
            category_info.check_id,
            category_info.title,
            category_info.description
        )
    
    console.print(table)


@get_cmd.command("standards")
def get_standards():
    """Get all available standards"""
    console = Console()
    
    standards = standards_loader.get_available_standards()
    if not standards:
        console.print("[yellow]No standards available[/yellow]")
        return
    
    table = Table(title="Available Standards")
    table.add_column("Standard", style="cyan", no_wrap=True)
    table.add_column("Title", style="green")
    table.add_column("Description", style="blue")
    
    for standard_name in standards:
        try:
            standard_data = standards_loader.load_standard(standard_name)
            table.add_row(
                standard_name,
                standard_data['title'],
                standard_data['description']
            )
        except Exception as e:
            table.add_row(standard_name, "[red]Error loading[/red]", str(e))
    
    console.print(table)


@get_cmd.command("profiles")
def get_profiles():
    """Get all available validation profiles"""
    console = Console()
    
    profiles = standards_loader.load_profiles()
    if not profiles:
        console.print("[yellow]No profiles available[/yellow]")
        return
    
    table = Table(title="Available Validation Profiles")
    table.add_column("Profile", style="cyan", no_wrap=True)
    table.add_column("Standards", style="green")
    
    for profile_name, standards in profiles.items():
        table.add_row(
            profile_name,
            ", ".join(standards)
        )
    
    console.print(table)


@get_cmd.command("checks")
@click.option("--category", help="Show checks for specific category")
@click.option("--standard", help="Show checks for specific standard")
@click.option("--profile", help="Show checks for specific profile")
def get_checks(category, standard, profile):
    """Get all available checks or checks for specific criteria"""
    console = Console()
    
    # Determine which checks to show based on options
    checks_to_show = []
    title_suffix = ""
    
    if category:
        # Show checks for specific category (case insensitive)
        category_obj = check_registry.get_check_category(category.lower())
        if not category_obj:
            console.print(f"[red]Check category '{category}' not found[/red]")
            return
        
        checks_to_show = category_obj.get_all_checks()
        title_suffix = f" for {category_obj.get_check_info().title}"
        
    elif standard:
        # Show checks for specific standard
        if standard not in standards_loader.get_available_standards():
            console.print(f"[red]Standard '{standard}' not found[/red]")
            return
            
        checks_to_show = check_registry.get_checks_for_standards([standard])
        title_suffix = f" for {standard}"
        
    elif profile:
        # Show checks for specific profile
        if profile not in standards_loader.get_available_profiles():
            console.print(f"[red]Profile '{profile}' not found[/red]")
            return
            
        checks_to_show = check_registry.get_checks_for_profile(profile)
        title_suffix = f" for {profile} profile"
        
    else:
        # Show all checks organized by category
        all_checks = check_registry.get_all_checks()
        if not all_checks:
            console.print("[yellow]No checks available[/yellow]")
            return
        
        for category_checks in all_checks.values():
            checks_to_show.extend(category_checks)
    
    if not checks_to_show:
        console.print(f"[yellow]No checks found{title_suffix}[/yellow]")
        return
    
    table = Table(title=f"Available Checks{title_suffix}")
    table.add_column("Check ID", style="cyan", no_wrap=True)
    table.add_column("Title", style="green")
    table.add_column("Severity", style="red", no_wrap=True)
    table.add_column("Standards", style="blue")
    
    for check in sorted(checks_to_show, key=lambda c: c.check_id):
        standards_str = ", ".join(sorted(check.standards)) if check.standards else "None"
        table.add_row(
            check.check_id,
            check.title,
            check.severity.value,
            standards_str
        )
    
    console.print(table)


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
def describe_cmd():
    """Describe check categories or individual checks in detail"""
    pass


@describe_cmd.command("category")
@click.argument("category_id")
def describe_category(category_id):
    """Show detailed information about a specific check category"""
    console = Console()
    
    category = check_registry.get_check_category(category_id)
    if not category:
        console.print(f"[red]Check category '{category_id}' not found[/red]")
        return
    
    category_info = category.get_check_info()
    checks = category.get_all_checks()
    
    console.print(f"ID: {category_info.check_id}")
    console.print(f"Title: {category_info.title}")
    console.print(f"Description: {category_info.description}")
    console.print(f"Total Checks: {len(checks)}")
    
    # Count checks by severity
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for check in checks:
        severity = check.severity.value
        if severity in severity_counts:
            severity_counts[severity] += 1
    
    # Display severity counts
    severity_colors = {"CRITICAL": "red", "HIGH": "orange1", "MEDIUM": "yellow", "LOW": "blue", "INFO": "green"}
    console.print()
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if severity_counts[severity] > 0:
            color = severity_colors[severity]
            console.print(f"[{color}]{severity}:[/{color}] {severity_counts[severity]}")
    console.print()


@describe_cmd.command("check")
@click.argument("check_spec")  # Format: category:check_id (required)
def describe_check(check_spec):
    """Show detailed information about a specific check.
    
    Check ID format: category:check_id
    
    Example: signature:weak_signature_algorithm
    """
    console = Console()
    
    # Parse check specification - must include category
    if ":" not in check_spec:
        console.print(f"[red]Invalid check format. Use 'category:check_id' format[/red]")
        console.print("Example: signature:weak_signature_algorithm")
        return
    
    category_id, check_id = check_spec.split(":", 1)
    category = check_registry.get_check_category(category_id)
    check = category.get_check(check_id) if category else None
    if not check:
        console.print(f"[red]Check '{check_spec}' not found[/red]")
        return
    
    # Display check details
    severity_colors = {
        "CRITICAL": "red",
        "HIGH": "orange1", 
        "MEDIUM": "yellow",
        "LOW": "blue",
        "INFO": "green"
    }
    
    color = severity_colors.get(check.severity.value, "white")
    
    console.print(f"Check ID: {check_spec}")
    console.print(f"Title: {check.title}")
    console.print(f"Category: {category_id}")
    console.print(f"Severity: [{color}]{check.severity.value}[/{color}]")
    console.print(f"Description: {check.description}")
    if check.remediation:
        console.print(f"Remediation: {check.remediation}")


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
def cli():
    """Certificate Scanner CLI"""
    pass


cli.add_command(scan_cmd, name="scan")
cli.add_command(init_config_cmd)
cli.add_command(get_cmd, name="get")
cli.add_command(describe_cmd)


if __name__ == "__main__":
    cli()
