import sys
import os
import time
import shutil
import argparse
import asyncio
from typing import List, Optional, Tuple
from openrecon import __version__
from openrecon.config import settings
from openrecon.utils.input_validator import validate_target
from openrecon.utils.dotenv import load_dotenv
from openrecon.modules import MODULE_REGISTRY
from openrecon.engine import ScanEngine
from openrecon.updater import run_opt_in_update_check
from openrecon.formatter import (
    console,
    err_console,
    print_startup_banner,
    render_results,
    render_modules_list,
    export_text_report
)

load_dotenv()

def format_modules_help() -> str:
    """Dynamically generate help text for -m / --modules from MODULE_REGISTRY."""
    lines = ["Comma-separated list of modules to run.", "Available modules:"]
    max_key_len = max(len(k) for k in MODULE_REGISTRY) + 2
    for k, v in MODULE_REGISTRY.items():
        desc = v.get("name") or v.get("description", "")
        lines.append(f"  {k:<{max_key_len}}{desc}")
    return "\n".join(lines)

def resolve_modules(module_filter: Optional[str]) -> Tuple[List[str], List[str]]:
    """
    Resolves a comma-separated module filter string into valid module identifiers.
    Returns (selected_modules, unknown_modules).
    """
    if not module_filter or module_filter.strip().lower() == "all":
        return list(MODULE_REGISTRY.keys()), []

    raw_keys = [k.strip().lower() for k in module_filter.split(",") if k.strip()]
    selected: List[str] = []
    unknown: List[str] = []

    for rk in raw_keys:
        if rk in MODULE_REGISTRY:
            if rk not in selected:
                selected.append(rk)
        else:
            # Check for substring match (e.g. subdomain -> subdomains)
            matched = [k for k in MODULE_REGISTRY if rk == k or rk in k]
            if matched:
                if matched[0] not in selected:
                    selected.append(matched[0])
            else:
                unknown.append(rk)

    return selected, unknown

def validate_output_path(output_file: str) -> Tuple[bool, str]:
    """
    Validates that the output file has a .txt extension.
    Returns (is_valid, extension_or_error).
    """
    ext = os.path.splitext(output_file)[1]
    if ext.lower() == ".txt":
        return True, ext
    return False, ext if ext else "none"

def print_unknown_module_error(unknown: List[str]):
    """Prints a clear error message when unknown module identifiers are provided."""
    unknown_str = ", ".join(unknown)
    avail_str = ", ".join(MODULE_REGISTRY.keys())
    err_console.print(f"[bold red][!] Unknown module:[/bold red] {unknown_str}\n")
    err_console.print(f"Available modules:\n    {avail_str}\n")

def print_unsupported_output_error(ext: str):
    """Prints an error when an unsupported output format is provided."""
    err_console.print(f"[bold red][!] Unsupported output format:[/bold red] {ext}")
    err_console.print("    OpenRecon supports only .txt output files.\n")

class OpenReconHelpFormatter(argparse.RawTextHelpFormatter):
    """
    Custom help formatter that uses a consistent description column
    wide enough for option flags while dynamically adapting to terminal width.
    """
    def __init__(self, prog, indent_increment=2, max_help_position=26, width=None):
        if width is None:
            cols = shutil.get_terminal_size().columns
            width = min(120, max(80, cols))
        super().__init__(prog, indent_increment=indent_increment, max_help_position=max_help_position, width=width)

class OpenReconArgumentParser(argparse.ArgumentParser):
    def format_help(self) -> str:
        return super().format_help()

def build_parser() -> argparse.ArgumentParser:
    timeout_default = int(settings.MODULE_TIMEOUT) if settings.MODULE_TIMEOUT.is_integer() else settings.MODULE_TIMEOUT
    parser = OpenReconArgumentParser(
        prog="openrecon",
        description="OpenRecon - OSINT based Passive Reconnaissance",
        formatter_class=OpenReconHelpFormatter,
        add_help=False,
        epilog="""
Module Reference:
  openrecon list-modules List all available modules and descriptions

Examples:
  openrecon example.com
  openrecon example.com -m dns,ssl,tech
  openrecon example.com -o results.txt
"""
    )

    parser.add_argument("-h", "--help", action="store_true", help="Show this help message and exit")
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s v{__version__}", help="Show program's version number and exit")
    parser.add_argument("target", nargs="?", help="Target domain, public IPv4, or 'list-modules'")
    parser.add_argument("-m", "--modules", dest="module", help=format_modules_help())
    parser.add_argument("-o", "--output", help="Save scan results to a text file (.txt only)")
    parser.add_argument("-t", "--timeout", type=float, default=settings.MODULE_TIMEOUT, help=f"Timeout per module in seconds (default: {timeout_default}s)")
    parser.add_argument("--check-update", action="store_true", help="Check for available updates and exit")
    parser.add_argument("--no-update", action="store_true", help="Skip automatic update check for this invocation")
    parser.add_argument("-e", "--evidence", action="store_true", help="Show structured provenance and evidence matching trace")

    return parser

async def execute_scan(
    target: str,
    module_filter: Optional[str],
    output_file: Optional[str],
    timeout: float,
    show_evidence: bool = False
) -> int:
    # 1. Validate Target
    val_res = validate_target(target)
    if not val_res.is_valid:
        err_console.print(f"[bold red]✖ Target Validation Error:[/bold red] {val_res.error_message}")
        return 1

    normalized_target = val_res.normalized_input or target

    # 2. Determine Modules to Run
    selected_modules, unknown_modules = resolve_modules(module_filter)
    if unknown_modules:
        print_unknown_module_error(unknown_modules)
        return 1

    if not selected_modules:
        err_console.print("[bold red]✖ Error:[/bold red] No valid modules selected.")
        return 1

    # 3. Validate Output File if provided
    if output_file:
        is_valid, ext = validate_output_path(output_file)
        if not is_valid:
            print_unsupported_output_error(ext)
            return 1

    engine = ScanEngine(timeout=timeout)

    # 4. Run Scan with Rich Spinner & timing
    start_time = time.perf_counter()
    with console.status(f"[bold cyan]Scanning target '{normalized_target}' ({len(selected_modules)} modules)...[/bold cyan]", spinner="dots"):
        results = await engine.run_modules(selected_modules, normalized_target)
    elapsed = time.perf_counter() - start_time

    # 5. Render Formatted Output to Terminal
    render_results(results, elapsed_seconds=elapsed, module_count=len(selected_modules), show_evidence=show_evidence)

    # 6. Save to File if requested (-o)
    if output_file:
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(export_text_report(results, elapsed_seconds=elapsed, module_count=len(selected_modules), show_evidence=show_evidence))
            console.print(f"[bold green]✔ Results saved to:[/bold green] [white]{output_file}[/white]")
        except Exception as e:
            err_console.print(f"[bold red]✖ Failed to save results to '{output_file}':[/bold red] {e}")
            return 1

    return 0

def print_help_with_banner(parser: argparse.ArgumentParser):
    print_startup_banner()
    parser.print_help()

def main(args_list: Optional[List[str]] = None):
    parser = build_parser()
    raw_args = args_list if args_list is not None else sys.argv[1:]
    args = parser.parse_args(raw_args)

    try:
        # Check for explicit update check flag (--check-update)
        if args.check_update:
            run_opt_in_update_check()
            sys.exit(0)

        # Check for explicit --help / -h
        if args.help:
            print_help_with_banner(parser)
            sys.exit(0)

        # Check for list-modules dedicated command
        if args.target == "list-modules":
            render_modules_list(MODULE_REGISTRY)
            sys.exit(0)

        # Validate module filter if passed
        if args.module:
            selected_modules, unknown_modules = resolve_modules(args.module)
            if unknown_modules:
                print_unknown_module_error(unknown_modules)
                sys.exit(1)

        # Validate output file if passed
        if args.output:
            is_valid, ext = validate_output_path(args.output)
            if not is_valid:
                print_unsupported_output_error(ext)
                sys.exit(1)

        # Check if target is provided for scan
        if args.target:
            ret = asyncio.run(
                execute_scan(
                target=args.target,
                module_filter=args.module,
                output_file=args.output,
                timeout=args.timeout,
                show_evidence=args.evidence
            )
            )
            sys.exit(ret)

        # No target provided (bare `openrecon`)
        else:
            print_help_with_banner(parser)
            sys.exit(0)

    except KeyboardInterrupt:
        err_console.print("\n[bold yellow]Scan aborted by user (Ctrl+C).[/bold yellow]")
        sys.exit(130)
    except Exception as e:
        err_console.print(f"\n[bold red]Fatal Error:[/bold red] {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
