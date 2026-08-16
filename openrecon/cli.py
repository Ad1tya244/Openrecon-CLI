import sys
import os
import time
import argparse
import asyncio
from typing import List, Optional
from openrecon import __version__
from openrecon.config import settings
from openrecon.utils.input_validator import validate_target
from openrecon.utils.dotenv import load_dotenv
from openrecon.modules import MODULE_REGISTRY
from openrecon.engine import ScanEngine
from openrecon.formatter import (
    console,
    err_console,
    print_startup_banner,
    render_results,
    render_modules_list,
    export_json,
    export_text_report
)

load_dotenv()

class OpenReconArgumentParser(argparse.ArgumentParser):
    def format_help(self) -> str:
        help_text = super().format_help()
        # Add startup banner to help output
        return help_text

def build_parser() -> argparse.ArgumentParser:
    parser = OpenReconArgumentParser(
        prog="openrecon",
        description="OpenRecon - Local OSINT & Reconnaissance CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False,
        epilog="""
Examples:
  openrecon example.com
  openrecon example.com -m dns,ssl,tech
  openrecon example.com -o results.json
  openrecon list-modules
"""
    )

    parser.add_argument("-h", "--help", action="store_true", help="Show this help message and exit")
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s v{__version__}")
    parser.add_argument("target", nargs="?", help="Target domain, public IPv4, or 'list-modules'")
    parser.add_argument("-m", "--module", "--modules", dest="module", help="Comma-separated list of modules to run (e.g. dns,ssl,tech)")
    parser.add_argument("-o", "--output", help="Save scan results to a file (format determined by extension, e.g. .json)")
    parser.add_argument("-t", "--timeout", type=float, default=settings.MODULE_TIMEOUT, help=f"Timeout per module in seconds (default: {settings.MODULE_TIMEOUT}s)")

    return parser

async def execute_scan(
    target: str,
    module_filter: Optional[str],
    output_file: Optional[str],
    timeout: float
) -> int:
    # 1. Validate Target
    val_res = validate_target(target)
    if not val_res.is_valid:
        err_console.print(f"[bold red]✖ Target Validation Error:[/bold red] {val_res.error_message}")
        return 1

    normalized_target = val_res.normalized_input or target

    # 2. Determine Modules to Run
    if module_filter and module_filter.strip().lower() != "all":
        raw_keys = [k.strip().lower() for k in module_filter.split(",") if k.strip()]
        selected_modules = []
        for rk in raw_keys:
            if rk in MODULE_REGISTRY:
                selected_modules.append(rk)
            else:
                matched = [k for k in MODULE_REGISTRY if rk in k]
                if matched:
                    selected_modules.append(matched[0])
                else:
                    err_console.print(f"[bold red]✖ Warning:[/bold red] Unknown module '{rk}' skipped.")
        if not selected_modules:
            err_console.print("[bold red]✖ Error:[/bold red] No valid modules selected.")
            return 1
    else:
        selected_modules = list(MODULE_REGISTRY.keys())

    engine = ScanEngine(timeout=timeout)

    # 3. Run Scan with Rich Spinner & timing
    start_time = time.perf_counter()
    with console.status(f"[bold cyan]Scanning target '{normalized_target}' ({len(selected_modules)} modules)...[/bold cyan]", spinner="dots"):
        results = await engine.run_modules(selected_modules, normalized_target)
    elapsed = time.perf_counter() - start_time

    # 4. Render Formatted Output to Terminal
    render_results(results, elapsed_seconds=elapsed, module_count=len(selected_modules))

    # 5. Save to File if requested (-o)
    if output_file:
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                if output_file.lower().endswith(".json"):
                    f.write(export_json(results))
                else:
                    f.write(export_text_report(results, elapsed_seconds=elapsed, module_count=len(selected_modules)))
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
        # Check for explicit --help / -h
        if args.help:
            print_help_with_banner(parser)
            sys.exit(0)

        # Check for list-modules dedicated command
        if args.target == "list-modules":
            render_modules_list(MODULE_REGISTRY)
            sys.exit(0)

        # Check if target is provided for scan
        elif args.target:
            ret = asyncio.run(
                execute_scan(
                    target=args.target,
                    module_filter=args.module,
                    output_file=args.output,
                    timeout=args.timeout
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
