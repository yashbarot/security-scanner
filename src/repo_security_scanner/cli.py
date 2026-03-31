from __future__ import annotations

import argparse
import os
import sys
import textwrap

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from repo_security_scanner.models import Severity
from repo_security_scanner.scanner import SecurityScanner
from repo_security_scanner.vulndb.osv import OSVDatabase
from repo_security_scanner.vulndb.github_advisory import GitHubAdvisoryDatabase
from repo_security_scanner.reports.json_report import generate_json_report
from repo_security_scanner.reports.html_report import generate_html_report

SEVERITY_STYLES = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "bold bright_red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "dim",
    Severity.UNKNOWN: "dim",
}

SEVERITY_RANK = {
    "critical": 0, "high": 1, "medium": 2, "low": 3,
}

SOURCE_LABELS = {
    "cisa_kev": "CISA KEV",
    "pypi_registry": "PyPI Registry",
    "npm_registry": "npm Registry",
    "hackernews": "Hacker News",
    "github_issues": "GitHub Issues",
    "rss_bleepingcomputer": "Bleeping Computer",
    "rss_google_security": "Google Security Blog",
    "opencve": "OpenCVE",
    "docker_eol": "Docker EOL",
    "docker_unpinned": "Docker Unpinned",
    "security_releases_nodejs": "Node.js Security",
    "security_releases_cpython": "Python Security",
    "security_releases_django": "Django Security",
    "security_releases_rails": "Rails Security",
    "security_releases_golang": "Go Security",
    "security_releases_spring": "Spring Security",
}

HELP_TEXT = textwrap.dedent("""\
    repo-scan — Scan local repositories for dependency security vulnerabilities.

    Detects dependencies across 7 ecosystems (Python, Node.js, Java, Go, Ruby,
    Rust, PHP), queries free vulnerability databases (Google OSV, GitHub Advisory),
    and reports known CVEs with severity levels and fix recommendations.

    ─────────────────────────────────────────────────────────────────────────────
    USAGE
    ─────────────────────────────────────────────────────────────────────────────

      repo-scan [DIRECTORY] [OPTIONS]

    If no directory is given, the current directory (.) is scanned.

    ─────────────────────────────────────────────────────────────────────────────
    OPTIONS
    ─────────────────────────────────────────────────────────────────────────────

      DIRECTORY                  Path to the project to scan (default: .)

      -f, --format FORMAT        Output format. Choices: table, json, html
                                 Default: table

      -o, --output FILE          Write the report to a file instead of stdout.
                                 Works with all formats.

      -s, --severity LEVEL       Minimum severity level to display.
                                 Choices: critical, high, medium, low
                                 Default: low (show everything)

      --github-token TOKEN       GitHub personal access token for higher API
                                 rate limits. Also reads from GITHUB_TOKEN env
                                 var. Used for GitHub Advisory cross-reference
                                 and GitHub Issues early warning.

      --skip-crossref            Skip the GitHub Advisory Database cross-
                                 reference check. Faster scans, OSV-only.

      --early-warning            Enable early warning intelligence sources that
                                 scan the web for threats not yet in CVE
                                 databases. Adds: CISA KEV, Hacker News,
                                 GitHub Issues, RSS security blogs, and
                                 PyPI/npm registry health checks.

      --scan-depth LEVEL         How thorough the early warning scan should be.
                                 Choices: quick (default), full, deep
                                   quick — Capped: 30 HN, 20 GitHub Issues,
                                           40 registry checks (~30-60s)
                                   full  — No caps, checks all deps (~2-5 min)
                                   deep  — No caps + all optional sources
                                           (~5-10 min for large projects)

      --llm                      Generate AI-powered security analysis using
                                 Claude (default) or GPT. Requires API key.
      --llm-provider PROVIDER    LLM provider: anthropic (default) or openai.

      --clear-cache              Clear cached early warning data stored at
                                 ~/.cache/security-scanner/

      --no-color                 Disable colored terminal output.

      -h, --help                 Show this help message and exit.

    ─────────────────────────────────────────────────────────────────────────────
    EXAMPLES
    ─────────────────────────────────────────────────────────────────────────────

      Scan current directory:
        $ repo-scan .

      Scan a specific project:
        $ repo-scan /path/to/my-app

      Only show critical and high severity:
        $ repo-scan . -s high

      Export JSON report:
        $ repo-scan . --format json --output report.json

      Export HTML report:
        $ repo-scan . -f html -o security-report.html

      Enable early warning (CISA KEV, Hacker News, RSS, registry checks):
        $ repo-scan . --early-warning

      Early warning with GitHub token for better rate limits:
        $ export GITHUB_TOKEN=ghp_xxxxxxxxxxxx
        $ repo-scan . --early-warning

      Fast scan (OSV only, no cross-reference):
        $ repo-scan . --skip-crossref

      Clear early warning cache and re-scan:
        $ repo-scan . --early-warning --clear-cache

      Pipe JSON output into jq:
        $ repo-scan . -f json | jq '.results[] | .package'

      Use in CI (exit code 1 on critical/high):
        $ repo-scan . -s high && echo "Clean" || echo "Vulnerabilities found"

    ─────────────────────────────────────────────────────────────────────────────
    EXIT CODES
    ─────────────────────────────────────────────────────────────────────────────

      0    No critical or high severity vulnerabilities found.
      1    Critical or high severity vulnerabilities detected.
      2    Runtime error (invalid directory, network failure, etc.)

    ─────────────────────────────────────────────────────────────────────────────
    ENVIRONMENT VARIABLES (all optional — everything works without them)
    ─────────────────────────────────────────────────────────────────────────────

      GITHUB_TOKEN       Optional. GitHub personal access token. Increases
                         rate limits from 60/hr to 5,000/hr for GitHub
                         Advisory and GitHub Issues searches.
                         Not required — scans work fine without it.

      OPENCVE_USER       Optional. OpenCVE username. When set along with
      OPENCVE_PASS       OPENCVE_PASS, enables OpenCVE as an additional
                         vulnerability source during --early-warning scans.
                         Silently skipped if not set.

    ─────────────────────────────────────────────────────────────────────────────
    SUPPORTED ECOSYSTEMS
    ─────────────────────────────────────────────────────────────────────────────

      Python     requirements.txt, pyproject.toml, Pipfile.lock, poetry.lock
      Node.js    package.json, package-lock.json, yarn.lock, pnpm-lock.yaml, bun.lock
      Java       pom.xml, build.gradle, build.gradle.kts
      Go         go.mod
      Ruby       Gemfile, Gemfile.lock
      Rust       Cargo.toml, Cargo.lock
      PHP        composer.json, composer.lock

    ─────────────────────────────────────────────────────────────────────────────
    VULNERABILITY SOURCES
    ─────────────────────────────────────────────────────────────────────────────

      Default (always active):
        - Google OSV         Free, no auth, 30+ ecosystems
        - GitHub Advisory    Free, optional token for higher limits

      Early warning (--early-warning):
        - CISA KEV           Actively exploited vulnerabilities (US govt)
        - PyPI/npm Registry  Yanked or deprecated package versions
        - Hacker News        Security posts from last 7 days
        - GitHub Issues      Security issues filed against your packages
        - RSS Feeds          Bleeping Computer, Google Security Blog
        - OpenCVE            Optional, needs OPENCVE_USER/OPENCVE_PASS

    ─────────────────────────────────────────────────────────────────────────────
    MORE INFO
    ─────────────────────────────────────────────────────────────────────────────

      Documentation:  https://github.com/yashbarot/security-scanner
      Report issues:  https://github.com/yashbarot/security-scanner/issues
""")


class CustomHelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Custom formatter that shows our detailed help instead of argparse default."""
    pass


def main():
    # Handle schedule subcommand before argparse (backward compatible)
    if len(sys.argv) > 1 and sys.argv[1] == "schedule":
        return _handle_schedule(sys.argv[2:])

    parser = argparse.ArgumentParser(
        prog="repo-scan",
        description="Scan local repositories for dependency security vulnerabilities",
        formatter_class=CustomHelpFormatter,
        add_help=False,
    )
    parser.add_argument("directory", nargs="?", default=".", help=argparse.SUPPRESS)
    parser.add_argument("-f", "--format", choices=["table", "json", "html"], default="table", help=argparse.SUPPRESS)
    parser.add_argument("-o", "--output", help=argparse.SUPPRESS)
    parser.add_argument("-s", "--severity", choices=["critical", "high", "medium", "low"], default="low", help=argparse.SUPPRESS)
    parser.add_argument("--github-token", help=argparse.SUPPRESS)
    parser.add_argument("--skip-crossref", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--early-warning", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--scan-depth", choices=["quick", "full", "deep"], default="quick", help=argparse.SUPPRESS)
    parser.add_argument("--llm", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--llm-provider", choices=["anthropic", "openai"], default="anthropic", help=argparse.SUPPRESS)
    parser.add_argument("--clear-cache", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--no-color", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("-h", "--help", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()

    console = Console(no_color=args.no_color)

    # Custom help
    if args.help:
        console.print(HELP_TEXT, highlight=False)
        sys.exit(0)

    # Handle cache clearing
    if args.clear_cache:
        from repo_security_scanner.cache import FileCache
        FileCache().clear()
        console.print("[green]Cache cleared.[/green]")
        if not args.early_warning:
            sys.exit(0)

    # Setup vulnerability sources
    vuln_sources = [OSVDatabase()]
    if not args.skip_crossref:
        vuln_sources.append(GitHubAdvisoryDatabase(token=args.github_token))

    # Always-on sources: Docker image checks + official security release feeds
    from repo_security_scanner.cache import FileCache
    from repo_security_scanner.vulndb.docker_images import DockerImageDatabase
    from repo_security_scanner.vulndb.security_releases import SecurityReleasesDatabase
    _cache = FileCache()
    vuln_sources.append(DockerImageDatabase(cache=_cache))
    vuln_sources.append(SecurityReleasesDatabase(cache=_cache))

    # Early warning sources
    if args.early_warning:
        from repo_security_scanner.vulndb.cisa_kev import CISAKEVDatabase
        from repo_security_scanner.vulndb.registry_health import RegistryHealthDatabase
        from repo_security_scanner.vulndb.hackernews import HackerNewsDatabase
        from repo_security_scanner.vulndb.github_issues import GitHubIssuesDatabase
        from repo_security_scanner.vulndb.rss_feeds import RSSFeedDatabase
        from repo_security_scanner.vulndb.opencve import OpenCVEDatabase

        # Scan depth controls how many deps are checked per source
        # quick (default): capped for speed | full: no cap | deep: no cap + extra sources
        depth_caps = {
            "quick": {"hn": 30, "gh_issues": 20, "registry": 40},
            "full":  {"hn": 0, "gh_issues": 0, "registry": 0},   # 0 = no cap
            "deep":  {"hn": 0, "gh_issues": 0, "registry": 0},
        }
        caps = depth_caps.get(args.scan_depth, depth_caps["quick"])

        if args.scan_depth != "quick":
            _dep_count = "all"
            _time_note = "2-5 min" if args.scan_depth == "full" else "5-10 min"
            console.print(f"[dim]Scan depth: {args.scan_depth} — checking {_dep_count} dependencies per source (est. {_time_note})[/dim]")

        cache = _cache
        vuln_sources.extend([
            CISAKEVDatabase(cache=cache),
            RegistryHealthDatabase(cache=cache, max_deps=caps["registry"]),
            HackerNewsDatabase(cache=cache, max_deps=caps["hn"]),
            GitHubIssuesDatabase(token=args.github_token, cache=cache, max_deps=caps["gh_issues"]),
            RSSFeedDatabase(cache=cache),
        ])
        if os.environ.get("OPENCVE_USER"):
            vuln_sources.append(OpenCVEDatabase(cache=cache))

    scanner = SecurityScanner(vuln_sources=vuln_sources)

    # Run scan
    spinner_msg = "[bold blue]Scanning dependencies"
    if args.early_warning:
        spinner_msg += " + early warning sources"
    spinner_msg += "..."
    with console.status(spinner_msg, spinner="dots"):
        try:
            report = scanner.scan(args.directory)
        except ValueError as e:
            console.print(f"[red]Error:[/red] {e}")
            sys.exit(2)

    # LLM analysis (optional)
    llm_analysis = None
    if args.llm:
        from repo_security_scanner.llm import LLMAnalyzer
        analyzer = LLMAnalyzer(provider=args.llm_provider)
        if not analyzer.api_key:
            console.print("[yellow]Warning:[/yellow] No API key found. Set ANTHROPIC_API_KEY or OPENAI_API_KEY env var.")
        else:
            with console.status("[bold blue]Generating AI security analysis...", spinner="dots"):
                llm_analysis = analyzer.analyze(report)

    # Filter by minimum severity
    min_rank = SEVERITY_RANK.get(args.severity, 3)

    # Generate output
    if args.format == "json":
        output = generate_json_report(report, llm_analysis=llm_analysis)
        if args.output:
            _write_file(args.output, output, console)
        else:
            console.print(output)
    elif args.format == "html":
        output = generate_html_report(report, llm_analysis=llm_analysis)
        if args.output:
            _write_file(args.output, output, console)
            console.print(f"[green]HTML report written to {args.output}[/green]")
        else:
            console.print(output)
    else:
        _print_table_report(report, console, min_rank, args.early_warning)

    # LLM analysis panel (table mode)
    if llm_analysis and args.format == "table":
        console.print()
        console.print(Panel(llm_analysis, title="AI Security Analysis", border_style="bright_blue"))

    # Help hint after results
    _print_help_hint(console, args)

    # Exit code
    if report.has_critical_or_high:
        sys.exit(1)
    sys.exit(0)


def _print_help_hint(console: Console, args):
    """Show contextual tips after scan results."""
    hints = []
    if not args.early_warning:
        hints.append("Tip: Use [bold]--early-warning[/bold] to detect threats before they hit CVE databases")
    if not args.llm:
        hints.append("Tip: Use [bold]--llm[/bold] for AI-powered security analysis and fix recommendations")
    if args.format == "table" and not args.output:
        hints.append("Tip: Use [bold]-f json -o report.json[/bold] or [bold]-f html -o report.html[/bold] to export reports")
    if not args.github_token and not os.environ.get("GITHUB_TOKEN"):
        hints.append("Tip: Set [bold]GITHUB_TOKEN[/bold] env var for higher API rate limits")

    if hints:
        console.print()
        console.print("[dim]" + "  |  ".join(hints[:2]) + "[/dim]")
        console.print("[dim]Run [bold]repo-scan --help[/bold] for all options and examples[/dim]")


def _print_table_report(report, console: Console, min_rank: int, show_early_warning: bool = False):
    confirmed = report.confirmed_results
    signals = report.early_signals if show_early_warning else []
    confirmed_vuln_count = sum(len(r.vulnerabilities) for r in confirmed)

    # Summary panel
    if report.is_clean and not signals:
        console.print(Panel(
            "[bold green]No vulnerabilities found![/bold green]",
            title="Security Scan Complete",
            subtitle=f"{report.total_dependencies} dependencies scanned",
        ))
        return

    summary = Text()
    summary.append("Found ", style="bold")
    summary.append(f"{confirmed_vuln_count} confirmed vulnerabilities", style="bold red" if report.has_critical_or_high else "bold yellow")
    summary.append(f" in {len(report.vulnerable_dependencies)} of {report.total_dependencies} dependencies\n")
    summary.append(f"  Critical: {report.critical_count}", style="bold red")
    summary.append(f"  High: {report.high_count}", style="bold bright_red")
    summary.append(f"  Medium: {report.medium_count}", style="bold yellow")
    summary.append(f"  Low: {report.low_count}", style="dim")
    if signals:
        summary.append(f"\n  Early Warning Signals: {report.early_signal_count}", style="bold bright_magenta")

    console.print(Panel(summary, title="Security Scan Results"))
    console.print()

    # Confirmed vulnerability table
    if confirmed:
        console.print("[bold]Confirmed Vulnerabilities[/bold]")
        table = Table(show_header=True, header_style="bold", show_lines=True)
        table.add_column("Package", style="bold cyan", min_width=15)
        table.add_column("Version", min_width=8)
        table.add_column("Ecosystem", min_width=8)
        table.add_column("Severity", min_width=8)
        table.add_column("Vulnerability", min_width=20)
        table.add_column("Fix", min_width=10)

        for result in confirmed:
            for v in result.vulnerabilities:
                sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 3}.get(v.severity.value, 3)
                if sev_rank > min_rank:
                    continue

                style = SEVERITY_STYLES.get(v.severity, "")
                fix_text = v.fixed_version or "No fix yet"

                table.add_row(
                    result.dependency.name,
                    result.dependency.version,
                    result.dependency.ecosystem.value,
                    Text(v.severity.value, style=style),
                    f"{v.id}\n{v.summary[:80]}",
                    fix_text,
                )

        console.print(table)
        console.print()

    # Early Warning Signals table
    if signals:
        console.print("[bold bright_magenta]Early Warning Signals[/bold bright_magenta]")
        console.print("[dim]These are unconfirmed signals from web sources — investigate before acting.[/dim]")
        console.print()

        sig_table = Table(show_header=True, header_style="bold", show_lines=True)
        sig_table.add_column("Package", style="bold cyan", min_width=15)
        sig_table.add_column("Version", min_width=8)
        sig_table.add_column("Signal", min_width=10)
        sig_table.add_column("Source", min_width=15)
        sig_table.add_column("Details", min_width=25)
        sig_table.add_column("Link", min_width=10)

        for result in signals:
            for v in result.vulnerabilities:
                source_label = SOURCE_LABELS.get(v.source, v.source)
                signal_type = _signal_type(v)
                ref_link = v.references[0] if v.references else ""
                short_link = ref_link[:50] + "..." if len(ref_link) > 50 else ref_link

                sig_table.add_row(
                    result.dependency.name,
                    result.dependency.version,
                    Text(signal_type, style="bold bright_magenta"),
                    source_label,
                    v.summary[:80],
                    short_link,
                )

        console.print(sig_table)
        console.print()

    # Action items
    console.print("[bold]Action Items:[/bold]")
    action_count = 0
    for result in report.results:
        for v in result.vulnerabilities:
            if v.confidence == "confirmed" and v.severity in (Severity.CRITICAL, Severity.HIGH) and v.fixed_version:
                action_count += 1
                style = SEVERITY_STYLES.get(v.severity, "")
                console.print(
                    f"  [{style}]{v.severity.value}[/{style}] "
                    f"Upgrade [bold]{result.dependency.name}[/bold] to "
                    f"[green]{v.fixed_version}[/green] "
                    f"(fixes {v.id})"
                )

    # Early warning action items
    for result in signals:
        for v in result.vulnerabilities:
            if v.confidence == "high_signal":
                action_count += 1
                console.print(
                    f"  [bold bright_magenta]WARNING[/bold bright_magenta] "
                    f"[bold]{result.dependency.name}[/bold] {v.summary[:60]}"
                )

    if action_count == 0:
        console.print("  [dim]No actionable items found[/dim]")


def _signal_type(v) -> str:
    if "YANKED" in v.id:
        return "YANKED"
    elif "DEPRECATED" in v.id:
        return "DEPRECATED"
    elif v.source == "hackernews":
        return "HN MENTION"
    elif v.source == "github_issues":
        return "GH ISSUE"
    elif v.source.startswith("rss_"):
        return "NEWS"
    elif v.source == "cisa_kev":
        return "CISA KEV"
    elif v.source == "docker_eol":
        return "EOL IMAGE"
    elif v.source == "docker_unpinned":
        return "UNPINNED"
    elif v.source.startswith("security_releases_"):
        return "SEC RELEASE"
    return "SIGNAL"


def _handle_schedule(args_list):
    """Handle repo-scan schedule subcommands."""
    from repo_security_scanner.scheduler import ScheduleManager, ScheduleDaemon

    parser = argparse.ArgumentParser(prog="repo-scan schedule")
    sub = parser.add_subparsers(dest="action")

    add_p = sub.add_parser("add", help="Add a scheduled scan")
    add_p.add_argument("path", help="Directory to scan")
    add_p.add_argument("--cron", required=True, help='Cron expression (e.g. "0 8 * * *")')
    add_p.add_argument("--name", required=True, help="Unique name for this schedule")

    sub.add_parser("list", help="List all scheduled scans")

    rm_p = sub.add_parser("remove", help="Remove a scheduled scan")
    rm_p.add_argument("name", help="Schedule name to remove")

    sub.add_parser("run", help="Start the scheduled scan daemon")

    parsed = parser.parse_args(args_list)
    console = Console()
    manager = ScheduleManager()

    if parsed.action == "add":
        try:
            manager.add(parsed.path, parsed.cron, parsed.name)
            console.print(f"[green]Schedule '{parsed.name}' added.[/green]")
            console.print(f"  Path: {parsed.path}")
            console.print(f"  Cron: {parsed.cron}")
            console.print(f"\nRun [bold]repo-scan schedule run[/bold] to start the daemon.")
        except ValueError as e:
            console.print(f"[red]Error:[/red] {e}")
            sys.exit(2)
    elif parsed.action == "list":
        schedules = manager.list_schedules()
        if not schedules:
            console.print("[dim]No schedules configured. Use 'repo-scan schedule add' to create one.[/dim]")
            return
        table = Table(show_header=True, header_style="bold")
        table.add_column("Name", style="bold cyan")
        table.add_column("Path")
        table.add_column("Cron")
        table.add_column("Created")
        for s in schedules:
            table.add_row(s["name"], s["path"], s["cron"], s.get("created_at", ""))
        console.print(table)
    elif parsed.action == "remove":
        if manager.remove(parsed.name):
            console.print(f"[green]Schedule '{parsed.name}' removed.[/green]")
        else:
            console.print(f"[red]Schedule '{parsed.name}' not found.[/red]")
            sys.exit(2)
    elif parsed.action == "run":
        console.print("[bold blue]Starting scheduled scan daemon...[/bold blue]")
        console.print("[dim]Press Ctrl+C to stop.[/dim]")
        daemon = ScheduleDaemon(manager)
        daemon.run()
        console.print("\n[dim]Daemon stopped.[/dim]")
    else:
        parser.print_help()


def _write_file(path: str, content: str, console: Console):
    try:
        with open(path, "w") as f:
            f.write(content)
    except OSError as e:
        console.print(f"[red]Error writing to {path}:[/red] {e}")
        sys.exit(2)


if __name__ == "__main__":
    main()
