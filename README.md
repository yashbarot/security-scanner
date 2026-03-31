<div align="center">

# security-scanner

### Stop shipping vulnerabilities. Start scanning locally.

A fast, zero-config CLI tool that scans your project dependencies for known security vulnerabilities — across **7 ecosystems**, powered by **free public vulnerability databases**.

[![Python](https://img.shields.io/badge/Python-3.9+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Ecosystems](https://img.shields.io/badge/Ecosystems-7-blue?style=for-the-badge)](#supported-ecosystems)
[![Vuln Sources](https://img.shields.io/badge/Vuln%20Sources-8%20Free%20APIs-orange?style=for-the-badge)](#vulnerability-intelligence-sources)
[![Early Warning](https://img.shields.io/badge/Early%20Warning-CISA%20%7C%20HN%20%7C%20RSS-7c3aed?style=for-the-badge)](#early-warning-system)

---

**One command. Every dependency. Every known vulnerability.**

```bash
pip install git+https://github.com/yashbarot/security-scanner.git
repo-scan /path/to/your/project
```

</div>

---

## The Problem

Open-source dependencies are under constant attack — and most teams find out **too late**.

### Recent high-impact incidents that shook the ecosystem

| Year | Package | Ecosystem | What Happened | Impact |
|------|---------|-----------|---------------|--------|
| 2026 | **axios** | npm | SSRF + credential leak via crafted requests ([#10604](https://github.com/axios/axios/issues/10604)) | 60M+ weekly downloads affected |
| 2026 | **litellm** | PyPI | Supply chain compromise — malicious code injected ([#24512](https://github.com/BerriAI/litellm/issues/24512)) | AI/ML pipelines across enterprises |
| 2025 | **react** | npm | Pre-auth RCE in React Server Components via unsafe deserialization ([CVE-2025-55182](https://nvd.nist.gov/vuln/detail/CVE-2025-55182)) | CVSS 10.0, CISA KEV, actively exploited |
| 2024 | **xz-utils** | Linux | Backdoor injected via social engineering of maintainer ([CVE-2024-3094](https://nvd.nist.gov/vuln/detail/CVE-2024-3094)) | Nearly every Linux distro at risk |
| 2023 | **jsonwebtoken** | npm | JWT signature bypass vulnerability ([CVE-2022-23529](https://nvd.nist.gov/vuln/detail/CVE-2022-23529)) | 36M+ weekly downloads |
| 2021 | **log4j** | Maven | Remote code execution — Log4Shell ([CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)) | ~93% of enterprise cloud environments |

### Current bottlenecks teams face

```
  "We didn't know our dependency had a CVE until production was breached."
  "Our scanner is locked behind an enterprise paywall."
  "It only works with npm — we have Python and Go services too."
  "Setting it up took longer than fixing the actual vulnerabilities."
```

**The reality:**

- **New CVEs are published daily** — over 35,000 in 2025 alone ([source](https://nvd.nist.gov/))
- **70% of codebases** contain open-source vulnerabilities ([Synopsys OSSRA 2024](https://www.synopsys.com/software-integrity/resources/analyst-reports/open-source-security-risk-analysis.html))
- **Most teams rely on `npm audit` or `pip-audit`** — but these are **single-ecosystem** and miss cross-project risks
- **Enterprise scanners (Snyk, Sonatype, etc.)** are powerful but expensive and complex to set up
- **Developers don't scan proactively** because existing tools require too much config, accounts, or CI pipeline changes

---

## The Solution

`security-scanner` takes a different approach:

```
No accounts. No API keys. No config files. No paywalls.
Just point it at any project directory and get instant results.
```

<div align="center">

| What You Get | Why It Matters |
|:-------------|:---------------|
| **One command scans everything** | No separate tools per ecosystem |
| **16+ dependency file formats** | Catches what single-ecosystem scanners miss |
| **Free vulnerability intelligence** | OSV (Google) + GitHub Advisory — no enterprise license needed |
| **Actionable fix recommendations** | Tells you exactly which version to upgrade to |
| **CI-friendly exit codes** | Drop into any pipeline in 2 lines |
| **Offline-first dependency parsing** | No data leaves your machine until vuln lookup |

</div>

---

## Quick Start

### Install

```bash
# From GitHub (always installs latest)
pip install git+https://github.com/yashbarot/security-scanner.git

# From source
git clone https://github.com/yashbarot/security-scanner.git
cd security-scanner
pip install .
```

> **Tip**: For CI/production, you can pin to a specific version tag: `pip install git+...@v0.2.0`. Check [Releases](https://github.com/yashbarot/security-scanner/releases) for available versions.

### Scan

```bash
repo-scan .                              # scan current directory
repo-scan /path/to/project               # scan any local project
repo-scan . -s high                      # only critical & high severity
repo-scan . --format json -o report.json # export as JSON
repo-scan . --format html -o report.html # export as HTML report
repo-scan . --early-warning              # enable early warning (CISA, HN, RSS, registry)
repo-scan --help                         # full help with all options and examples
```

That's it. No setup, no accounts, no config files.

> After every scan, `repo-scan` shows contextual tips for features you haven't used yet.
> Run `repo-scan --help` anytime for the full reference with examples.

---

## Example Output

```
╭──────────────────────────── Security Scan Results ─────────────────────────────╮
│ Found 5 vulnerabilities in 3 of 42 dependencies                               │
│   Critical: 1  High: 2  Medium: 1  Low: 1                                     │
╰────────────────────────────────────────────────────────────────────────────────╯

┏━━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━┓
┃ Package       ┃ Version ┃ Ecosystem ┃ Severity ┃ Vulnerability               ┃ Fix     ┃
┡━━━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━┩
│ axios         │ 0.21.1  │ npm       │ CRITICAL │ CVE-2023-45857              │ 1.6.0   │
│               │         │           │          │ SSRF via XSRF-TOKEN header  │         │
├───────────────┼─────────┼───────────┼──────────┼─────────────────────────────┼─────────┤
│ flask         │ 2.2.0   │ PyPI      │ HIGH     │ CVE-2023-30861              │ 2.3.2   │
│               │         │           │          │ Cookie injection vuln       │         │
├───────────────┼─────────┼───────────┼──────────┼─────────────────────────────┼─────────┤
│ spring-core   │ 5.3.20  │ Maven     │ HIGH     │ CVE-2022-22965              │ 5.3.22  │
│               │         │           │          │ Spring4Shell RCE            │         │
├───────────────┼─────────┼───────────┼──────────┼─────────────────────────────┼─────────┤
│ lodash        │ 4.17.20 │ npm       │ MEDIUM   │ CVE-2021-23337              │ 4.17.21 │
│               │         │           │          │ Prototype pollution         │         │
└───────────────┴─────────┴───────────┴──────────┴─────────────────────────────┴─────────┘

Action Items:
  CRITICAL  Upgrade axios to 1.6.0 (fixes CVE-2023-45857)
  HIGH      Upgrade flask to 2.3.2 (fixes CVE-2023-30861)
  HIGH      Upgrade spring-core to 5.3.22 (fixes CVE-2022-22965)
```

### HTML Report

Running `repo-scan . --format html -o report.html` generates a clean, shareable report:

- Color-coded severity badges
- Summary dashboard with vulnerability counts
- Clickable CVE/GHSA references
- Suitable for sharing with team leads and security reviewers

---

## Supported Ecosystems

<div align="center">

| Ecosystem | Dependency Files | Lock Files |
|:---------:|:-----------------|:-----------|
| **Python** | `requirements.txt` `pyproject.toml` | `Pipfile.lock` `poetry.lock` |
| **Node.js** | `package.json` | `package-lock.json` `yarn.lock` `pnpm-lock.yaml` `bun.lock` |
| **Java** | `pom.xml` `build.gradle` `build.gradle.kts` | — |
| **Go** | `go.mod` | — |
| **Ruby** | `Gemfile` | `Gemfile.lock` |
| **Rust** | `Cargo.toml` | `Cargo.lock` |
| **PHP** | `composer.json` | `composer.lock` |

</div>

> **Lock files get priority.** When both a manifest and lock file exist, the scanner uses the lock file's exact versions for more accurate vulnerability matching.

---

## Vulnerability Intelligence Sources

The scanner queries **two free, public vulnerability databases** and cross-references findings for accuracy:

### Primary: Google OSV

[OSV (Open Source Vulnerabilities)](https://osv.dev/) is Google's open, distributed vulnerability database.

- **No authentication required**
- **No rate limits**
- **30+ ecosystems** covered
- Aggregates data from: GitHub Advisory, PyPI Advisory, RustSec, Go Vulnerability Database, and more
- Batch query API — scans hundreds of dependencies in a single request

### Secondary: GitHub Advisory Database

[GitHub Advisory Database](https://github.com/advisories) provides peer-reviewed security advisories.

- Works without authentication (60 requests/hour)
- Set `GITHUB_TOKEN` for 5,000 requests/hour
- Used to **cross-reference** critical and high severity findings from OSV

### How cross-referencing works

```
Dependencies ──> OSV Batch Query ──> All vulnerabilities found
                                          │
                            Critical/High findings
                                          │
                                          v
                              GitHub Advisory ──> Cross-reference
                                          │
                                          v
                              Merged, deduplicated results
                                     with fix versions
```

---

## Early Warning System

> **The problem with CVE databases**: Official sources (OSV, NVD, GitHub Advisory) lag behind real-world disclosures by **hours to weeks**. The [axios npm compromise](https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan), the [litellm supply chain attack](https://github.com/BerriAI/litellm/issues/24512), the xz-utils backdoor — these all surfaced on blogs, Twitter, and GitHub Issues long before any CVE was assigned.

`security-scanner` solves this with the `--early-warning` flag:

```bash
repo-scan . --early-warning
```

This activates **6 additional free intelligence sources** that scan the web for mentions of your specific dependencies:

| Source | What It Catches | Signal Type | Auth Required |
|--------|----------------|-------------|---------------|
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Government-verified actively exploited vulnerabilities | Confirmed | No |
| **PyPI / npm Registry** | Yanked or deprecated package versions | High Signal | No |
| [Hacker News](https://news.ycombinator.com) | Community-reported security threats (last 7 days) | Early Signal | No |
| [GitHub Issues](https://github.com) | Security issues filed against your dependencies | Early Signal | Optional |
| **Security Blog RSS** | Coverage from Bleeping Computer, Google Security Blog | Early Signal | No |
| [OpenCVE](https://www.opencve.io) | Curated CVE data (optional, needs free account) | Confirmed | Yes |

### How it works

```
Your Dependencies ──> Filter (skip generic names like "utils", "test")
                          │
          ┌───────────────┼───────────────┐
          v               v               v
     CISA KEV       Hacker News      Registry Health
     (confirmed)    (7-day window)   (yanked/deprecated)
          │               │               │
          v               v               v
     GitHub Issues   RSS Feeds       OpenCVE
     (scored 0-1)    (14-day window) (optional)
          │               │               │
          └───────┬───────┴───────┬───────┘
                  v               v
          Noise Filters     Relevance Scoring
          (word boundary,   (>= 0.5 threshold)
           keyword match)
                  │
                  v
          ┌─────────────────────────┐
          │  Two-Section Output     │
          │  ┌───────────────────┐  │
          │  │ Confirmed CVEs    │  │
          │  ├───────────────────┤  │
          │  │ Early Signals     │  │
          │  └───────────────────┘  │
          └─────────────────────────┘
```

### Example output with early warning

```
╭──────────────────────────── Security Scan Results ─────────────────────────────╮
│ Found 3 confirmed vulnerabilities in 2 of 15 dependencies                      │
│   Critical: 1  High: 1  Medium: 1  Low: 0                                     │
│   Early Warning Signals: 2                                                     │
╰────────────────────────────────────────────────────────────────────────────────╯

Confirmed Vulnerabilities
┏━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━┓
┃ Package     ┃ Version ┃ Ecosystem ┃ Severity ┃ Vulnerability            ┃ Fix    ┃
┡━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━┩
│ axios       │ 0.21.1  │ npm       │ CRITICAL │ CVE-2023-45857           │ 1.6.0  │
│             │         │           │          │ SSRF via XSRF-TOKEN      │        │
└─────────────┴─────────┴───────────┴──────────┴──────────────────────────┴────────┘

Early Warning Signals
These are unconfirmed signals from web sources — investigate before acting.

┏━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Package     ┃ Version ┃ Signal     ┃ Source        ┃ Details                   ┃
┡━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ litellm     │ 1.46.0  │ GH ISSUE   │ GitHub Issues │ Supply chain compromise   │
│ axios       │ 0.21.1  │ HN MENTION │ Hacker News   │ Axios compromised on npm  │
└─────────────┴─────────┴────────────┴───────────────┴───────────────────────────┘
```

### Noise reduction

Early warning sources are inherently noisy. The scanner uses multiple strategies to minimize false positives:

- **Generic name blocklist**: Skips web searches for packages named "utils", "core", "test", etc.
- **Minimum name length**: Ignores 1-2 character package names
- **Word boundary matching**: `axios` won't match "maxios" or "axiosify"
- **Security keyword co-occurrence**: Package name must appear alongside security terms (CVE, vulnerability, exploit, etc.)
- **Relevance scoring**: Each match is scored 0.0-1.0 based on recency, keyword density, community engagement, and name prominence. Only results scoring >= 0.5 are shown.

### Caching

Early warning results are cached locally at `~/.cache/security-scanner/` to avoid repeated network calls:

| Source | Cache Duration |
|--------|---------------|
| CISA KEV | 6 hours |
| RSS feeds | 2 hours |
| Registry health | 1 hour |
| Hacker News | 30 minutes |
| GitHub Issues | 30 minutes |

Clear the cache: `repo-scan . --clear-cache`

---

## CLI Reference

Run `repo-scan --help` for the full built-in reference. Here's an overview:

```
Usage: repo-scan [DIRECTORY] [OPTIONS]

Arguments:
  DIRECTORY                  Path to the project to scan (default: .)

Output Options:
  -f, --format FORMAT        Output format: table, json, html (default: table)
  -o, --output FILE          Write report to file instead of stdout
  -s, --severity LEVEL       Minimum severity: critical, high, medium, low (default: low)
      --no-color             Disable colored terminal output

Scan Options:
      --github-token TOKEN   GitHub token for higher rate limits (or GITHUB_TOKEN env var)
      --skip-crossref        Skip GitHub Advisory cross-reference (faster, OSV only)
      --early-warning        Enable early warning sources (CISA KEV, Hacker News,
                             GitHub Issues, RSS feeds, PyPI/npm registry health)
      --clear-cache          Clear cached early warning data

Help:
  -h, --help                 Show detailed help with all options, examples,
                             supported ecosystems, and environment variables
```

### Contextual Help

After every scan, `repo-scan` shows smart tips based on what you're doing:

```
Tip: Use --early-warning to detect threats before they hit CVE databases
Tip: Use -f json -o report.json or -f html -o report.html to export reports
Tip: Set GITHUB_TOKEN env var for higher API rate limits
Run repo-scan --help for all options and examples
```

### Environment Variables (all optional)

> None of these are required. Everything works out of the box with zero configuration.

| Variable | Required | Purpose | Without it |
|----------|----------|---------|------------|
| `GITHUB_TOKEN` | No | Higher API rate limits (60/hr -> 5,000/hr) | Works fine at 60 req/hr |
| `OPENCVE_USER` | No | OpenCVE username for `--early-warning` | OpenCVE silently skipped |
| `OPENCVE_PASS` | No | OpenCVE password for `--early-warning` | OpenCVE silently skipped |

### Exit Codes

| Code | Meaning | CI Behavior |
|:----:|---------|-------------|
| `0` | No critical/high vulnerabilities | Pipeline **passes** |
| `1` | Critical or high vulnerabilities found | Pipeline **fails** |
| `2` | Runtime error (bad path, network failure) | Pipeline **errors** |

---

## Use in CI/CD

Drop into any CI pipeline with two lines:

### GitHub Actions

```yaml
- name: Security scan
  run: |
    pip install git+https://github.com/yashbarot/security-scanner.git
    repo-scan . -s high
```

### GitLab CI

```yaml
security-scan:
  script:
    - pip install git+https://github.com/yashbarot/security-scanner.git
    - repo-scan . -s high
```

### Bitbucket Pipelines

```yaml
- step:
    name: Security scan
    script:
      - pip install git+https://github.com/yashbarot/security-scanner.git
      - repo-scan . -s high
```

> **Tip**: Pin to a specific version tag (e.g. `@v0.2.0`) in CI for reproducible builds.
> The exit code `1` on critical/high findings will automatically fail the pipeline step.

---

## How It Works

```
 Your Project Directory
         │
         v
 ┌───────────────────┐
 │  File Discovery    │  Walk directory tree, match against
 │                    │  16+ known dependency filenames
 └────────┬──────────┘
          │
          v
 ┌───────────────────┐
 │  Dependency        │  Parse each file format with
 │  Parsing           │  ecosystem-specific parsers
 └────────┬──────────┘
          │
          v
 ┌───────────────────┐
 │  Deduplication     │  Lock file versions override
 │                    │  manifest version ranges
 └────────┬──────────┘
          │
          v
 ┌───────────────────┐
 │  OSV Batch Query   │  Single API call for all deps
 │  (Primary)         │  — no rate limits, no auth
 └────────┬──────────┘
          │
          v
 ┌───────────────────┐
 │  GitHub Advisory   │  Cross-reference critical/high
 │  (Secondary)       │  findings for accuracy
 └────────┬──────────┘
          │
          v
 ┌───────────────────┐
 │  Report            │  Table, JSON, or HTML output
 │  Generation        │  with fix recommendations
 └───────────────────┘
```

---

## Comparison with Existing Tools

| Feature | security-scanner | npm audit | pip-audit | Snyk | Dependabot |
|---------|:--------------------:|:---------:|:---------:|:----:|:----------:|
| Multi-ecosystem | **7** | 1 | 1 | Many | Many |
| Free & open source | Yes | Yes | Yes | Freemium | Free (GitHub only) |
| No account required | **Yes** | Yes | Yes | No | No |
| No config required | **Yes** | Yes | Yes | No | No |
| Works locally | **Yes** | Yes | Yes | Yes | No |
| CI-friendly exit codes | **Yes** | Yes | Yes | Yes | N/A |
| Cross-references sources | **Yes** | No | No | Yes | No |
| Early warning (web intel) | **Yes** | No | No | No | No |
| JSON/HTML reports | **Yes** | JSON | JSON | Yes | No |
| Single command | **Yes** | Yes | Yes | No | No |

---

## Development

```bash
# Clone
git clone https://github.com/yashbarot/security-scanner.git
cd security-scanner

# Install in dev mode
pip install -e ".[dev]"

# Run tests
pytest

# Run tests with verbose output
pytest -v
```

### Project Structure

```
src/repo_security_scanner/
├── models.py                 # Core data models (Dependency, Vulnerability, ScanReport)
├── scanner.py                # Orchestrator — ties everything together
├── cli.py                    # CLI interface with rich terminal output
├── parsers/                  # Dependency file parsers (one per ecosystem)
│   ├── python.py             #   requirements.txt, pyproject.toml, Pipfile.lock, poetry.lock
│   ├── node.py               #   package.json, package-lock.json, yarn.lock, pnpm-lock.yaml, bun.lock
│   ├── java.py               #   pom.xml, build.gradle
│   ├── go.py                 #   go.mod
│   ├── ruby.py               #   Gemfile, Gemfile.lock
│   ├── rust.py               #   Cargo.toml, Cargo.lock
│   └── php.py                #   composer.json, composer.lock
├── vulndb/                   # Vulnerability database clients
│   ├── osv.py                #   Google OSV (primary)
│   └── github_advisory.py    #   GitHub Advisory (secondary)
└── reports/                  # Report generators
    ├── json_report.py        #   JSON export
    └── html_report.py        #   HTML export
```

### Adding a New Ecosystem Parser

1. Create `src/repo_security_scanner/parsers/your_ecosystem.py`
2. Define a class extending `DependencyParser`
3. Decorate with `@register_parser`
4. Add the ecosystem to the `Ecosystem` enum in `models.py`

```python
from repo_security_scanner.parsers.base import DependencyParser, register_parser
from repo_security_scanner.models import Dependency, Ecosystem

@register_parser
class YourParser(DependencyParser):
    filenames = ["your-lockfile.lock"]
    ecosystem = Ecosystem.YOUR_ECOSYSTEM

    def parse(self, content: str, filename: str) -> list[Dependency]:
        # Parse the file content and return dependencies
        ...
```

That's it. The registry auto-discovers it.

---

## Roadmap

### Completed
- [x] Early warning system (CISA KEV, Hacker News, GitHub Issues, RSS feeds, registry health)
- [x] File-based caching for early warning sources
- [x] Noise reduction with relevance scoring and blocklists

### Up Next
- [ ] SBOM export (CycloneDX 1.5 / SPDX 2.3)
- [ ] SARIF output for GitHub Code Scanning integration
- [ ] Config file (`security-scanner.toml`) with vulnerability suppression and expiry dates
- [ ] NVD enrichment for CVSS scores

### Planned
- [ ] Offline mode with downloadable OSV database
- [ ] Guided remediation (interactive fix suggestions)
- [ ] License scanning with allowlist-based compliance checks
- [ ] Monorepo support (scan subdirectories independently)
- [ ] Pre-commit hook integration
- [ ] `--watch` mode for continuous scanning during development
- [ ] Support for `.NET` (NuGet), `Dart` (pub), `Elixir` (mix), `Haskell` (cabal) ecosystems
- [ ] Container image scanning (Dockerfile dependency detection)
- [ ] Call graph analysis to detect if vulnerable code is actually reachable
- [ ] GitHub Action published to marketplace

---

## Contributing

Contributions are welcome! Whether it's a new ecosystem parser, a bug fix, or a documentation improvement.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Run the tests (`pytest`)
4. Commit your changes (`git commit -m 'Add amazing feature'`)
5. Push to the branch (`git push origin feature/amazing-feature`)
6. Open a Pull Request

---

## Requirements

- **Python** >= 3.9
- **Internet access** for querying vulnerability databases
- **No API keys required** (optional GitHub token for higher rate limits)

## License

MIT License. See [LICENSE](LICENSE) for details.

---

<div align="center">

**Built to solve a real problem — because knowing your vulnerabilities shouldn't cost a fortune.**

If this tool helped you, consider giving it a star!

</div>
