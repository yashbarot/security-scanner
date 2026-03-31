<div align="center">

# security-scanner

### Stop shipping vulnerabilities. Start scanning locally.

A fast, zero-config CLI tool that scans your project dependencies **and Dockerfiles** for known security vulnerabilities — across **8 ecosystems**, powered by **free public vulnerability databases**, with **AI-powered analysis** and **scheduled scanning**.

[![Python](https://img.shields.io/badge/Python-3.9+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Ecosystems](https://img.shields.io/badge/Ecosystems-8-blue?style=for-the-badge)](#supported-ecosystems)
[![Tests](https://img.shields.io/badge/Tests-129%20passing-brightgreen?style=for-the-badge)](#running-tests)
[![Vuln Sources](https://img.shields.io/badge/Vuln%20Sources-10%2B%20Free-orange?style=for-the-badge)](#vulnerability-intelligence-sources)
[![Early Warning](https://img.shields.io/badge/Early%20Warning-CISA%20%7C%20HN%20%7C%20RSS-7c3aed?style=for-the-badge)](#early-warning-system)
[![LLM Analysis](https://img.shields.io/badge/AI%20Analysis-Claude%20%7C%20GPT-2563eb?style=for-the-badge)](#ai-powered-security-analysis)

---

**One command. Every dependency. Every known vulnerability.**

```bash
pip install git+https://github.com/yashbarot/security-scanner.git
repo-scan /path/to/your/project
```

</div>

---

## What's New

### v0.3.1 — Severity Accuracy Fix

Most UNKNOWN severity entries are now resolved. Root causes fixed:

| Bug | Impact | Fix |
|-----|--------|-----|
| **MODERATE not mapped to MEDIUM** | GitHub Advisory uses "MODERATE" — our enum didn't recognize it, every MODERATE CVE showed UNKNOWN | `from_string()` now maps MODERATE -> MEDIUM |
| **Security feed flooding** | One Node.js digest created 973 duplicate UNKNOWN entries across all npm deps | Runtime feeds now create 1 entry per article, not 1 per dep |
| **Hydration fallback returned stubs** | Network failures produced empty data parsed as UNKNOWN | Returns empty instead of unparseable stubs |
| **Severity extraction crashes on None** | `from_string(None)` crashed silently, skipped valid data | Guarded with `isinstance(str)` checks |
| **GitHub Advisory only fetched critical,high** | All MEDIUM/LOW CVEs missed from cross-reference | Removed severity filter, fetches all |
| **Fix version from wrong package** | Multi-package CVE returned wrong package's fix | Now filters by package name |

### v0.3.0 — Major Features

| Feature | What It Does | Unique? |
|---------|-------------|---------|
| **Dockerfile scanning** | Detects EOL base images (node:14, python:3.8, ubuntu:18.04), unpinned `:latest` tags, docker-compose support | Integrated into same scan pipeline |
| **AI security analysis** | `--llm` flag sends findings to Claude/GPT for priority ranking, mitigation steps, and posture assessment | No other open-source scanner has this |
| **Scheduled scanning** | `repo-scan schedule add/run` — cron-based daemon scans projects on schedule, alerts on new critical vulns | Solves the "code hasn't been touched in months" problem |
| **Security release feeds** | Auto-monitors Node.js, Python, Django, Rails, Go, Spring official security release pages | **No other scanner does this** — catches patches before CVE databases update |
| **Configurable scan depth** | `--scan-depth quick\|full\|deep` controls speed vs thoroughness | Caps configurable per source |
| **Parallel source queries** | All vuln sources queried concurrently — 5+ min reduced to ~30-60s | ThreadPoolExecutor throughout |

---

## The Problem

Open-source dependencies are under constant attack — and most teams find out **too late**.

### Recent high-impact incidents

| Year | Package | Ecosystem | What Happened | Impact |
|------|---------|-----------|---------------|--------|
| 2026 | **axios** | npm | SSRF + credential leak via crafted requests ([#10604](https://github.com/axios/axios/issues/10604)) | 60M+ weekly downloads affected |
| 2026 | **litellm** | PyPI | Supply chain compromise — malicious code injected ([#24512](https://github.com/BerriAI/litellm/issues/24512)) | AI/ML pipelines across enterprises |
| 2025 | **react** | npm | Pre-auth RCE in React Server Components ([CVE-2025-55182](https://nvd.nist.gov/vuln/detail/CVE-2025-55182)) | CVSS 10.0, CISA KEV, actively exploited |
| 2024 | **xz-utils** | Linux | Backdoor injected via social engineering ([CVE-2024-3094](https://nvd.nist.gov/vuln/detail/CVE-2024-3094)) | Nearly every Linux distro at risk |
| 2023 | **jsonwebtoken** | npm | JWT signature bypass ([CVE-2022-23529](https://nvd.nist.gov/vuln/detail/CVE-2022-23529)) | 36M+ weekly downloads |
| 2021 | **log4j** | Maven | Remote code execution — Log4Shell ([CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)) | ~93% of enterprise cloud environments |

### Current bottlenecks

- **New CVEs are published daily** — over 35,000 in 2025 alone
- **70% of codebases** contain open-source vulnerabilities
- **Most scanners are single-ecosystem** — npm audit only checks npm, pip-audit only checks Python
- **Enterprise scanners** are powerful but expensive and complex
- **No one monitors official security release pages** (Node.js, Python, Django, etc.) proactively

---

## The Solution

```
No accounts. No API keys. No config files. No paywalls.
Point it at any project directory and get instant results.
```

<div align="center">

| What You Get | Why It Matters |
|:-------------|:---------------|
| **8 ecosystems + Docker in one command** | No separate tools per ecosystem |
| **20+ dependency file formats** | Catches what single-ecosystem scanners miss |
| **10+ free vulnerability sources** | OSV, GitHub Advisory, CISA KEV, HN, RSS, registries, security feeds |
| **AI-powered analysis** | LLM explains what to fix first and why |
| **Dockerfile scanning** | Catches EOL base images and unpinned tags |
| **Scheduled scanning** | Cron-based daemon alerts on new vulns in active projects |
| **Official security release monitoring** | Catches patches before CVE databases update |
| **CI-friendly exit codes** | Drop into any pipeline in 2 lines |

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

> **Tip**: For CI/production, pin to a specific version: `pip install git+...@v0.3.0`. See [Releases](https://github.com/yashbarot/security-scanner/releases).

### Update to Latest

```bash
cd security-scanner
git pull origin main
pip install .
```

To switch to a specific version:

```bash
git checkout v0.3.0
pip install .
```

Verify your installed version:

```bash
repo-scan --help
# or
python -c "import repo_security_scanner; print(repo_security_scanner.__version__)"
```

### Scan

```bash
repo-scan .                              # scan current directory
repo-scan /path/to/project               # scan any local project
repo-scan . -s high                      # only critical & high severity
repo-scan . --format json -o report.json # JSON report
repo-scan . --format html -o report.html # HTML report
repo-scan . --early-warning              # enable early warning sources (~30-60s)
repo-scan . --early-warning --scan-depth full  # check ALL deps, no caps (~2-5 min)
repo-scan . --llm                        # AI-powered security analysis
repo-scan --help                         # full help with all options
```

---

## Example Output

```
╭──────────────────────────── Security Scan Results ─────────────────────────────╮
│ Found 5 confirmed vulnerabilities in 3 of 42 dependencies                      │
│   Critical: 1  High: 2  Medium: 1  Low: 1                                     │
╰────────────────────────────────────────────────────────────────────────────────╯

Confirmed Vulnerabilities
┏━━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━┓
┃ Package       ┃ Version ┃ Ecosystem ┃ Severity ┃ Vulnerability               ┃ Fix     ┃
┡━━━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━┩
│ node          │ 14.21   │ Docker    │ HIGH     │ DOCKER-EOL-node-14.21       │ 22      │
│               │         │           │          │ Base image is end-of-life   │         │
├───────────────┼─────────┼───────────┼──────────┼─────────────────────────────┼─────────┤
│ axios         │ 1.6.0   │ npm       │ HIGH     │ GHSA-8hc4-vh64-cxmj        │ 1.8.2   │
│               │         │           │          │ SSRF + credential leak      │         │
├───────────────┼─────────┼───────────┼──────────┼─────────────────────────────┼─────────┤
│ flask         │ 2.2.0   │ PyPI      │ HIGH     │ CVE-2023-30861              │ 2.3.2   │
│               │         │           │          │ Cookie injection vuln       │         │
└───────────────┴─────────┴───────────┴──────────┴─────────────────────────────┴─────────┘

Action Items:
  HIGH      Upgrade node base image to 22 (fixes DOCKER-EOL-node-14.21)
  HIGH      Upgrade axios to 1.8.2 (fixes GHSA-8hc4-vh64-cxmj)
  HIGH      Upgrade flask to 2.3.2 (fixes CVE-2023-30861)
```

---

## AI-Powered Security Analysis

Add `--llm` to any scan for AI-powered vulnerability analysis:

```bash
repo-scan . --llm                        # uses Claude (default)
repo-scan . --llm --llm-provider openai  # uses GPT
```

The AI provides:
- **Priority ranking** of what to fix first with reasoning
- **Specific mitigation steps** for each critical/high finding
- **Security posture assessment** (Good / Fair / Poor / Critical)

```
╭──────────────────────── AI Security Analysis ────────────────────────╮
│ ## Priority Ranking                                                  │
│ 1. **axios 1.6.0** (HIGH) — Fix immediately. SSRF allows            │
│    credential leakage. Run: npm install axios@1.8.2                  │
│ 2. **node:14** (HIGH) — EOL since April 2023, no security           │
│    patches. Update Dockerfile FROM to node:22-alpine                 │
│                                                                      │
│ ## Security Posture: FAIR                                            │
│ 2 high-severity issues require immediate attention.                  │
│ No critical findings. Medium/low issues are acceptable short-term.   │
╰──────────────────────────────────────────────────────────────────────╯
```

**Requirements**: Set `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` environment variable. No API key = scan runs normally without AI analysis.

---

## Dockerfile & Docker Compose Scanning

The scanner **automatically detects** Dockerfiles and docker-compose files — no flags needed:

```dockerfile
# This gets flagged:
FROM node:14            # EOL — suggests upgrading to node:22
FROM python:3.8         # EOL — suggests upgrading to python:3.13
FROM ubuntu:18.04       # EOL — suggests upgrading to ubuntu:24.04
FROM nginx:latest       # Unpinned — suggests pinning to specific version
FROM nginx              # Unpinned — same warning
```

### Supported Docker files

| File | What's Detected |
|------|----------------|
| `Dockerfile` | FROM instructions — base image name, version, EOL status |
| `Dockerfile.prod` / `.dev` / `.staging` | Same as above |
| `docker-compose.yml` / `compose.yml` | `image:` directives in services |

### EOL base images detected

| Image | EOL Versions | Suggested Replacement |
|-------|-------------|----------------------|
| node | 10, 12, 14, 16 | 22 |
| python | 2.7, 3.6, 3.7, 3.8 | 3.13 |
| ubuntu | 14.04, 16.04, 18.04, 20.04 | 24.04 |
| alpine | 3.14, 3.15, 3.16, 3.17 | 3.20 |
| nginx | 1.18, 1.19, 1.20, 1.21 | 1.27 |
| golang | 1.18, 1.19, 1.20 | 1.22 |
| ruby | 2.6, 2.7, 3.0 | 3.3 |
| php | 7.4, 8.0 | 8.3 |
| postgres | 11, 12, 13 | 16 |
| mysql | 5.7 | 8.0 |
| redis | 5, 6 | 7 |
| debian | stretch, buster, jessie | bookworm |

---

## Official Security Release Feeds

**No other scanner does this.** The tool automatically monitors official security release pages from major runtimes and frameworks your project uses:

| Feed | When Active | What It Catches |
|------|------------|-----------------|
| [Node.js Vulnerabilities](https://nodejs.org/en/blog/vulnerability/) | Project has `package.json` | Node.js runtime security patches |
| [Python Security Blog](https://blog.python.org/) | Project has `requirements.txt` / `pyproject.toml` | CPython security advisories |
| [Django Security Releases](https://www.djangoproject.com/weblog/) | Project uses Django | Django framework patches |
| [Rails Security](https://rubyonrails.org/) | Project has `Gemfile` | Rails security patches |
| [Go Security](https://groups.google.com/g/golang-announce) | Project has `go.mod` | Go runtime announcements |
| [Spring Security](https://spring.io/blog) | Project uses Spring | Spring Framework CVEs |

These feeds are checked automatically (cached 4 hours). They announce patches **before CVE databases update** — giving you a head start.

---

## Scheduled Scanning

For projects that don't change often but still need monitoring (the "we developed it and no one touched it" problem):

```bash
# Add a project to scan daily at 8 AM
repo-scan schedule add /path/to/project --cron "0 8 * * *" --name "my-project"

# List all scheduled scans
repo-scan schedule list

# Remove a schedule
repo-scan schedule remove my-project

# Start the daemon (runs in foreground, Ctrl+C to stop)
repo-scan schedule run
```

### How it works

- Config stored at `~/.config/security-scanner/schedules.json`
- Results saved to `~/.config/security-scanner/results/`
- Alerts written to `~/.config/security-scanner/alerts.log` when new critical/high vulns are found
- Supports standard 5-field cron expressions (`* * * * *`)
- Each scan runs with OSV database (full hydration)

### Example cron expressions

| Expression | Schedule |
|-----------|----------|
| `0 8 * * *` | Every day at 8 AM |
| `0 8 * * 1` | Every Monday at 8 AM |
| `*/30 * * * *` | Every 30 minutes |
| `0 8,18 * * *` | Twice daily at 8 AM and 6 PM |
| `0 0 1 * *` | First day of every month |

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
| **Docker** | `Dockerfile` `Dockerfile.*` | `docker-compose.yml` `compose.yml` |

</div>

> **All 4 Node.js package managers**: npm, yarn, pnpm, and bun lock files are supported.
>
> **Lock files get priority.** When both a manifest and lock file exist, the scanner uses the lock file's exact versions for more accurate vulnerability matching.

---

## Early Warning System

> Official CVE databases lag behind real-world disclosures by **hours to weeks**. The [axios compromise](https://github.com/axios/axios/issues/10604), the [litellm supply chain attack](https://github.com/BerriAI/litellm/issues/24512), the xz-utils backdoor — all surfaced on blogs, Twitter, and GitHub Issues long before any CVE was assigned.

```bash
repo-scan . --early-warning                      # quick scan (~30-60s, capped)
repo-scan . --early-warning --scan-depth full     # all deps, no caps (~2-5 min)
repo-scan . --early-warning --scan-depth deep     # maximum thoroughness (~5-10 min)
```

### Scan Depth

Control how thorough the early warning scan is:

| Depth | HN Deps | GitHub Issues Deps | Registry Deps | Est. Time |
|-------|---------|-------------------|---------------|-----------|
| `quick` (default) | 30 | 20 | 40 | ~30-60s |
| `full` | all | all | all | ~2-5 min |
| `deep` | all | all | all | ~5-10 min |

> **Note**: On second run, cached results make all depths fast. Cache durations range from 30 min (HN/Issues) to 6 hours (CISA KEV).

This activates **6 additional free intelligence sources**:

| Source | What It Catches | Signal Type | Auth |
|--------|----------------|-------------|------|
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Government-verified actively exploited vulns | Confirmed | No |
| **PyPI / npm Registry** | Yanked or deprecated package versions | High Signal | No |
| [Hacker News](https://news.ycombinator.com) | Community-reported threats (7-day window) | Early Signal | No |
| [GitHub Issues](https://github.com) | Security issues filed against your deps | Early Signal | Optional |
| **Security Blog RSS** | Bleeping Computer, Google Security Blog | Early Signal | No |
| [OpenCVE](https://www.opencve.io) | Curated CVE data (optional) | Confirmed | Yes |

### Noise reduction

- **Generic name blocklist**: Skips "utils", "core", "test", etc.
- **Word boundary matching**: `axios` won't match "maxios"
- **Security keyword co-occurrence**: Name must appear alongside CVE/vulnerability/exploit terms
- **Relevance scoring**: 0.0-1.0 scale, only >= 0.5 shown

### Caching

| Source | Cache Duration |
|--------|---------------|
| CISA KEV | 6 hours |
| Security release feeds | 4 hours |
| RSS feeds | 2 hours |
| Registry health | 1 hour |
| Hacker News / GitHub Issues | 30 minutes |

---

## Vulnerability Intelligence Sources

All sources are **free** and require **no authentication** (tokens are optional for higher rate limits):

### Always Active (every scan)

| Source | What It Provides |
|--------|-----------------|
| [Google OSV](https://osv.dev/) | Primary vuln database — batch query, 30+ ecosystems, full hydration via `/v1/vulns/{id}` |
| [GitHub Advisory](https://github.com/advisories) | Cross-reference with version range matching |
| **Docker EOL Database** | Hardcoded EOL detection for 12 popular base images |
| **Official Security Feeds** | Node.js, Python, Django, Rails, Go, Spring release monitoring |

### Early Warning (`--early-warning` flag)

CISA KEV, Hacker News, GitHub Issues, RSS feeds, PyPI/npm registry health, OpenCVE

### AI Analysis (`--llm` flag)

Claude (Anthropic) or GPT (OpenAI) — priority ranking, mitigation steps, posture assessment

---

## CLI Reference

Run `repo-scan --help` for the full built-in reference.

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
      --early-warning        Enable early warning intelligence sources
      --scan-depth LEVEL     Scan thoroughness: quick (default), full, deep
      --llm                  Enable AI-powered security analysis (requires API key)
      --llm-provider         LLM provider: anthropic (default) or openai
      --clear-cache          Clear cached early warning data

Schedule Commands:
  repo-scan schedule add PATH --cron EXPR --name NAME
  repo-scan schedule list
  repo-scan schedule remove NAME
  repo-scan schedule run                   Start the cron daemon

Help:
  -h, --help                 Show detailed help with examples
```

### Environment Variables (all optional)

> None of these are required. Everything works out of the box with zero configuration.

| Variable | Purpose | Without it |
|----------|---------|------------|
| `GITHUB_TOKEN` | Higher API rate limits (60/hr -> 5,000/hr) | Works fine at 60 req/hr |
| `ANTHROPIC_API_KEY` | AI analysis via Claude (`--llm`) | LLM features skipped |
| `OPENAI_API_KEY` | AI analysis via GPT (`--llm --llm-provider openai`) | LLM features skipped |
| `OPENCVE_USER` / `OPENCVE_PASS` | OpenCVE source for `--early-warning` | OpenCVE silently skipped |

### Exit Codes

| Code | Meaning | CI Behavior |
|:----:|---------|-------------|
| `0` | No critical/high vulnerabilities | Pipeline **passes** |
| `1` | Critical or high vulnerabilities found | Pipeline **fails** |
| `2` | Runtime error | Pipeline **errors** |

---

## Use in CI/CD

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

> The exit code `1` on critical/high findings automatically fails the pipeline step.

---

## Comparison with Existing Tools

| Feature | security-scanner | npm audit | pip-audit | Snyk | Dependabot | osv-scanner |
|---------|:----:|:---------:|:---------:|:----:|:----------:|:-----------:|
| Multi-ecosystem | **8** | 1 | 1 | Many | Many | 11+ |
| Dockerfile scanning | **Yes** | No | No | No | No | Yes |
| Free & open source | **Yes** | Yes | Yes | Freemium | Free | Yes |
| No account required | **Yes** | Yes | Yes | No | No | Yes |
| AI-powered analysis | **Yes** | No | No | No | No | No |
| Configurable scan depth | **Yes** | No | No | No | No | No |
| Scheduled scanning | **Yes** | No | No | No | No | No |
| Early warning (web intel) | **Yes** | No | No | No | No | No |
| Security release feeds | **Yes** | No | No | No | No | No |
| Registry health checks | **Yes** | No | No | No | No | No |
| Cross-references sources | **Yes** | No | No | Yes | No | No |
| Version range matching | **Yes** | Yes | Yes | Yes | Yes | Yes |
| CVSS v3.1 parsing | **Yes** | No | No | Yes | No | Yes |
| JSON/HTML reports | **Yes** | JSON | JSON | Yes | No | Yes |

---

## How It Works

```
 Your Project Directory
         │
         v
 ┌───────────────────┐
 │  File Discovery    │  Walk tree, match 20+ dependency filenames
 │                    │  + Dockerfiles + docker-compose
 └────────┬──────────┘
          │
          v
 ┌───────────────────┐
 │  Parsing           │  8 ecosystem parsers + Docker parser
 │                    │  Lock file versions override manifests
 └────────┬──────────┘
          │
          v
 ┌───────────────────┐
 │  OSV Batch Query   │  Batch API → Parallel hydration via
 │  + Hydration       │  /v1/vulns/{id} (10 concurrent workers)
 └────────┬──────────┘
          │
          v
 ┌───────────────────┐
 │  Cross-Reference   │  GitHub Advisory (version range matching)
 │  + Docker EOL      │  + Docker image EOL/unpinned detection
 │  + Security Feeds  │  + Official runtime security releases
 └────────┬──────────┘
          │
          v
 ┌───────────────────┐
 │  AI Analysis       │  Optional: Claude/GPT priority ranking
 │  (--llm)           │  + mitigation steps + posture assessment
 └────────┬──────────┘
          │
          v
 ┌───────────────────┐
 │  Report            │  Table, JSON, or HTML output
 │  Generation        │  with fix recommendations
 └───────────────────┘
```

---

## Development

```bash
git clone https://github.com/yashbarot/security-scanner.git
cd security-scanner
pip install -e ".[dev]"
pytest          # 129 tests
pytest -v       # verbose
```

### Project Structure

```
src/repo_security_scanner/
├── models.py                 # Core data models (Dependency, Vulnerability, ScanReport)
├── scanner.py                # Orchestrator — walks dirs, parses, queries, reports
├── cli.py                    # CLI with rich output + schedule subcommand
├── llm.py                    # AI analysis (Claude + GPT)
├── scheduler.py              # Cron-based scheduled scanning daemon
├── cache.py                  # File-based cache for early warning sources
├── filters.py                # Noise reduction for web-based sources
├── version_utils.py          # Semver + PEP 440 version comparison
├── parsers/                  # Dependency file parsers
│   ├── python.py             #   requirements.txt, pyproject.toml, Pipfile.lock, poetry.lock
│   ├── node.py               #   package.json, package-lock.json, yarn.lock, pnpm-lock.yaml, bun.lock
│   ├── java.py               #   pom.xml, build.gradle
│   ├── go.py                 #   go.mod
│   ├── ruby.py               #   Gemfile, Gemfile.lock
│   ├── rust.py               #   Cargo.toml, Cargo.lock
│   ├── php.py                #   composer.json, composer.lock
│   └── docker.py             #   Dockerfile, docker-compose.yml
├── vulndb/                   # Vulnerability database clients
│   ├── osv.py                #   Google OSV (primary, with parallel hydration)
│   ├── github_advisory.py    #   GitHub Advisory (with version range matching)
│   ├── docker_images.py      #   Docker EOL/unpinned detection
│   ├── security_releases.py  #   Official runtime security release feeds
│   ├── cisa_kev.py           #   CISA Known Exploited Vulnerabilities
│   ├── registry_health.py    #   PyPI yanked / npm deprecated detection
│   ├── hackernews.py         #   Hacker News security mentions
│   ├── github_issues.py      #   GitHub Issues security search
│   ├── rss_feeds.py          #   Security blog RSS feeds
│   └── opencve.py            #   OpenCVE (optional)
└── reports/                  # Report generators
    ├── json_report.py        #   JSON export (with optional LLM analysis)
    └── html_report.py        #   HTML export (with optional LLM analysis)
```

### Adding a New Ecosystem Parser

```python
from repo_security_scanner.parsers.base import DependencyParser, register_parser
from repo_security_scanner.models import Dependency, Ecosystem

@register_parser
class YourParser(DependencyParser):
    filenames = ["your-lockfile.lock"]
    ecosystem = Ecosystem.YOUR_ECOSYSTEM

    def parse(self, content: str, filename: str) -> list[Dependency]:
        ...
```

The registry auto-discovers it. That's it.

---

## Roadmap

### Completed
- [x] 8 ecosystem support (Python, Node.js, Java, Go, Ruby, Rust, PHP, Docker)
- [x] Early warning system (CISA KEV, Hacker News, GitHub Issues, RSS, registry health)
- [x] Official security release feed monitoring (Node.js, Python, Django, Rails, Go, Spring)
- [x] Dockerfile + docker-compose scanning with EOL detection
- [x] AI-powered security analysis (Claude + GPT)
- [x] Scheduled scanning with cron daemon
- [x] OSV hydration with parallel `/v1/vulns/{id}` calls
- [x] CVSS v3.1 vector parsing from spec
- [x] Version range matching for GitHub Advisory
- [x] All 4 Node.js lockfiles (npm, yarn, pnpm, bun)
- [x] 129 tests including real-world vulnerability fixtures

### Up Next
- [ ] SBOM export (CycloneDX 1.5 / SPDX 2.3)
- [ ] SARIF output for GitHub Code Scanning integration
- [ ] Config file (`security-scanner.toml`) with vulnerability suppression and expiry dates
- [ ] NVD enrichment for CVSS scores

### Planned
- [ ] Offline mode with downloadable OSV database
- [ ] Guided remediation (interactive fix suggestions)
- [ ] License scanning with allowlist-based compliance
- [ ] Monorepo support (scan subdirectories independently)
- [ ] Pre-commit hook integration
- [ ] REST API mode (`--serve`) for code review tool integration
- [ ] EPSS scoring from FIRST.org
- [ ] Support for `.NET` (NuGet), `Dart` (pub), `Elixir` (mix), `Haskell` (cabal)
- [ ] GitHub Action published to marketplace
- [ ] Docker image for CI/CD pipelines

---

## Release History

| Version | Date | Highlights |
|---------|------|-----------|
| **v0.3.1** | 2026-03-31 | Severity accuracy fix — MODERATE mapping, 7 data pipeline bugs, feed flooding fix |
| **v0.3.0** | 2026-03-31 | Dockerfile scanning, AI analysis, scheduled scanning, security release feeds, `--scan-depth` |
| **v0.2.0** | 2026-03-31 | Critical OSV hydration fix, CVSS v3.1 parsing, version range matching, pnpm + bun |
| **v0.1.0** | 2026-03-31 | Initial release — 7 ecosystems, early warning system, CLI |

See [Releases](https://github.com/yashbarot/security-scanner/releases) for full changelogs.

---

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Run the tests (`pytest`)
4. Commit and push
5. Open a Pull Request

---

## Requirements

- **Python** >= 3.9
- **Internet access** for querying vulnerability databases
- **No API keys required** (optional for AI analysis and higher rate limits)

## License

MIT License. See [LICENSE](LICENSE) for details.

---

<div align="center">

**Built to solve a real problem — because knowing your vulnerabilities shouldn't cost a fortune.**

If this tool helped you, consider giving it a star!

</div>
