# CyberSleuth

[![Version](https://img.shields.io/badge/version-0.4.0-blue)](https://github.com/Mar8x/cybersleuth/releases)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![MCP](https://img.shields.io/badge/MCP-compatible-purple)](https://modelcontextprotocol.io/)
[![Claude](https://img.shields.io/badge/Claude-Desktop%20%7C%20Code-orange)](https://claude.ai)
[![PAI](https://img.shields.io/badge/PAI-integrated-red)](https://github.com/danielmiessler/Personal_AI_Infrastructure)
[![uv](https://img.shields.io/badge/uv-package%20manager-blueviolet)](https://docs.astral.sh/uv/)
[![Built with Claude](https://img.shields.io/badge/built%20with-Claude-black)](https://claude.ai)

CyberSleuth is an OSINT (Open Source Intelligence) tool that exposes cyber-investigation capabilities as an MCP server. Connect it to Claude Desktop or Claude Code and use natural language to investigate infrastructure, certificates, domains, and more.

## Features

- **Infrastructure Analysis** -- favicon hash generation, DNS enumeration, WHOIS investigation, reverse DNS, AS (Autonomous System) intelligence with hosting/cloud detection
- **Certificate Intelligence** -- SSL/TLS certificate history via CertSpotter + Censys (CT log aggregation), subdomain discovery, CA tracking
- **Security Contact Discovery** -- security.txt lookup (RFC 9116): contact, policy, encryption key, expiry check
- **Web Analysis** -- URLScan.io scanning and historical data, BuiltWith technology lookup (free API)
- **Threat Intelligence** -- Shodan searches, VirusTotal domain/IP reports, infrastructure mapping, multi-source correlation
- **Tech-Stack Intelligence** -- ATS discovery (Greenhouse, Lever, Ashby, Workable, Teamtailor, Personio, and 6 more), job-posting keyword extraction, GitHub org recon (repos, dep files, CI workflows), Wayback Machine fallback, synthesis profile
- **People & Company OSINT** -- people investigation methodology, jurisdiction data availability, CV claim verification, content character profiling

## Requirements

- Python 3.10+
- [uv](https://docs.astral.sh/uv/) (recommended) or pip
- `GITHUB_TOKEN` (optional, for `github_recon` / `tech_stack`; raises rate limit from 60 to 5000 req/h)
- `CERTSPOTTER_API_KEY` (optional, for `certificate_info`; free tier works without it, key raises rate limit)
- `CENSYS_API_ID` + `CENSYS_API_SECRET` (optional, for secondary CT source in `certificate_info`)
- `SHODAN_API_KEY` (optional, for `shodan_search`)
- `URLSCAN_API_KEY` (optional, for `urlscan_history` / `urlscan_submit`)
- `BUILTWITH_API_KEY` (optional, for `builtwith_lookup`; free at [builtwith.com/signup](https://builtwith.com/signup), rate limit 1 req/s)
- `VIRUSTOTAL_API_KEY` (optional, for `vt_domain_report` / `vt_ip_report`; free tier rate-limited, e.g. 4 req/min)

## Installation

```bash
git clone https://github.com/Mar8x/cybersleuth.git
cd cybersleuth
uv sync
```

Or with pip:

```bash
pip install -e .
```

## Setup

### Claude Desktop

Add to your Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "cybersleuth": {
      "command": "uv",
      "args": ["run", "--directory", "/absolute/path/to/cybersleuth", "server.py"],
      "env": {
        "SHODAN_API_KEY": "your-shodan-api-key",
        "URLSCAN_API_KEY": "your-urlscan-api-key",
        "BUILTWITH_API_KEY": "your-builtwith-api-key",
        "VIRUSTOTAL_API_KEY": "your-virustotal-api-key"
      }
    }
  }
}
```

### Claude Code

```bash
claude mcp add cybersleuth -- uv run --directory /absolute/path/to/cybersleuth server.py
```

Set the API keys in your shell environment:

```bash
export SHODAN_API_KEY='your-shodan-api-key'
export URLSCAN_API_KEY='your-urlscan-api-key'
export BUILTWITH_API_KEY='your-builtwith-api-key'
export VIRUSTOTAL_API_KEY='your-virustotal-api-key'
```

### Skill File & Agent Instructions

Load `cybersleuth.md` as the system prompt or project instructions in your chat agent. It contains the CyberSleuth persona, investigation methodology, and example queries.

The same content is also exposed by the MCP server as resources:

- **`cybersleuth://instructions`** — skill/agent instructions (persona, methodology, example queries)
- **`cybersleuth://reports`** — report generation guide (DDR structure, confidence framework, eisvogel/pandoc templates)
- **`cybersleuth://people-osint`** — people OSINT methodology (jurisdiction data availability, CV claim scorecard, content character profiling)
- **Prompt:** "CyberSleuth system instructions" — load the instructions as an MCP prompt (for clients that support MCP prompts)

### Methodology Docs

The `docs/` directory contains standalone reference guides stripped of agent-specific orchestration:

- `docs/ethics.md` — OSINT ethics and legal boundaries
- `docs/methodology.md` — intelligence cycle, confidence levels, quality gates
- `docs/domain-workflow.md` — step-by-step domain investigation phases
- `docs/company-workflow.md` — step-by-step company OSINT phases
- `docs/entity-workflow.md` — step-by-step entity/threat investigation phases
- `docs/company-ddr.md` — **Company DDR playbook**: full 5-phase due diligence workflow (domain discovery → infra recon → 12-agent parallel research fleet → claims verification → DDR PDF); PAI-portable, runs in any Claude Code session with CyberSleuth MCP installed; also available as `cybersleuth://company-ddr` resource

## Available Tools

| Tool | Description |
|---|---|
| `whois_lookup` | WHOIS registration data for a domain or IP (region-aware: RIR for IPs, TLD fallback for domains; optional server=) |
| `dns_records` | DNS enumeration (A, AAAA, MX, NS, TXT, SOA, CNAME, PTR, SRV, CAA) |
| `reverse_dns` | Reverse DNS lookup for an IP address |
| `as_intelligence` | ASN, AS org, country, and hosting/cloud classification for an IP or domain |
| `certificate_info` | SSL/TLS certificate history from CertSpotter (+ Censys if `CENSYS_API_ID`/`CENSYS_API_SECRET` set) |
| `security_txt` | Fetch and parse security.txt for a domain (RFC 9116) |
| `favicon_hash` | Favicon hashes for Shodan infrastructure searches |
| `shodan_search` | Search Shodan for internet-connected devices |
| `urlscan_history` | Historical URLScan.io scan data |
| `urlscan_submit` | Submit a URL for live scanning on URLScan.io |
| `builtwith_lookup` | Technology groups and categories for a domain (BuiltWith Free API; 1 req/s) |
| `vt_domain_report` | VirusTotal reputation and analysis stats for a domain (rate-limited on free tier) |
| `vt_ip_report` | VirusTotal reputation and analysis stats for an IP address (rate-limited on free tier) |
| `career_sources` | Discover ATS platforms and career pages for a domain (Greenhouse, Lever, Ashby, Workable, Teamtailor, Personio + 6 more); Wayback Machine fallback |
| `job_postings` | Fetch job postings from a known ATS and extract tech keywords by category; call `career_sources` first to get ats_type + handle |
| `github_recon` | GitHub org recon: repos, language distribution, dep manifests, CI/CD workflow tooling signals; set `GITHUB_TOKEN` for higher rate limit |
| `tech_stack` | Synthesise a full tech-stack profile for a domain: orchestrates career_sources → job_postings → github_recon, merges keywords with source attribution |

### Resources & Prompts

| Type | Identifier | Description |
|------|-------------|-------------|
| Resource | `cybersleuth://instructions` | Skill/agent instructions (persona, methodology, example queries) |
| Resource | `cybersleuth://reports` | Report generation guide (DDR structure, confidence framework, templates) |
| Resource | `cybersleuth://people-osint` | People OSINT methodology (jurisdiction guide, CV scorecard, character profiling) |
| Resource | `cybersleuth://company-ddr` | Company DDR workflow: 5-phase playbook for due diligence investigations producing a DDR PDF |
| Resource | `cybersleuth://tech-stack-recon` | Tech-stack intelligence methodology: ATS discovery, job-posting extraction, GitHub recon, LinkedIn dorks, Wayback fallback, confidence calibration |
| Prompt | CyberSleuth system instructions | Load instructions as a prompt for use as system or project instructions |

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  Claude Desktop / Claude Code                                │
│  ┌────────────────────┐  ┌─────────────────────────────────┐ │
│  │ cybersleuth.md     │  │ MCP Client                      │ │
│  │ (skill / persona)  │  │ (connects to server via stdio)  │ │
│  └────────────────────┘  └──────────────┬──────────────────┘ │
└─────────────────────────────────────────┼────────────────────┘
                                          │ MCP protocol
┌─────────────────────────────────────────┼────────────────────┐
│  YOUR LOCAL MACHINE                     │                    │
│  ┌──────────────────────────────────────▼─────────────────┐  │
│  │  server.py (MCP Server)                                │  │
│  │  └── tools.py (OSINT functions)                        │  │
│  └──────────────────────┬─────────────────────────────────┘  │
│                         │                                    │
│  ┌──────────────────────▼─────────────────────────────────┐  │
│  │  Environment Variables                                 │  │
│  │  SHODAN_API_KEY, URLSCAN_API_KEY, BUILTWITH_API_KEY,   │
│  │  VIRUSTOTAL_API_KEY                                    │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌──────────────────────────────────────────────────────────────┐
│  External APIs (HTTPS)                                       │
│  CertSpotter · Censys · Shodan · URLScan.io · BuiltWith ·    │
│  VirusTotal · WHOIS · DNS                                    │
└──────────────────────────────────────────────────────────────┘
```

## Data Sources & Attribution

- Certificate data: [CertSpotter](https://sslmate.com/certspotter/) (primary, free tier; set `CERTSPOTTER_API_KEY` for higher rate limits) and [Censys](https://search.censys.io) (secondary, requires `CENSYS_API_ID` + `CENSYS_API_SECRET`)
- Network intelligence: [Shodan](https://shodan.io)
- URL scanning: [URLScan.io](https://urlscan.io)
- Technology lookup: [BuiltWith](https://builtwith.com) (Free API)
- DNS information: Public DNS services
- WHOIS data: Public WHOIS servers (RIR- and TLD-aware)
- Threat reputation: [VirusTotal](https://www.virustotal.com) (API v3)
- Ransomware victim listings: [ransomware.live](https://www.ransomware.live) (manual web fetch; no API yet)

## Security & OPSEC

- API keys are stored as environment variables
- All external API queries may be logged by the respective services
- Services track IP addresses and usage patterns
- Consider using approved proxies for sensitive research
- No persistent storage of investigation results
- Respect API rate limits

## License

MIT -- see [LICENSE](LICENSE) for details.
