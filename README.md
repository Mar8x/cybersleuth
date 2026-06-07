# CyberSleuth

[![Version](https://img.shields.io/badge/version-0.4.0-blue)](https://github.com/Mar8x/cybersleuth/releases)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![MCP](https://img.shields.io/badge/MCP-compatible-purple)](https://modelcontextprotocol.io/)
[![Claude](https://img.shields.io/badge/Claude-Desktop%20%7C%20Code-orange)](https://claude.ai)
[![PAI](https://img.shields.io/badge/PAI-integrated-red)](https://github.com/danielmiessler/Personal_AI_Infrastructure)
[![uv](https://img.shields.io/badge/uv-package%20manager-blueviolet)](https://docs.astral.sh/uv/)
[![Built with Claude](https://img.shields.io/badge/built%20with-Claude-black)](https://claude.ai)

CyberSleuth is an OSINT (Open Source Intelligence) tool that exposes 32 cyber-investigation capabilities as an MCP server. Connect it to Claude Desktop or Claude Code and use natural language to investigate infrastructure, domains, companies, people, tech stacks, privacy posture, LLM surfaces, and more.

## Features

- **Infrastructure Analysis** — favicon hash generation, DNS enumeration, WHOIS investigation, reverse DNS, AS intelligence with hosting/cloud detection, passive DNS via ip.thc.org (reverse-IP hostnames, reverse-CNAME, passive subdomains)
- **Certificate Intelligence** — SSL/TLS certificate history via CertSpotter + Censys (CT log aggregation), subdomain discovery, CA tracking
- **Security Contact Discovery** — security.txt lookup (RFC 9116): contact, policy, encryption key, expiry check
- **Web Analysis** — URLScan.io scanning and historical data, BuiltWith technology lookup (free API)
- **Threat Intelligence** — Shodan searches, VirusTotal domain/IP reports, infrastructure mapping, multi-source correlation
- **Tech-Stack Intelligence** — ATS discovery (Greenhouse, Lever, Ashby, Workable, Teamtailor, Personio + 6 more), job-posting keyword extraction, GitHub org recon (repos, dep files, CI workflows), Wayback Machine fallback, synthesis profile
- **LLM / AI Surface Recon** — passive fingerprinting of LLM-powered apps (provider, framework, model strings, leaked credentials, MCP exposure); benign chat probe; authorization-gated OWASP LLM Top 10:2025 probes
- **Privacy & Data Handling** — privacy policy discovery and OPP-115 classification; jurisdiction detection (GDPR/CCPA/LGPD/PIPL/PIPEDA) with compliance gap analysis; AI training clause detection; tracker scan (~30 entries) with enforcement-backed contradiction detection
- **Research & Web Search** — privacy-neutral web search (Brave), research-agent–optimised structured results (Tavily), AI-synthesised answers with citations (Perplexity); all optional, key-gated
- **People & Company OSINT** — people investigation methodology, jurisdiction data availability, CV claim verification, content character profiling

## Requirements

- Python 3.10+
- [uv](https://docs.astral.sh/uv/) (recommended) or pip

### API Keys

All keys are optional. Tools that require a missing key return a structured error with a signup link.

| Key | Enables | Notes |
|-----|---------|-------|
| `SHODAN_API_KEY` | `shodan_search`, `shodan_domain`, `shodan_scan` (active scan needs scan credits) | [shodan.io](https://shodan.io) |
| `URLSCAN_API_KEY` | `urlscan_history`, `urlscan_submit` | [urlscan.io](https://urlscan.io) |
| `VIRUSTOTAL_API_KEY` | `vt_domain_report`, `vt_ip_report` | Free tier: ~4 req/min. [virustotal.com](https://www.virustotal.com) |
| `BUILTWITH_API_KEY` | `builtwith_lookup` | Free at [builtwith.com/signup](https://builtwith.com/signup). Rate limit: 1 req/s |
| `BRAVE_API_KEY` | `web_search` | [api.search.brave.com](https://api.search.brave.com) |
| `TAVILY_API_KEY` | `research` | [tavily.com](https://tavily.com) |
| `PERPLEXITY_API_KEY` | `research_synthesis` | [perplexity.ai/api](https://www.perplexity.ai/api) |
| `CERTSPOTTER_API_KEY` | `certificate_info` | Optional — free tier works without it; key raises rate limit. [sslmate.com/certspotter](https://sslmate.com/certspotter/) |
| `CENSYS_API_ID` + `CENSYS_API_SECRET` | `certificate_info` | Secondary CT source. [search.censys.io](https://search.censys.io) |
| `GITHUB_TOKEN` | `github_recon`, `tech_stack` | Raises rate limit from 60 to 5000 req/h. [github.com/settings/tokens](https://github.com/settings/tokens) |

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
      "args": ["run", "--directory", "/absolute/path/to/cybersleuth", "cybersleuth"],
      "env": {
        "SHODAN_API_KEY": "your-shodan-api-key",
        "URLSCAN_API_KEY": "your-urlscan-api-key",
        "VIRUSTOTAL_API_KEY": "your-virustotal-api-key",
        "BUILTWITH_API_KEY": "your-builtwith-api-key",
        "BRAVE_API_KEY": "your-brave-api-key",
        "TAVILY_API_KEY": "your-tavily-api-key",
        "PERPLEXITY_API_KEY": "your-perplexity-api-key"
      }
    }
  }
}
```

### Claude Code

```bash
claude mcp add cybersleuth -- uv run --directory /absolute/path/to/cybersleuth cybersleuth
```

Set API keys in your MCP config or shell environment:

```bash
export SHODAN_API_KEY='your-shodan-api-key'
export URLSCAN_API_KEY='your-urlscan-api-key'
export VIRUSTOTAL_API_KEY='your-virustotal-api-key'
export BRAVE_API_KEY='your-brave-api-key'
export TAVILY_API_KEY='your-tavily-api-key'
export PERPLEXITY_API_KEY='your-perplexity-api-key'
```

### Skill File & Agent Instructions

Load `cybersleuth.md` as the system prompt or project instructions in your chat agent. It contains the CyberSleuth persona, investigation methodology, and example queries.

The same content is also exposed by the MCP server as resources:

| Resource | Description |
|----------|-------------|
| `cybersleuth://instructions` | Skill/agent instructions (persona, methodology, example queries) |
| `cybersleuth://reports` | Report generation guide (DDR structure, confidence framework, eisvogel/pandoc templates) |
| `cybersleuth://people-osint` | People OSINT methodology (jurisdiction guide, CV claim scorecard, character profiling) |
| `cybersleuth://company-ddr` | Company DDR workflow: 5-phase playbook producing a due diligence PDF |
| `cybersleuth://tech-stack-recon` | Tech-stack intelligence methodology: ATS discovery, job-posting extraction, GitHub recon |
| `cybersleuth://llm-recon` | LLM/AI surface recon methodology: passive signals, OWASP LLM Top 10:2025 mapping |
| `cybersleuth://privacy-analysis` | Privacy & data handling methodology: OPP-115, jurisdiction gap analysis, tracker risk DB |
| `cybersleuth://threat-surface` | Threat-surface deep-recon methodology: Shodan pivot chains (favicon/cert/org/asn/net), enumeration breadth, surface tagging |
| `cybersleuth://dns-twist` | DNS-twist methodology: fuzzers (homoglyph/typo/bitsquat/tld-swap/subdomain/combosquat), cloud default-naming (Azure/AWS/GCP/SaaS), cert-transparency clues, look-alike triage |

**Prompt:** `CyberSleuth system instructions` — load the instructions as an MCP prompt (for clients that support MCP prompts).

### Methodology Docs

The `docs/` directory contains standalone reference guides:

- `docs/ethics.md` — OSINT ethics and legal boundaries
- `docs/methodology.md` — intelligence cycle, confidence levels, quality gates
- `docs/domain-workflow.md` — step-by-step domain investigation phases
- `docs/company-workflow.md` — step-by-step company OSINT phases
- `docs/entity-workflow.md` — step-by-step entity/threat investigation phases
- `docs/company-ddr.md` — Company DDR playbook (also available as `cybersleuth://company-ddr`)
- `docs/tech-stack-recon.md` — Tech-stack intelligence methodology
- `docs/llm-recon.md` — LLM/AI surface reconnaissance methodology
- `docs/privacy-analysis.md` — Privacy & data handling analysis methodology
- `docs/threat-surface.md` — Threat-surface deep-recon methodology (also `cybersleuth://threat-surface`)
- `docs/dns-twist.md` — DNS-twist look-alike/permutation methodology (also `cybersleuth://dns-twist`)

## Available Tools

### Infrastructure

| Tool | Description |
|------|-------------|
| `whois_lookup` | WHOIS registration data for a domain or IP (RIR-aware for IPs, TLD fallback; optional `server=`) |
| `dns_records` | DNS enumeration (A, AAAA, MX, NS, TXT, SOA, CNAME, PTR, SRV, CAA) |
| `reverse_dns` | Reverse DNS lookup for an IP address |
| `thc_recon` | Passive DNS via ip.thc.org — domain: reverse-CNAME (who CNAMEs to it) + passive subdomains; IP: passive reverse-IP hostnames + ASN/org (fills gaps when live PTR is empty). No key; rate-limited ~0.5 req/s |
| `dns_twist` | Generate look-alike domain permutations (typosquat/homoglyph/bitsquat/tld-swap/subdomain) for a domain via dnstwist, resolve them + check AI-supplied `extra_permutations`, and return only registered/resolving hits with DNS/WHOIS properties. See `cybersleuth://dns-twist` |
| `as_intelligence` | ASN, AS org, country, and hosting/cloud classification for an IP or domain |

### Certificate & Web

| Tool | Description |
|------|-------------|
| `certificate_info` | SSL/TLS certificate history from CertSpotter (+ Censys if credentials set); subdomain discovery |
| `security_txt` | Fetch and parse security.txt for a domain (RFC 9116): contact, policy, encryption key, expiry |
| `email_auth` | Domain email-authentication posture: SPF, DMARC, DKIM parsing + gap analysis (no API key) |
| `favicon_hash` | Favicon hashes for Shodan infrastructure searches |
| `urlscan_history` | Historical URLScan.io scan data for a URL or domain |
| `urlscan_submit` | Submit a URL for live scanning on URLScan.io |
| `builtwith_lookup` | Technology groups and categories (BuiltWith Free API; 1 req/s) |

### Threat Intelligence

| Tool | Description |
|------|-------------|
| `shodan_search` | Search Shodan for internet-connected devices and services |
| `shodan_scan` | **Active** on-demand Shodan scan of IP(s)/netblock(s) — probes the target's ports (authorised targets only; costs scan credits). Returns a scan_id |
| `shodan_scan_status` | Poll an on-demand `shodan_scan` (SUBMITTING→QUEUE→PROCESSING→DONE); read results via `shodan_search ip:<addr>` |
| `vt_domain_report` | VirusTotal reputation and analysis stats for a domain |
| `vt_ip_report` | VirusTotal reputation and analysis stats for an IP address |
| `hudson_rock` | Check whether a domain appears in infostealer logs (Hudson Rock Cavalier; free, no API key) |

### Tech-Stack Intelligence

| Tool | Description |
|------|-------------|
| `career_sources` | Discover ATS platforms and career pages (Greenhouse, Lever, Ashby, Workable, Teamtailor, Personio + 6 more); Wayback Machine fallback |
| `job_postings` | Fetch job postings from an ATS board URL and extract tech keywords by category |
| `github_recon` | GitHub org recon: repos, languages, dep manifests, CI/CD tooling signals |
| `tech_stack` | Full tech-stack profile: orchestrates `career_sources` → `job_postings` → `github_recon`, merges signals with source attribution |

### LLM / AI Surface Recon

| Tool | Description |
|------|-------------|
| `llm_fingerprint` | Passive fingerprint: provider, framework, model strings, leaked credentials, MCP exposure, OWASP LLM Top 10:2025 findings |
| `llm_probe_public_chat` | Send one benign message to a public chat endpoint; detects model self-disclosure |
| `llm_security_probe` | **Authorization-gated.** OWASP LLM01/02/07 probe battery (requires `authorized=True` + `authorization_note`) |

### Privacy & Data Handling

| Tool | Description |
|------|-------------|
| `privacy_policy` | Discover and analyse privacy/ToS/cookie policy: jurisdiction detection, OPP-115 categories, AI training clause flags, compliance gap analysis |
| `tracker_scan` | Scan homepage for ~30 third-party trackers (Meta Pixel, GA4, Segment, Hotjar, FingerprintJS, etc.); enforcement-backed contradiction hints; context escalation (healthcare, finance, children) |

### Research & Web Search

| Tool | Description |
|------|-------------|
| `web_search` | Privacy-neutral web search via Brave — no filter bubbles. Best for reputation checks, entity lookups, news. Requires `BRAVE_API_KEY` |
| `research` | Research-agent–optimised search via Tavily — structured results + synthesised answer. Best for iterative investigation and multi-source corroboration. Requires `TAVILY_API_KEY` |
| `research_synthesis` | AI-synthesised answer with numbered citations via Perplexity. Best for business intel summaries, regulatory lookups, breach context. Requires `PERPLEXITY_API_KEY` |

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
│  │  server.py (MCP Server — 32 tools, 9 resources)        │  │
│  │  └── tools.py (OSINT + research functions)             │  │
│  └──────────────────────┬─────────────────────────────────┘  │
│                         │                                    │
│  ┌──────────────────────▼─────────────────────────────────┐  │
│  │  Environment Variables (all optional)                  │  │
│  │  SHODAN · URLSCAN · VIRUSTOTAL · BUILTWITH · BRAVE     │  │
│  │  TAVILY · PERPLEXITY · CERTSPOTTER · CENSYS · GITHUB   │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌──────────────────────────────────────────────────────────────┐
│  External APIs (HTTPS)                                       │
│  CertSpotter · Censys · Shodan · URLScan.io · BuiltWith ·    │
│  VirusTotal · Brave Search · Tavily · Perplexity ·           │
│  WHOIS · DNS · ip.thc.org · GitHub · IPinfo                  │
└──────────────────────────────────────────────────────────────┘
```

## Data Sources & Attribution

- Certificate data: [CertSpotter](https://sslmate.com/certspotter/) (primary) + [Censys](https://search.censys.io) (secondary)
- Network intelligence: [Shodan](https://shodan.io)
- URL scanning: [URLScan.io](https://urlscan.io)
- Technology lookup: [BuiltWith](https://builtwith.com) (Free API)
- Threat reputation: [VirusTotal](https://www.virustotal.com) (API v3)
- Web search: [Brave Search](https://api.search.brave.com)
- Research: [Tavily](https://tavily.com)
- AI synthesis: [Perplexity](https://www.perplexity.ai)
- DNS: Public DNS services
- Passive DNS / reverse-IP / CNAME: [ip.thc.org](https://ip.thc.org) (no key; rate-limited ~0.5 req/s)
- WHOIS: Public WHOIS servers (RIR- and TLD-aware)
- Ransomware victim listings: [ransomware.live](https://www.ransomware.live) (manual web fetch)

## Security & OPSEC

- API keys are stored as environment variables — never hardcoded
- All external API queries may be logged by the respective services
- Services track IP addresses and usage patterns
- Consider using approved proxies for sensitive research
- No persistent storage of investigation results
- Respect API rate limits

## License

MIT — see [LICENSE](LICENSE) for details.
