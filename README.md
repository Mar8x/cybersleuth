# CyberSleuth

CyberSleuth is an OSINT (Open Source Intelligence) tool that exposes cyber-investigation capabilities as an MCP server. Connect it to Claude Desktop or Claude Code and use natural language to investigate infrastructure, certificates, domains, and more.

## Features

- **Infrastructure Analysis** -- favicon hash generation, DNS enumeration, WHOIS investigation, reverse DNS, AS (Autonomous System) intelligence with hosting/cloud detection
- **Certificate Intelligence** -- SSL/TLS certificate history via crt.sh, subdomain discovery, CA tracking
- **Web Analysis** -- URLScan.io scanning and historical data, BuiltWith technology lookup (free API)
- **Threat Intelligence** -- Shodan searches, VirusTotal domain/IP reports, infrastructure mapping, multi-source correlation

## Requirements

- Python 3.10+
- [uv](https://docs.astral.sh/uv/) (recommended) or pip
- Shodan API key (optional, for `shodan_search`)
- URLScan.io API key (optional, for `urlscan_history` / `urlscan_submit`)
- BuiltWith API key (optional, for `builtwith_lookup`; free at [builtwith.com/signup](https://builtwith.com/signup), rate limit 1 req/s)
- VirusTotal API key (optional, for `vt_domain_report` / `vt_ip_report`; free tier rate-limited, e.g. 4 req/min)

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

The same content is also exposed by the MCP server:

- **Resource:** `cybersleuth://instructions` — read the skill/agent instructions via the MCP resource API.
- **Prompt:** "CyberSleuth system instructions" — use this MCP prompt to load the system instructions (clients that support MCP prompts can pull it from the server).

## Available Tools

| Tool | Description |
|---|---|
| `whois_lookup` | WHOIS registration data for a domain or IP (region-aware: RIR for IPs, TLD fallback for domains; optional server=) |
| `dns_records` | DNS enumeration (A, AAAA, MX, NS, TXT, SOA, CNAME, PTR, SRV, CAA) |
| `reverse_dns` | Reverse DNS lookup for an IP address |
| `as_intelligence` | ASN, AS org, country, and hosting/cloud classification for an IP or domain |
| `certificate_info` | SSL/TLS certificate history from crt.sh |
| `favicon_hash` | Favicon hashes for Shodan infrastructure searches |
| `shodan_search` | Search Shodan for internet-connected devices |
| `urlscan_history` | Historical URLScan.io scan data |
| `urlscan_submit` | Submit a URL for live scanning on URLScan.io |
| `builtwith_lookup` | Technology groups and categories for a domain (BuiltWith Free API; 1 req/s) |
| `vt_domain_report` | VirusTotal reputation and analysis stats for a domain (rate-limited on free tier) |
| `vt_ip_report` | VirusTotal reputation and analysis stats for an IP address (rate-limited on free tier) |

### Resources & Prompts

| Type | Identifier | Description |
|------|-------------|-------------|
| Resource | `cybersleuth://instructions` | Skill/agent instructions (persona, methodology, example queries) |
| Prompt | CyberSleuth system instructions | Load the same content as a prompt for use as system or project instructions |

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
│  crt.sh · Shodan · URLScan.io · BuiltWith · VirusTotal ·     │
│  WHOIS · DNS                                                 │
└──────────────────────────────────────────────────────────────┘
```

## Data Sources & Attribution

- Certificate data: [crt.sh](https://crt.sh) (Certificate Transparency logs)
- Network intelligence: [Shodan](https://shodan.io)
- URL scanning: [URLScan.io](https://urlscan.io)
- Technology lookup: [BuiltWith](https://builtwith.com) (Free API)
- DNS information: Public DNS services
- WHOIS data: Public WHOIS servers (RIR- and TLD-aware)
- Threat reputation: [VirusTotal](https://www.virustotal.com) (API v3)
- Ransomware victim listings: [ransomware.live](https://www.ransomware.live) (manual web fetch; no API yet)

## Security & OPSEC

- API keys are stored as environment variables, never sent to the LLM
- All external API queries may be logged by the respective services
- Services track IP addresses and usage patterns
- Consider using approved proxies for sensitive research
- No persistent storage of investigation results
- Respect API rate limits

## License

MIT -- see [LICENSE](LICENSE) for details.
