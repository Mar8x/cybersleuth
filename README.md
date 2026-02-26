# CyberSleuth

CyberSleuth is an OSINT (Open Source Intelligence) tool that exposes cyber-investigation capabilities as an MCP server. Connect it to Claude Desktop or Claude Code and use natural language to investigate infrastructure, certificates, domains, and more.

## Features

- **Infrastructure Analysis** -- favicon hash generation, DNS enumeration, WHOIS investigation, reverse DNS
- **Certificate Intelligence** -- SSL/TLS certificate history via crt.sh, subdomain discovery, CA tracking
- **Web Analysis** -- URLScan.io scanning and historical data
- **Threat Intelligence** -- Shodan searches, infrastructure mapping, multi-source correlation

## Requirements

- Python 3.10+
- [uv](https://docs.astral.sh/uv/) (recommended) or pip
- Shodan API key (optional, for `shodan_search`)
- URLScan.io API key (optional, for `urlscan_history` / `urlscan_submit`)

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
        "URLSCAN_API_KEY": "your-urlscan-api-key"
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
```

### Skill File

Load `cybersleuth.md` as the system prompt or project instructions in your chat agent. It contains the CyberSleuth persona, investigation methodology, and example queries.

## Available Tools

| Tool | Description |
|---|---|
| `whois_lookup` | WHOIS registration data for a domain or IP |
| `dns_records` | DNS enumeration (A, AAAA, MX, NS, TXT, SOA, CNAME, PTR, SRV, CAA) |
| `reverse_dns` | Reverse DNS lookup for an IP address |
| `certificate_info` | SSL/TLS certificate history from crt.sh |
| `favicon_hash` | Favicon hashes for Shodan infrastructure searches |
| `shodan_search` | Search Shodan for internet-connected devices |
| `urlscan_history` | Historical URLScan.io scan data |
| `urlscan_submit` | Submit a URL for live scanning on URLScan.io |

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  Claude Desktop / Claude Code                                │
│  ┌────────────────────┐  ┌─────────────────────────────────┐ │
│  │ cybersleuth.md      │  │ MCP Client                     │ │
│  │ (skill / persona)   │  │ (connects to server via stdio)  │ │
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
│  │  SHODAN_API_KEY, URLSCAN_API_KEY                       │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌──────────────────────────────────────────────────────────────┐
│  External APIs (HTTPS)                                       │
│  crt.sh · Shodan · URLScan.io · WHOIS servers · DNS          │
└──────────────────────────────────────────────────────────────┘
```

## Data Sources & Attribution

- Certificate data: [crt.sh](https://crt.sh) (Certificate Transparency logs)
- Network intelligence: [Shodan](https://shodan.io)
- URL scanning: [URLScan.io](https://urlscan.io)
- DNS information: Public DNS services
- WHOIS data: Public WHOIS servers

## Security & OPSEC

- API keys are stored as environment variables, never sent to the LLM
- All external API queries may be logged by the respective services
- Services track IP addresses and usage patterns
- Consider using approved proxies for sensitive research
- No persistent storage of investigation results
- Respect API rate limits

## License

MIT -- see [LICENSE](LICENSE) for details.
