# CyberSleuth

A OSINT and infrastructure analysis tool leveraging multiple APIs to gather intelligence about domains, certificates, and web assets.

## Features

- Infrastructure Analysis (DNS, WHOIS, Reverse DNS)
- SSL/TLS Certificate Intelligence
- Favicon Hash Analysis
- Web Asset Analysis via URLScan.io
- Network Reconnaissance via Shodan

## Requirements

- Python 3.8+
- Required API keys:
  - OpenAI API key
  - Shodan API key
  - URLScan.io API key

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/cybersleuth.git
cd cybersleuth
```

2. Install dependencies:
```bash
pip install openai shodan requests beautifulsoup4 mmh3 python-whois dnspython prompt_toolkit
```

3. Set up environment variables:
```bash
export OPENAI_API_KEY='your-openai-key'
export SHODAN_API_KEY='your-shodan-key'
export URLSCAN_API_KEY='your-urlscan-key'
```

## Usage

Run the tool:
```bash
python cybersleuth.py
```

Example commands:
- `Analyze certificates for domain.com`
- `Find subdomains from certificates for domain.com`
- `Check recent certificate activity for domain.com`
- `Review certificate authorities for domain.com`

Type 'exit' to quit the program.

## Tool Modules

- `cybersleuth.py`: Main entry point and CLI interface
- `agent.py`: OpenAI GPT integration and command processing
- `tools.py`: Core OSINT and analysis functions

## Architecture & Security

```
┌─────────────────────────────────────────────────────────────────┐
│                        YOUR LOCAL MACHINE                       │
│  ┌─────────────┐    ┌──────────────┐    ┌────────────────────┐  │
│  │             │    │  CyberSleuth │    │ Environment Vars   │  │
│  │ User Input  ├───►│  (Main App)  │◄───┤ API Keys (.env)    │  │
│  │             │    │              │    │ - OpenAI           │  │
│  └─────────────┘    └──────┬───────┘    │ - Shodan           │  │
│                            │            │ - URLScan          │  │
│                            ▼            └────────────────────┘  │
│               ┌────────────────────────┐                        │
│               │   Agent (OpenAI GPT)   │                        │
│               └────────────┬───────────┘                        │
│                            │                                    │
│  ┌──────────────────────┐  │  ┌───────────────────────┐         │
│  │    Tools Module      │  │  │  Security Features    │         │
│  │ - Certificate Info   │◄ ┘  │                       │         │
│  │ - WHOIS              │     │ - Rate Limiting TBD   │         │
│  │ - DNS Records        │     │ - Error Handling      │         │
│  │ - Favicon Analysis   │     │ - Input Validation TBD│         │
│  └─────────┬────────────┘     └───────────────────────┘         │
└────────────┼────────────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────┐    ┌──────────────────┐
│  External APIs (HTTPS)  │    │ Security Notes   │
│  - crt.sh               │    │ - API Rate Limits│
│  - Shodan               │    │ - IP Tracking    │
│  - URLScan.io           │    │ - Query Logging  │
│  - WHOIS Servers        │    │ - Data Retention │
└─────────────────────────┘    └──────────────────┘
```



## Data Sources & Attribution
This tool uses the following services:
- Certificate data: crt.sh (Certificate Transparency logs)
- Network intelligence: Shodan (https://shodan.io)
- URL scanning: URLScan.io (https://urlscan.io)
- DNS information: Public DNS services
- WHOIS data: Public WHOIS servers

## Security & Compliance
### API Key Management
- Store API keys in environment variables or `.env` file
- Use separate API keys for development and production
- Rotate API keys regularly
- Never commit API keys to version control

### OpenAI API Usage
- Follow your organization's data handling policies
- Use OpenAI organization ID and project-specific API keys
- Consider data privacy implications when sending queries
- Review OpenAI's data usage policies: https://openai.com/policies/api-data-usage-policies

### OPSEC Considerations
1. Query Tracking:
   - All external API queries may be logged
   - Services track IP addresses and usage patterns
   - Favicon search will be done from cybersleuth's IP.
   - Consider using approved proxies for sensitive research for example with proxychains

2. Data Handling:
   - No persistent storage of results - only commands
   - Memory-only operation - verify with your openAI project settings
   - Sanitized error messages
   - Follow your organization's data retention policies

3. Rate Limiting:
   - Respect API rate limits
   - Implement backoff strategies
   - Monitor usage patterns

### Corporate Compliance
- Obtain necessary approvals before deployment
- Review your company's:
  - Data handling policies
  - API usage guidelines
  - Security requirements
  - Privacy impact assessments
  - Third-party service policies

