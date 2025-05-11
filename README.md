# CyberSleuth

CyberSleuth is an AI-powered OSINT (Open Source Intelligence) tool that helps investigate and analyze cyber threats, infrastructure, and security configurations.

## Features

- Infrastructure Analysis
  - Favicon hash generation and analysis
  - DNS enumeration and analysis
  - WHOIS database investigation
  - Reverse DNS lookups
- Certificate Intelligence
  - SSL/TLS certificate analysis
  - Subdomain discovery
  - Certificate authority identification
  - Certificate tracking
- Web Analysis
  - URLScan.io integration
  - Historical domain tracking
  - Technology stack identification
- Threat Intelligence
  - Multi-source data correlation
  - Infrastructure mapping
  - Security issue identification

## Requirements

- Python 3.8+
- OpenAI API key
- Shodan API key (optional)
- URLScan.io API key (optional)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/Mar8x/cybersleuth.git
cd cybersleuth
```

2. Create and activate a virtual environment:
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up your API keys:
```bash
export OPENAI_API_KEY='your-openai-api-key'
export SHODAN_API_KEY='your-shodan-api-key'  # Optional
export URLSCAN_API_KEY='your-urlscan-api-key'  # Optional
```

## Configuration

### Model Selection

The tool uses OpenAI's GPT model for analysis. You can configure the model in two ways:

1. Environment Variable:
```bash
export OPENAI_MODEL='your-preferred-model'
```

2. Default Model:
If no model is specified in the environment, the tool will use a default model. See `agent.py` for the current default model configuration.

## Usage

Run the tool:
```bash
python cybersleuth.py
```

Follow the interactive prompts to:
1. Enter your investigation target
2. Choose analysis methods
3. Review findings
4. Export results

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

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

