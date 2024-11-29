#!/usr/bin/env python
import os
from agent import Agent
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory

from tools import (
    # Online Service Operations
    # Favicon Analysis & Shodan
    get_favicon_hash,
    search_shodan,
    # URLScan Operations
    search_urlscan_history,
    scan_url,
    # Network Intelligence
    get_whois_info,
    get_dns_records,
    reverse_dns_lookup,
    get_certificate_info
)

# Verify required API keys are present
required_keys = ['SHODAN_API_KEY', 'URLSCAN_API_KEY', 'OPENAI_API_KEY']
missing_keys = [key for key in required_keys if not os.environ.get(key)]
if missing_keys:
    raise ValueError(f"Missing required API keys: {', '.join(missing_keys)}")

api_keys = {
    'shodan': os.environ.get('SHODAN_API_KEY'),
    'urlscan': os.environ.get('URLSCAN_API_KEY')
}

agent = Agent(
    name="CyberSleuth",
    personality="""I am an experienced cyber intelligence investigator specializing in OSINT techniques 
    and infrastructure analysis. 

    Core Capabilities:
    - Infrastructure Analysis:
        • Generate and analyze favicon hashes for infrastructure discovery
        • Perform comprehensive DNS enumeration and analysis
        • Investigate domain ownership through various WHOIS databases
        • Conduct reverse DNS lookups for network mapping

    - Certificate Intelligence:
        • Analyze SSL/TLS certificates from Certificate Transparency logs
        • Discover subdomains through certificate records
        • Identify certificate authorities and patterns
        • Track certificate issuance and expiration
        • Detect potential security misconfigurations
    - Web Analysis:
        • Scan and analyze websites using URLScan.io
        • Track historical changes and appearances of domains
        • Identify technology stacks and security configurations
    - Threat Intelligence:
        • Search and correlate data across multiple sources
        • Create detailed infrastructure maps
        • Identify potential security issues and misconfigurations
    Investigation Approach:
    - I start broad and narrow down based on findings
    - I correlate information across different sources
    - I provide context and explain the significance of findings
    - I suggest follow-up queries to deepen the investigation
    Report Generation:
    - I create clear, organized summaries of findings
    - I highlight significant discoveries and potential security implications
    - I provide actionable intelligence and recommendations
    - I can format findings for different audiences (technical/non-technical)
    
    if an  url is provided always assure there is the https protocol in the url. If the user says explicitly to disable
    ssl/tls verification, then the https protocol is not added to the url. Its also possible a user adds a port to the end. 
    You will always check the URL si confomant to the RFC 3986 standard. If the URL is not valid, you will inform the user.

    I'll always explain my reasoning and suggest next steps in the investigation. 
    I can adjust my analysis depth and technical detail based on your needs.""",
    tools={
        # Infrastructure Analysis
        'get_whois_info': get_whois_info,
        'get_dns_records': get_dns_records,
        'reverse_dns_lookup': reverse_dns_lookup,
        'get_certificate_info': get_certificate_info,
        # Asset Discovery
        'get_favicon_hash': get_favicon_hash,
        'search_shodan': search_shodan,
        # Web Analysis
        'search_urlscan_history': search_urlscan_history,
        'scan_url': scan_url
    },
    api_keys=api_keys
)

agent.create_thread()
print("""CyberSleuth - OSINT & Infrastructure Analysis Tool

Available Investigations:
- Infrastructure Analysis:
  • Favicon hash analysis
  • DNS enumeration (all record types)
  • WHOIS investigation (multiple registrars)
  • Reverse DNS mapping

- Certificate Intelligence:
  • SSL/TLS certificate history analysis
  • Certificate Transparency log monitoring
  • Subdomain discovery via certificates
  • Certificate authority tracking
  • Certificate configuration review

- Web Intelligence:
  • URL scanning and analysis
  • Historical site data
  • Technology stack identification
  • Security posture assessment

- Network Reconnaissance:
  • Shodan infrastructure search
  • Service enumeration
  • Security configuration analysis
  • Infrastructure relationship mapping

Investigation Commands Examples:
- "Analyze certificates for domain.com"
- "Find subdomains from certificates for domain.com"
- "Check recent certificate activity for domain.com"
- "Review certificate authorities for domain.com"

type 'exit' to quit.""")


# Create a history file in user's home directory
session = PromptSession(
    history=FileHistory('.cybersleuth_history'),
    auto_suggest=AutoSuggestFromHistory()
)

# Replace the current input loop:
while True:
    try:
        # Rich input with history and editing
        user_input = session.prompt(
            "\nYou: ",
            complete_while_typing=True,
        )

        if user_input.lower() == 'exit':
            print("Investigation session ended. All data has been saved.")
            break

        agent.add_message(user_input)
        response = agent.run_agent()
        print(f"CyberSleuth: {response}")
    except KeyboardInterrupt:
        continue
    except EOFError:
        break
