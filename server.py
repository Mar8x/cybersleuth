#!/usr/bin/env python
import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from tools import (
    get_favicon_hash,
    search_shodan,
    search_urlscan_history,
    scan_url,
    get_whois_info,
    get_dns_records,
    reverse_dns_lookup,
    get_certificate_info,
    get_builtwith_free,
    get_vt_domain_report,
    get_vt_ip_report,
    get_as_intelligence,
)

mcp = FastMCP(
    "cybersleuth",
    dependencies=[
        "requests",
        "mmh3",
        "python-whois",
        "dnspython",
        "shodan",
        "beautifulsoup4",
    ],
)

_SKILL_FILE = Path(__file__).resolve().parent / "cybersleuth.md"


def _get_skill_content() -> str:
    """Return CyberSleuth skill/agent instructions from cybersleuth.md."""
    return _SKILL_FILE.read_text(encoding="utf-8")


@mcp.resource("cybersleuth://instructions")
def instructions_resource() -> str:
    """CyberSleuth persona, methodology, and example queries (skill / agent instructions)."""
    return _get_skill_content()


@mcp.prompt(title="CyberSleuth system instructions")
def system_instructions_prompt() -> str:
    """Load the CyberSleuth system prompt: persona, investigation methodology, and example queries. Use as system or project instructions in your agent."""
    return _get_skill_content()


@mcp.tool()
def whois_lookup(domain: str, server: str | None = None) -> dict:
    """Get WHOIS registration information for a domain or IP.

    Queries WHOIS databases to retrieve registrar, creation/expiration dates,
    name servers, registrant info, and more. Optionally targets a specific
    WHOIS server (e.g. whois.arin.net, whois.ripe.net).

    Args:
        domain: Domain name or IP address to query
        server: Specific WHOIS server to use (optional)
    """
    return get_whois_info(domain, server)


@mcp.tool()
def dns_records(domain: str, record_types: list[str] | None = None) -> dict:
    """Enumerate DNS records for a domain.

    Queries all common record types (A, AAAA, MX, NS, TXT, SOA, CNAME, PTR,
    SRV, CAA) or a specified subset.

    Args:
        domain: Domain name to query
        record_types: Specific record types to query, e.g. ["A", "MX", "TXT"]
    """
    return get_dns_records(domain, record_types)


@mcp.tool()
def reverse_dns(ip: str) -> dict:
    """Perform reverse DNS lookup for an IP address.

    Resolves an IP address to its associated hostname(s) via PTR records.

    Args:
        ip: IP address to look up
    """
    return reverse_dns_lookup(ip)


@mcp.tool()
def certificate_info(
    domain: str, include_expired: bool = False, wildcard: bool = True
) -> dict:
    """Get SSL/TLS certificate information from Certificate Transparency logs.

    Queries crt.sh to find certificates issued for a domain, including
    subdomains, issuers, validity periods, and pattern analysis.

    Args:
        domain: Domain to search for
        include_expired: Include expired certificates in results
        wildcard: Include wildcard certificate matches
    """
    return get_certificate_info(domain, include_expired, wildcard)


@mcp.tool()
def favicon_hash(url: str, verify_ssl: bool = True) -> dict:
    """Generate favicon hashes for Shodan infrastructure searches.

    Finds all favicons for a website, computes MurmurHash3 hashes, and
    provides ready-to-use Shodan queries (http.favicon.hash:<hash>).

    Args:
        url: Website URL or domain
        verify_ssl: Whether to verify SSL certificates
    """
    return get_favicon_hash(url, verify_ssl)


@mcp.tool()
def shodan_search(query: str, limit: int = 5) -> dict:
    """Search Shodan for internet-connected devices and services.

    Returns matching hosts with IP, port, organization, country, domains,
    and aggregate statistics. Supports Shodan query syntax including
    favicon hash filters.

    Args:
        query: Shodan search query (e.g. "http.favicon.hash:-123456" or "org:Example")
        limit: Maximum number of detailed matches to return
    """
    api_key = os.environ.get("SHODAN_API_KEY")
    if not api_key:
        return {"error": "SHODAN_API_KEY environment variable is not set"}
    return search_shodan(api_key, query, limit)


@mcp.tool()
def urlscan_history(url: str, limit: int = 10) -> dict:
    """Search URLScan.io historical scan data for a URL or domain.

    Retrieves past scans including timestamps, screenshots, and
    maliciousness verdicts.

    Args:
        url: URL or domain to search
        limit: Maximum number of results to return
    """
    api_key = os.environ.get("URLSCAN_API_KEY")
    if not api_key:
        return {"error": "URLSCAN_API_KEY environment variable is not set"}
    return search_urlscan_history(url, api_key, limit)


@mcp.tool()
def urlscan_submit(url: str) -> dict:
    """Submit a URL for scanning on URLScan.io and retrieve results.

    Submits a public scan, waits for completion (up to ~3 minutes), and
    returns the analysis including domain, IP, server, maliciousness
    verdict, report URL, and screenshot.

    Args:
        url: URL to scan
    """
    api_key = os.environ.get("URLSCAN_API_KEY")
    if not api_key:
        return {"error": "URLSCAN_API_KEY environment variable is not set"}
    return scan_url(url, api_key)


@mcp.tool()
def builtwith_lookup(domain: str) -> dict:
    """Get technology groups and categories for a domain via BuiltWith Free API.

    Uses the BuiltWith Free API (no paid subscription). Returns technology
    groups and categories with live/dead counts and last-seen timestamps.
    A free API key from builtwith.com is required. Rate limit: 1 request per second.

    Args:
        domain: Domain to look up (e.g. example.com)
    """
    api_key = os.environ.get("BUILTWITH_API_KEY")
    return get_builtwith_free(domain, api_key)


@mcp.tool()
def as_intelligence(domain_or_ip: str) -> dict:
    """Get Autonomous System (AS) intelligence for an IP or domain.

    Resolves domain to IP if needed, then returns ASN, AS org, country, and
    flags for whether the AS is a known hosting/cloud provider. When not
    hosting, the AS org may be the actual organization (enterprise or ISP).

    Args:
        domain_or_ip: Domain name or IP address to look up
    """
    return get_as_intelligence(domain_or_ip)


@mcp.tool()
def vt_domain_report(domain: str) -> dict:
    """Get VirusTotal reputation and analysis stats for a domain.

    Returns last_analysis_stats (malicious, suspicious, harmless, undetected),
    reputation, and categories. Free tier is rate-limited (e.g. 4 requests/min).

    Args:
        domain: Domain to look up (e.g. example.com)
    """
    api_key = os.environ.get("VIRUSTOTAL_API_KEY")
    if not api_key:
        return {"error": "VIRUSTOTAL_API_KEY environment variable is not set"}
    return get_vt_domain_report(domain, api_key)


@mcp.tool()
def vt_ip_report(ip: str) -> dict:
    """Get VirusTotal reputation and analysis stats for an IP address.

    Returns last_analysis_stats, reputation, network, and country when available.
    Free tier is rate-limited (e.g. 4 requests/min).

    Args:
        ip: IP address to look up
    """
    api_key = os.environ.get("VIRUSTOTAL_API_KEY")
    if not api_key:
        return {"error": "VIRUSTOTAL_API_KEY environment variable is not set"}
    return get_vt_ip_report(ip, api_key)


if __name__ == "__main__":
    mcp.run()
