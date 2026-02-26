#!/usr/bin/env python
import os
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


if __name__ == "__main__":
    mcp.run()
