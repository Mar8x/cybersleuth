#!/usr/bin/env python
import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from tools import (
    get_favicon_hash,
    search_shodan,
    get_shodan_domain,
    submit_shodan_scan,
    get_shodan_scan_status,
    search_urlscan_history,
    scan_url,
    get_whois_info,
    get_dns_records,
    reverse_dns_lookup,
    get_certificate_info,
    get_security_txt,
    get_builtwith_free,
    get_vt_domain_report,
    get_vt_ip_report,
    get_as_intelligence,
    find_career_sources,
    fetch_job_postings,
    github_org_recon,
    tech_stack_profile,
    llm_fingerprint as _llm_fingerprint_impl,
    llm_probe_public_chat as _llm_probe_public_chat_impl,
    llm_security_probe as _llm_security_probe_impl,
    get_privacy_policy,
    scan_trackers,
    search_brave,
    search_tavily,
    get_perplexity_synthesis,
    hudson_rock_domain,
    get_email_auth,
    dns_twist_impl,
    get_thc_recon,
    get_tor_nodes,
    get_ransomware_check,
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

# All tools below are synchronous (blocking I/O). FastMCP runs sync tools directly on the event loop,
# which serializes every concurrent request on a single process. Override `@mcp.tool()` so each sync tool
# is dispatched to a worker thread (anyio) — concurrent tool calls then run in parallel instead of head-of-
# line blocking each other. functools.wraps preserves the signature/name/doc so the MCP schema is identical.
import functools as _functools
import inspect as _inspect

import anyio as _anyio

_orig_tool = mcp.tool


def _threaded_tool(*targs, **tkwargs):
    register = _orig_tool(*targs, **tkwargs)

    def wrap(fn):
        if _inspect.iscoroutinefunction(fn):
            return register(fn)

        @_functools.wraps(fn)
        async def _async(*a, **k):
            return await _anyio.to_thread.run_sync(_functools.partial(fn, *a, **k))

        return register(_async)

    return wrap


mcp.tool = _threaded_tool

_SKILL_FILE = Path(__file__).resolve().parent / "cybersleuth.md"
_REPORTS_FILE = Path(__file__).resolve().parent / "reports.md"
_PEOPLE_FILE = Path(__file__).resolve().parent / "people-osint.md"
_COMPANY_DDR_FILE = Path(__file__).resolve().parent / "docs" / "company-ddr.md"
_TECH_STACK_FILE = Path(__file__).resolve().parent / "docs" / "tech-stack-recon.md"
_LLM_RECON_FILE = Path(__file__).resolve().parent / "docs" / "llm-recon.md"
_PRIVACY_FILE = Path(__file__).resolve().parent / "docs" / "privacy-analysis.md"
_THREAT_SURFACE_FILE = Path(__file__).resolve().parent / "docs" / "threat-surface.md"


def _get_skill_content() -> str:
    """Return CyberSleuth skill/agent instructions from cybersleuth.md."""
    return _SKILL_FILE.read_text(encoding="utf-8")


def _get_reports_content() -> str:
    """Return report generation guide from reports.md."""
    return _REPORTS_FILE.read_text(encoding="utf-8")


def _get_people_content() -> str:
    """Return people OSINT methodology from people-osint.md."""
    return _PEOPLE_FILE.read_text(encoding="utf-8")


def _get_company_ddr_content() -> str:
    """Return company DDR workflow from docs/company-ddr.md."""
    return _COMPANY_DDR_FILE.read_text(encoding="utf-8")


def _get_tech_stack_content() -> str:
    """Return tech-stack recon methodology from docs/tech-stack-recon.md."""
    return _TECH_STACK_FILE.read_text(encoding="utf-8")


def _get_llm_recon_content() -> str:
    """Return LLM reconnaissance methodology from docs/llm-recon.md."""
    return _LLM_RECON_FILE.read_text(encoding="utf-8")


def _get_privacy_content() -> str:
    """Return privacy-analysis methodology from docs/privacy-analysis.md."""
    return _PRIVACY_FILE.read_text(encoding="utf-8")


def _get_threat_surface_content() -> str:
    """Return threat-surface Shodan deep-recon methodology from docs/threat-surface.md."""
    return _THREAT_SURFACE_FILE.read_text(encoding="utf-8")


@mcp.resource("cybersleuth://instructions")
def instructions_resource() -> str:
    """CyberSleuth persona, methodology, and example queries (skill / agent instructions)."""
    return _get_skill_content()


@mcp.resource("cybersleuth://reports")
def reports_resource() -> str:
    """Report generation guide: types, structure, confidence framework, eisvogel templates, and formatting standards."""
    return _get_reports_content()


@mcp.resource("cybersleuth://people-osint")
def people_osint_resource() -> str:
    """People OSINT methodology: jurisdiction data availability, CV claim scorecard, content character profiling."""
    return _get_people_content()


@mcp.resource("cybersleuth://company-ddr")
def company_ddr_resource() -> str:
    """Company DDR workflow: 5-phase due diligence playbook (domain discovery, infra recon, 12-agent research fleet, claims verification, DDR PDF). PAI-portable — uses CyberSleuth MCP tools and Claude Code Agent calls."""
    return _get_company_ddr_content()


@mcp.resource("cybersleuth://tech-stack-recon")
def tech_stack_recon_resource() -> str:
    """Tech-stack intelligence methodology: ATS discovery, job-posting keyword extraction, GitHub org recon, LinkedIn dorks, Wayback fallback, confidence calibration."""
    return _get_tech_stack_content()


@mcp.resource("cybersleuth://llm-recon")
def llm_recon_resource() -> str:
    """LLM / AI surface reconnaissance methodology: passive fingerprint signals, OWASP LLM Top 10:2025 mapping, authorization tiers, research citations."""
    return _get_llm_recon_content()


@mcp.resource("cybersleuth://privacy-analysis")
def privacy_analysis_resource() -> str:
    """Privacy & data handling analysis methodology: OPP-115 practice categories, jurisdictional compliance (GDPR/CCPA/LGPD/PIPL/PIPEDA), AI training red-flag detection, tracker risk database, contradiction patterns."""
    return _get_privacy_content()


@mcp.resource("cybersleuth://threat-surface")
def threat_surface_resource() -> str:
    """Threat-surface deep-recon methodology: widen attack surface from a domain/IP/ASN/CIDR via Shodan pivot chains (favicon hash, cert CN/org, org, asn:, net:), deep enumeration of ports/products/vulns/exposed services, facet breadth, and surface tagging with depth/credit discipline."""
    return _get_threat_surface_content()


@mcp.resource("cybersleuth://dns-twist")
def dns_twist_resource() -> str:
    """DNS-twist methodology: fuzzers (homoglyph/typo/bitsquat/tld-swap/subdomain/combosquat), cloud
    default-naming patterns (Azure/AWS/GCP/SaaS), cert-transparency clues, and look-alike triage."""
    return (Path(__file__).resolve().parent / "docs" / "dns-twist.md").read_text(encoding="utf-8")


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
def thc_recon(target: str) -> dict:
    """Passive-DNS recon via ip.thc.org (CNAME, subdomains, reverse-IP).

    Complements live DNS with passive/historical data — especially useful when reverse_dns
    finds no PTR, or to pivot on CNAME relationships:
      - IP target  → ASN/org/geo + passive reverse-IP hostnames (domains that resolved here).
      - Domain target → reverse-CNAME (domains that CNAME to it) + passive subdomains.

    Slow and rate-limited (the service allows ~0.5 requests/sec) — requests are throttled to
    >= 2s apart and results are first-page only (totals are reported separately). No API key.

    Args:
        target: a domain or an IP address.
    """
    return get_thc_recon(target)


@mcp.tool()
def certificate_info(
    domain: str, include_expired: bool = False, wildcard: bool = True
) -> dict:
    """Get SSL/TLS certificate information from Certificate Transparency logs.

    Queries CertSpotter (primary, no key needed; set CERTSPOTTER_API_KEY for
    higher rate limits) and Censys (secondary, requires CENSYS_API_ID +
    CENSYS_API_SECRET). Results from both sources are merged and deduplicated.

    Args:
        domain: Domain to search for
        include_expired: Include expired certificates in results
        wildcard: Search for subdomain certificates as well
    """
    return get_certificate_info(domain, include_expired, wildcard)


@mcp.tool()
def security_txt(domain: str) -> dict:
    """Fetch and parse security.txt for a domain (RFC 9116).

    Checks /.well-known/security.txt (canonical) and /security.txt (legacy
    fallback) over HTTPS then HTTP. Returns parsed contact details, security
    policy URL, PGP encryption key link, expiry status, and all RFC 9116 fields.

    Args:
        domain: Domain to check (e.g. example.com)
    """
    return get_security_txt(domain)


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
def shodan_search(query: str, limit: int = 5, facets: str = "") -> dict:
    """Search Shodan for internet-connected devices and services.

    Returns matching hosts with IP, port, organization, country, domains,
    and aggregate statistics. Supports full Shodan query syntax including
    favicon hash, ASN, netblock, org, and SSL filters — ideal for widening
    a threat surface (see the cybersleuth://threat-surface playbook).

    Args:
        query: Shodan search query (e.g. "http.favicon.hash:-123456", "org:Example",
            "asn:AS13335", "net:185.12.0.0/22", "ssl.cert.subject.cn:example.com")
        limit: Maximum number of detailed matches to return. Use a larger value
            (e.g. 100-300) to deep-enumerate an ASN/netblock; >100 auto-pages and
            consumes one Shodan query credit per 100 results.
        facets: Optional comma-separated facet names for aggregate breakdowns across
            the FULL result set (e.g. "port,org,product,vuln,asn") — use for breadth.
    """
    api_key = os.environ.get("SHODAN_API_KEY")
    if not api_key:
        return {"error": "SHODAN_API_KEY environment variable is not set"}
    return search_shodan(api_key, query, limit, facets or None)


@mcp.tool()
def shodan_domain(domain: str, limit: int = 10) -> dict:
    """High-signal Shodan search for a DOMAIN — the union of hostname and TLS-cert queries.

    Runs `hostname:<domain>` and `ssl.cert.subject.cn:<domain>` and merges the results
    (de-duplicated by ip:port, each annotated with `matched_by`). This is the recommended
    entry point for a domain: do NOT search the resolved apex IP — for shared hosting / CDN /
    parked domains the apex belongs to the provider, returning provider noise and unrelated
    co-tenants while missing the org's real infrastructure. The cert query also catches hosts
    (e.g. domain-joined machines with exposed RDP) that the hostname query misses.

    For an IP / ASN / CIDR, use `shodan_search` with `ip:` / `asn:` / `net:` instead.

    Args:
        domain: Domain to search (e.g. example.com)
        limit: Max detailed matches per sub-query
    """
    api_key = os.environ.get("SHODAN_API_KEY")
    if not api_key:
        return {"error": "SHODAN_API_KEY environment variable is not set"}
    return get_shodan_domain(api_key, domain, limit)


@mcp.tool()
def shodan_scan(ips: str, force: bool = False) -> dict:
    """Submit an ON-DEMAND Shodan scan that ACTIVELY probes the given IP(s)/netblock(s).

    This is ACTIVE reconnaissance — Shodan connects to the target's ports, unlike the passive
    shodan_search/shodan_domain queries. Only use on infrastructure you are AUTHORISED to scan.
    Requires a Shodan plan with scan credits. Returns immediately with a scan_id; results land in
    Shodan's database asynchronously — poll with shodan_scan_status, then read them with
    shodan_search using `ip:<address>`.

    Args:
        ips: One IP/netblock or a comma-separated list (e.g. "1.2.3.4" or "1.2.3.0/24,5.6.7.8")
        force: Re-scan even if recently scanned (enterprise only; default False)
    """
    api_key = os.environ.get("SHODAN_API_KEY")
    if not api_key:
        return {"error": "SHODAN_API_KEY environment variable is not set"}
    return submit_shodan_scan(api_key, ips, force)


@mcp.tool()
def shodan_scan_status(scan_id: str) -> dict:
    """Poll the status of an on-demand Shodan scan submitted via shodan_scan.

    Status progresses SUBMITTING -> QUEUE -> PROCESSING -> DONE. Once DONE, read the fresh host
    data with shodan_search using `ip:<address>`.

    Args:
        scan_id: The scan id returned by shodan_scan
    """
    api_key = os.environ.get("SHODAN_API_KEY")
    if not api_key:
        return {"error": "SHODAN_API_KEY environment variable is not set"}
    return get_shodan_scan_status(api_key, scan_id)


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


@mcp.tool()
def career_sources(domain: str) -> dict:
    """Discover ATS platforms and career pages used by a company.

    Crawls common careers paths, detects ATS by URL patterns (Greenhouse,
    Lever, Ashby, Workable, Recruitee, SmartRecruiters, Personio, BambooHR,
    Teamtailor, Workday, iCIMS, Taleo), and falls back to Wayback Machine
    CDX if no live careers page is found. The ATS choice is itself a
    regional/company-stage signal.

    Methodology: cybersleuth://tech-stack-recon

    Args:
        domain: Company domain to check (e.g. example.com)
    """
    return find_career_sources(domain)


@mcp.tool()
def job_postings(board_url: str, max_jobs: int = 50) -> dict:
    """Fetch job postings from a discovered ATS board URL and extract tech-stack keywords.

    Use career_sources() first — it returns a ``board_url`` for each discovered
    ATS. Pass that URL here; the ATS platform and company handle are identified
    automatically from the URL.

    Supported ATS platforms with public JSON APIs: greenhouse, lever, ashby,
    workable, recruitee, smartrecruiters, personio, bamboohr.

    Returns per-job normalised records and aggregated keyword frequency counts
    across all postings, categorised by language, framework, cloud, DB, etc.

    Methodology: cybersleuth://tech-stack-recon

    Args:
        board_url: ATS board URL from career_sources() (e.g.
                   "https://boards.greenhouse.io/acmecorp")
        max_jobs: Maximum number of postings to fetch (default 50)
    """
    return fetch_job_postings(board_url, max_jobs)


@mcp.tool()
def github_recon(org: str, max_repos: int = 20) -> dict:
    """Enumerate a GitHub organisation's public repos for tech-stack intelligence.

    Returns org metadata, top repos by stars, aggregate language distribution,
    tech keywords from dependency manifests (package.json, requirements.txt,
    go.mod, Cargo.toml, etc.), and CI/CD tooling signals from GitHub Actions
    workflow files. Set GITHUB_TOKEN for 5000 req/h instead of 60.

    Methodology: cybersleuth://tech-stack-recon

    Args:
        org: GitHub organisation or user slug (e.g. "anthropics")
        max_repos: Number of repos to inspect for deps/workflows (default 20)
    """
    return github_org_recon(org, max_repos)


@mcp.tool()
def tech_stack(domain: str, github_org: str | None = None) -> dict:
    """Build a comprehensive tech-stack profile from job postings and GitHub.

    Orchestrates: career_sources → job_postings (all ATS with public APIs) →
    github_recon (if github_org provided). Merges tech keywords from all
    sources with frequency counts and source attribution. Higher frequency =
    multiple independent sources confirming the same technology.

    Methodology: cybersleuth://tech-stack-recon

    Args:
        domain: Company domain (e.g. example.com)
        github_org: GitHub organisation slug (optional; skipped if not provided)
    """
    return tech_stack_profile(domain, github_org)


@mcp.tool()
def llm_fingerprint(url: str) -> dict:
    """Passively fingerprint an LLM-powered application (no prompts sent).

    Inspects response headers, CSP, top-level JS bundles, and the error shape
    of common LLM API paths. Detects providers (OpenAI, Anthropic, Google,
    Mistral, Cohere, Llama, Ollama), frameworks (Vercel AI SDK, LangChain,
    LlamaIndex, MCP, LangSmith, Helicone), hardcoded model strings, and leaked
    client-side credentials. Surfaces OWASP LLM Top 10:2025 findings.

    Methodology: cybersleuth://llm-recon

    Args:
        url: Target URL (e.g. https://example.com/chat)
    """
    return _llm_fingerprint_impl(url)


@mcp.tool()
def llm_probe_public_chat(url: str, query: str = "Hello") -> dict:
    """Send one benign user-style message to a discovered public chat endpoint.

    Tries Vercel AI SDK, OpenAI-compatible, and Anthropic shapes in order.
    Returns the first reachable endpoint's response with model self-disclosure
    detection. Intended for endpoints the target intentionally exposes to
    anonymous users. Stop if rate-limited or auth-walled.

    Methodology: cybersleuth://llm-recon

    Args:
        url: Base URL of the target application
        query: Benign user message (default "Hello"). Keep non-adversarial.
    """
    return _llm_probe_public_chat_impl(url, query)


@mcp.tool()
def llm_security_probe(url: str, authorized: bool = False, authorization_note: str = "") -> dict:
    """AUTHORIZATION REQUIRED. Run a small OWASP-mapped probe battery against an LLM endpoint.

    Refuses without authorized=True AND non-empty authorization_note. Sends
    one query per probe (LLM07 system prompt extraction, LLM01 instruction
    isolation, LLM02 training data probe). Does not chain, retry, or attempt
    GCG suffixes. For deep red-teaming use garak / PyRIT / promptfoo under
    formal engagement.

    Methodology: cybersleuth://llm-recon

    Args:
        url: Target URL with a chat endpoint
        authorized: Must be True. Caller asserts written authorization to test.
        authorization_note: Free-text scope (engagement ID, asset, owner) — recorded for audit.
    """
    return _llm_security_probe_impl(url, authorized, authorization_note)


@mcp.tool()
def privacy_policy(domain: str) -> dict:
    """Discover and analyse privacy-related documents for a domain.

    Finds privacy policy, Terms of Service, and cookie policy URLs; fetches
    and cleans text; detects jurisdictions (GDPR, CCPA/CPRA, LGPD, PIPL,
    PIPEDA); maps text against OPP-115 data-practice categories (data
    collection, use, sharing, retention, security, user rights, etc.);
    flags AI/ML training data clauses; and produces per-jurisdiction
    compliance gap analysis (missing mandatory elements per Art. 13/14,
    CCPA 1798.135, etc.).

    Cross-reference with tracker_scan() to challenge stated policy against
    technical reality. Methodology: cybersleuth://privacy-analysis

    Args:
        domain: Target domain (e.g. example.com)
    """
    return get_privacy_policy(domain)


@mcp.tool()
def tracker_scan(domain: str) -> dict:
    """Scan a domain's homepage for third-party trackers and consent mechanisms.

    Checks HTML source against ~30 tracker entries (Meta Pixel, GA4, GTM,
    Segment, Mixpanel, Amplitude, Hotjar, FullStory, Microsoft Clarity,
    TikTok Pixel, LinkedIn Insight Tag, HubSpot, FingerprintJS, Criteo,
    Adobe Analytics, OneTrust, Cookiebot, and more).

    Detects high-risk context (healthcare, finance, children) and escalates
    risk accordingly (Meta Pixel + healthcare = HIPAA risk flag). Returns
    policy contradiction hints backed by enforcement precedents (CNIL GA4
    ruling, FTC/HHS Meta Pixel guidance, GDPR fingerprinting obligations).

    Methodology: cybersleuth://privacy-analysis

    Args:
        domain: Target domain (e.g. example.com)
    """
    return scan_trackers(domain)


@mcp.tool()
def web_search(query: str, count: int = 10) -> dict:
    """Search the web via Brave Search — privacy-neutral, unbiased index.

    Returns raw web results without personalisation or filter bubbles.
    Best for: reputation checks, entity lookups, news, source cross-referencing,
    and any search where objectivity matters. Results include title, URL,
    description, and age. Set BRAVE_API_KEY to enable.

    Args:
        query: Search query
        count: Number of results to return
    """
    api_key = os.environ.get("BRAVE_API_KEY")
    if not api_key:
        return {"error": "BRAVE_API_KEY environment variable is not set — get a key at https://api.search.brave.com/"}
    return search_brave(api_key, query, count)


@mcp.tool()
def research(query: str, search_depth: str = "basic", max_results: int = 5) -> dict:
    """Research-agent–optimised search via Tavily with structured results.

    Purpose-built for AI research workflows. Returns a synthesised answer plus
    ranked source excerpts. Best for: iterative investigation, competitive intel,
    multi-source corroboration, and follow-up queries. Use search_depth="advanced"
    for deeper coverage at the cost of latency. Set TAVILY_API_KEY to enable.

    Args:
        query: Research question or search query
        search_depth: "basic" (fast) or "advanced" (deeper, slower)
        max_results: Number of source results to return
    """
    api_key = os.environ.get("TAVILY_API_KEY")
    if not api_key:
        return {"error": "TAVILY_API_KEY environment variable is not set — get a key at https://tavily.com/"}
    return search_tavily(api_key, query, search_depth, max_results)


@mcp.tool()
def research_synthesis(query: str) -> dict:
    """AI-synthesised research answer with citations via Perplexity.

    Returns a concise synthesised answer drawn from live web sources, with
    numbered citations. Best for: business intel synthesis, ransomware/breach
    context, people OSINT background, regulatory lookups, and any query where
    you need a summarised answer rather than raw links. Set PERPLEXITY_API_KEY
    to enable.

    Args:
        query: Research question (can be detailed and contextual)
    """
    api_key = os.environ.get("PERPLEXITY_API_KEY")
    if not api_key:
        return {"error": "PERPLEXITY_API_KEY environment variable is not set — get a key at https://www.perplexity.ai/api"}
    return get_perplexity_synthesis(api_key, query)


@mcp.tool()
def hudson_rock(domain: str) -> dict:
    """Check if a domain appears in infostealer logs via Hudson Rock Cavalier.

    Free intelligence feed — no API key required. Returns counts of
    compromised employees, users, and third-party exposures plus sample
    URLs captured from stealer-infected machines.

    Args:
        domain: Target domain to check (e.g. example.com)
    """
    return hudson_rock_domain(domain)


@mcp.tool()
def tor_nodes(ip: str) -> dict:
    """Check whether an IP is a Tor relay or exit node (Tor Project's Onionoo API — free, no key).

    Returns is_tor_node, is_exit, is_relay, nickname, fingerprint, flags, first/last seen, and AS/country.
    Use this to confirm whether infrastructure (e.g. an IP in a target's netblock) is part of the Tor
    network — a Tor exit/relay on corporate-owned space is a notable finding.

    Args:
        ip: IP address to check.
    """
    return get_tor_nodes(ip)


@mcp.tool()
def ransomware_check(query: str) -> dict:
    """Check whether an organisation or domain is named as a victim on a ransomware leak site
    (ransomware.live — free, no key; aggregates ransomware-gang .onion leak sites).

    Returns is_victim, the ransomware groups, and victim records. It is a keyword search over victim
    names — treat a hit as a lead to verify, not a confirmed breach.

    Args:
        query: Company name or domain (e.g. "Acme Corp" or "acme.com").
    """
    return get_ransomware_check(query)


@mcp.tool()
def email_auth(domain: str) -> dict:
    """Check a domain's email authentication posture: SPF, DMARC, and DKIM.

    Parses the SPF (v=spf1) and DMARC (_dmarc) records, probes common DKIM
    selectors, and reports an overall posture (strong/partial/weak/none) plus
    a list of gaps (e.g. no SPF, DMARC p=none, no DKIM found).

    Args:
        domain: Domain to check (e.g. example.com)
    """
    return get_email_auth(domain)


@mcp.tool()
def dns_twist(domain: str, extra_permutations: list[str] | None = None, fuzzers: str | None = None,
              resolve: bool = True, whois: bool = False, limit: int = 150) -> dict:
    """Generate look-alike domain permutations (typosquat/homoglyph/bitsquat/tld-swap/subdomain) for a
    domain via dnstwist, resolve them, and also check any AI-supplied `extra_permutations`. Returns only
    positive (registered/resolving) hits with DNS/WHOIS properties, capped at `limit`.

    Args:
        domain: Target domain (e.g. paypal.com)
        extra_permutations: Optional custom variants to also resolve (e.g. cloud-naming / AI-suggested)
        fuzzers: Optional comma-separated dnstwist fuzzers (e.g. "homoglyph,tld-swap,addition"); all if omitted
        resolve: Only return variants that resolve / are registered (default True)
        whois: Also fetch WHOIS registrar/created (slower; default False)
        limit: Max hits to return (default 150)
    """
    return dns_twist_impl(domain, extra_permutations=extra_permutations, fuzzers=fuzzers,
                          resolve=resolve, whois=whois, limit=limit)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--transport", default="stdio", choices=["stdio", "sse", "streamable-http"])
    parser.add_argument("--port", type=int, default=5001)
    parser.add_argument("--host", default="0.0.0.0")
    args = parser.parse_args()

    if args.transport in ("sse", "streamable-http"):
        from mcp.server.transport_security import TransportSecuritySettings
        mcp.settings.host = args.host
        mcp.settings.port = args.port
        # Disable DNS rebinding protection for internal service-to-service calls
        mcp.settings.transport_security = TransportSecuritySettings(
            enable_dns_rebinding_protection=False
        )
        mcp.run(transport=args.transport)
    else:
        mcp.run()
