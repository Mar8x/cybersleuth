"""Source-provenance manifest for chain-of-evidence.

Publishes (a) an absolute build reference — the git commit + build date baked into the image — and (b) the
tool→external-source map, so a consumer (gathr) can record WHICH cybersleuth build + WHICH external provider
produced every finding. `source_ref()` is stamped onto every tool response via `tools._make_telemetry`; the
full manifest is exposed as the `cybersleuth://manifest` MCP resource.
"""
from __future__ import annotations

import datetime
import os
from importlib.metadata import PackageNotFoundError, version as _pkg_version

try:
    CYBERSLEUTH_VERSION = _pkg_version("cybersleuth")
except PackageNotFoundError:
    CYBERSLEUTH_VERSION = "0.4.0"

# Baked at image build time (Dockerfile ARG → ENV); "unknown" in a dev checkout.
GIT_COMMIT = os.environ.get("CYBERSLEUTH_GIT_COMMIT", "unknown")
BUILD_DATE = os.environ.get("CYBERSLEUTH_BUILD_DATE", "unknown")


def source_ref() -> dict:
    """The compact, immutable build reference stamped onto every tool response (under `_telemetry.source`)."""
    return {
        "cybersleuth_version": CYBERSLEUTH_VERSION,
        "cybersleuth_commit": GIT_COMMIT,
        "cybersleuth_build_date": BUILD_DATE,
        "retrieved_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }


def _p(name: str, url: str, key: bool = False) -> dict:
    return {"provider": name, "url": url, "requires_key": key}


# Tool (MCP name) → {category, providers[]}. The single source of truth for "where did this come from".
# Providers list the external data source(s) a tool draws on; `requires_key` flags metered/keyed providers.
SOURCES: dict[str, dict] = {
    # Infrastructure
    "dns_records":        {"category": "infrastructure", "providers": [_p("Public DNS", "dns://resolver")]},
    "reverse_dns":        {"category": "infrastructure", "providers": [_p("Public DNS (PTR)", "dns://resolver")]},
    "whois_lookup":       {"category": "infrastructure", "providers": [_p("Public WHOIS (RIR/TLD)", "whois://")]},
    "as_intelligence":    {"category": "infrastructure", "providers": [_p("ip-api.com", "http://ip-api.com")]},
    "thc_recon":          {"category": "infrastructure", "providers": [_p("ip.thc.org (passive DNS)", "https://ip.thc.org")]},
    "email_auth":         {"category": "infrastructure", "providers": [_p("Public DNS (SPF/DMARC/DKIM)", "dns://resolver")]},
    "dns_twist":          {"category": "infrastructure", "providers": [_p("dnstwist (local)", "local://dnstwist"), _p("Public DNS", "dns://resolver")]},
    # Certificate & web
    "certificate_info":   {"category": "certificate", "providers": [_p("CertSpotter", "https://api.certspotter.com", True), _p("Censys", "https://search.censys.io", True), _p("crt.sh", "https://crt.sh")]},
    "security_txt":       {"category": "web", "providers": [_p("Target host (/.well-known/security.txt)", "https://")]},
    "favicon_hash":       {"category": "web", "providers": [_p("Target host (favicon mmh3)", "https://")]},
    "urlscan_history":    {"category": "web", "providers": [_p("URLScan.io", "https://urlscan.io", True)]},
    "urlscan_submit":     {"category": "web", "providers": [_p("URLScan.io", "https://urlscan.io", True)]},
    # Threat intelligence
    "shodan_search":      {"category": "threat-intel", "providers": [_p("Shodan", "https://api.shodan.io", True)]},
    "shodan_domain":      {"category": "threat-intel", "providers": [_p("Shodan", "https://api.shodan.io", True)]},
    "shodan_scan":        {"category": "threat-intel", "providers": [_p("Shodan (active on-demand scan)", "https://api.shodan.io", True)]},
    "shodan_scan_status": {"category": "threat-intel", "providers": [_p("Shodan", "https://api.shodan.io", True)]},
    "vt_domain_report":   {"category": "threat-intel", "providers": [_p("VirusTotal", "https://www.virustotal.com", True)]},
    "vt_ip_report":       {"category": "threat-intel", "providers": [_p("VirusTotal", "https://www.virustotal.com", True)]},
    "hudson_rock":        {"category": "threat-intel", "providers": [_p("Hudson Rock Cavalier", "https://cavalier.hudsonrock.com")]},
    "tor_nodes":          {"category": "threat-intel", "providers": [_p("Tor Project Onionoo", "https://onionoo.torproject.org")]},
    "ransomware_check":   {"category": "threat-intel", "providers": [_p("ransomware.live", "https://api.ransomware.live")]},
    # Tech-stack
    "builtwith_lookup":   {"category": "tech-stack", "providers": [_p("BuiltWith (Free API)", "https://api.builtwith.com", True)]},
    "tech_stack":         {"category": "tech-stack", "providers": [_p("BuiltWith", "https://builtwith.com"), _p("GitHub", "https://api.github.com", True), _p("Job boards", "https://")]},
    "github_recon":       {"category": "tech-stack", "providers": [_p("GitHub", "https://api.github.com", True)]},
    "career_sources":     {"category": "tech-stack", "providers": [_p("Target career pages", "https://"), _p("Wayback Machine", "https://web.archive.org")]},
    "job_postings":       {"category": "tech-stack", "providers": [_p("Job boards / ATS", "https://"), _p("Wayback Machine", "https://web.archive.org")]},
    # LLM / AI surface
    "llm_fingerprint":    {"category": "llm-recon", "providers": [_p("Target host", "https://")]},
    "llm_probe_public_chat": {"category": "llm-recon", "providers": [_p("Target host", "https://")]},
    "llm_security_probe": {"category": "llm-recon", "providers": [_p("Target host", "https://")]},
    # Privacy & data handling
    "privacy_policy":     {"category": "privacy", "providers": [_p("Target host (policy crawl)", "https://")]},
    "tracker_scan":       {"category": "privacy", "providers": [_p("Target host (tracker crawl)", "https://")]},
    # Research & web search
    "web_search":         {"category": "research", "providers": [_p("Brave Search", "https://api.search.brave.com", True), _p("Tavily", "https://api.tavily.com", True)]},
    "research":           {"category": "research", "providers": [_p("Brave Search", "https://api.search.brave.com", True), _p("Tavily", "https://api.tavily.com", True), _p("Perplexity", "https://api.perplexity.ai", True)]},
    "research_synthesis": {"category": "research", "providers": [_p("Perplexity", "https://api.perplexity.ai", True)]},
}


def build_manifest() -> dict:
    """The full manifest: build reference + the tool→sources map. Served at `cybersleuth://manifest`."""
    ref = source_ref()
    return {
        "service": "cybersleuth",
        "version": ref["cybersleuth_version"],
        "commit": ref["cybersleuth_commit"],
        "build_date": ref["cybersleuth_build_date"],
        "generated_at": ref["retrieved_at"],
        "tool_count": len(SOURCES),
        "tools": [{"name": t, "category": s["category"], "providers": s["providers"]} for t, s in sorted(SOURCES.items())],
    }
