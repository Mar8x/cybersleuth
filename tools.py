import codecs
import collections
import socket
import datetime
import ipaddress
import re
import time
from typing import Dict, List, Optional
from urllib.parse import urljoin

import dns.resolver
import dns.reversename
import mmh3
import requests
import shodan
import urllib3
import whois
from bs4 import BeautifulSoup


def get_certificate_info(domain: str, include_expired: bool = False, wildcard: bool = True) -> Dict:
    """
    Get certificate information from crt.sh.

    Args:
        domain (str): Domain to search for
        include_expired (bool): Include expired certificates
        wildcard (bool): Include wildcard certificates

    Returns:
        Dict: Certificate information and analysis
    """
    try:
        # Format domain for wildcard search if enabled
        search_domain = f"%.{domain}" if wildcard else domain

        # Query crt.sh database
        url = "https://crt.sh/"
        params = {
            'q': search_domain,
            'output': 'json'
        }

        response = requests.get(url, params=params)
        response.raise_for_status()
        certificates = response.json()

        # Process and categorize certificates
        processed_certs = []
        unique_domains = set()
        unique_issuers = set()
        still_valid = []

        for cert in certificates:
            # Extract common name and SANs
            domains = set()
            if cert.get('common_name'):
                domains.add(cert['common_name'].lower())
            if cert.get('name_value'):
                # Split and clean DNS names
                sans = re.findall(r'DNS:([\w\.-]+)', cert['name_value'])
                domains.update([san.lower() for san in sans])

            # Convert dates - handle multiple possible formats
            try:
                # Try ISO format first
                not_before = datetime.datetime.fromisoformat(
                    cert['not_before'].replace('Z', '+00:00'))
                not_after = datetime.datetime.fromisoformat(
                    cert['not_after'].replace('Z', '+00:00'))
            except ValueError:
                try:
                    # Try standard crt.sh format
                    not_before = datetime.datetime.strptime(
                        cert['not_before'].split('[')[0].strip(), '%Y-%m-%d')
                    not_after = datetime.datetime.strptime(
                        cert['not_after'].split('[')[0].strip(), '%Y-%m-%d')
                except ValueError:
                    # Try another common format
                    not_before = datetime.datetime.strptime(
                        cert['not_before'], '%Y-%m-%d %H:%M:%S')
                    not_after = datetime.datetime.strptime(
                        cert['not_after'], '%Y-%m-%d %H:%M:%S')

            is_valid = not_after > datetime.datetime.now()
            if is_valid:
                still_valid.append(cert['serial_number'])

            if is_valid or include_expired:
                cert_info = {
                    'id': cert['id'],
                    'serial_number': cert['serial_number'],
                    'issuer': cert['issuer_name'],
                    'domains': list(domains),
                    'not_before': not_before.isoformat(),
                    'not_after': not_after.isoformat(),
                    'is_valid': is_valid
                }
                processed_certs.append(cert_info)

                # Update unique sets
                unique_domains.update(domains)
                unique_issuers.add(cert['issuer_name'])

        # Group domains by type
        domain_categories = {
            'apex_domains': set(),
            'subdomains': set(),
            'wildcards': set()
        }

        base_domain = domain.lower()
        for d in unique_domains:
            if '*' in d:
                domain_categories['wildcards'].add(d)
            elif d == base_domain:
                domain_categories['apex_domains'].add(d)
            else:
                domain_categories['subdomains'].add(d)

        # Analyze patterns and anomalies
        analysis = {
            'total_certificates': len(processed_certs),
            'valid_certificates': len(still_valid),
            'unique_domains': {
                'total': len(unique_domains),
                'apex_domains': len(domain_categories['apex_domains']),
                'subdomains': len(domain_categories['subdomains']),
                'wildcards': len(domain_categories['wildcards'])
            },
            'unique_issuers_count': len(unique_issuers),
            'interesting_patterns': []
        }

        # Detect interesting patterns
        interesting = []

        # Check for numerous subdomains
        if len(domain_categories['subdomains']) > 10:
            interesting.append(
                f"Large number of subdomains found ({len(domain_categories['subdomains'])})")

        # Check for multiple issuers
        if len(unique_issuers) > 1:
            interesting.append(
                f"Multiple certificate issuers detected ({len(unique_issuers)})")

        # Check for recently issued certificates
        recent_certs = [cert for cert in processed_certs
                        if datetime.datetime.fromisoformat(cert['not_before']) >
                        (datetime.datetime.now() - datetime.timedelta(days=7))]
        if recent_certs:
            interesting.append(
                f"Recently issued certificates found ({len(recent_certs)} in past week)")

        # Note wildcard usage
        if domain_categories['wildcards']:
            interesting.append(
                f"Wildcard certificates detected ({len(domain_categories['wildcards'])})")

        analysis['interesting_patterns'] = interesting

        return {
            'certificates': processed_certs,
            'domains': {
                'all': sorted(list(unique_domains)),
                'apex': sorted(list(domain_categories['apex_domains'])),
                'subdomains': sorted(list(domain_categories['subdomains'])),
                'wildcards': sorted(list(domain_categories['wildcards']))
            },
            'issuers': sorted(list(unique_issuers)),
            'analysis': analysis,
            'query_info': {
                'domain': domain,
                'include_expired': include_expired,
                'wildcard_search': wildcard,
                'timestamp': datetime.datetime.now().isoformat()
            }
        }

    except requests.exceptions.RequestException as e:
        return {
            "error": f"Failed to fetch certificate data: {str(e)}",
            "query_info": {
                'domain': domain,
                'timestamp': datetime.datetime.now().isoformat()
            }
        }
    except Exception as e:
        return {
            "error": f"Error processing certificate data: {str(e)}",
            "query_info": {
                'domain': domain,
                'timestamp': datetime.datetime.now().isoformat()
            }
        }


# RIR whois servers for IP lookups (approximate first-octet mapping for IPv4).
_RIR_WHOIS_SERVERS = {
    "arin": "whois.arin.net",    # Americas
    "ripe": "whois.ripe.net",    # Europe, Middle East, Central Asia
    "apnic": "whois.apnic.net",  # Asia-Pacific
    "lacnic": "whois.lacnic.net",  # Latin America, Caribbean
    "afrinic": "whois.afrinic.net",  # Africa
}
# IPv4 first octet -> RIR (simplified; some ranges overlap; IANA assignment may vary).
_IPV4_FIRST_OCTET_TO_RIR = {
    **{o: "apnic" for o in (1, 14, 27, 36, 39, 42, 49, 58, 59, 60, 61, 101, 106, 163, 171, 175, 180, 182, 183, 202, 203, 210, 211, 218, 219, 220, 221, 222, 223)},
    **{o: "apnic" for o in range(110, 127)},  # 110-126
    **{o: "ripe" for o in (2, 5, 31, 37, 46, 62, 109, 141, 145, 151, 176, 178, 185, 188, 193, 194, 195, 212, 213, 217)},
    **{o: "ripe" for o in range(77, 96)},   # 77-95
    **{o: "arin" for o in (7, 8, 9, 12, 13, 15, 16, 17, 18, 19, 20, 23, 24, 32, 34, 35, 38, 40, 44, 45, 47, 50, 52, 54, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 96, 97, 98, 99, 128, 129, 130, 131, 132, 134, 136, 137, 138, 139, 140, 142, 143, 144, 146, 147, 148, 152, 155, 156, 157, 158, 159, 160, 161, 162, 164, 165, 166, 167, 168, 169, 170, 172, 173, 174, 184, 192, 198, 199, 204, 205, 206, 207, 208, 209, 216)},
    **{o: "afrinic" for o in (41, 102, 105, 154, 196, 197)},
    **{o: "lacnic" for o in (177, 179, 181, 186, 187, 189, 190, 191, 200, 201)},
}


def _get_rir_whois_server(ip_str: str) -> Optional[str]:
    """Return the recommended RIR whois server for an IP, or None if unknown."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return None
    if addr.version == 4:
        first = int(addr.packed[0])
        rir = _IPV4_FIRST_OCTET_TO_RIR.get(first)
        if rir:
            return _RIR_WHOIS_SERVERS[rir]
    else:
        # IPv6: many allocations in RIPE; could extend with a proper table
        return _RIR_WHOIS_SERVERS["ripe"]
    return None


def _raw_whois_query(server: str, query: str, port: int = 43) -> str:
    """Send a WHOIS query to server:port and return the raw response text."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(15)
    try:
        s.connect((server, port))
        s.send((query.strip() + "\r\n").encode("utf-8"))
        response = []
        while True:
            data = s.recv(4096)
            if not data:
                break
            response.append(data.decode("utf-8", errors="ignore"))
        return "".join(response)
    finally:
        s.close()


def _parse_raw_whois(raw: str) -> Dict:
    """
    Parse raw WHOIS response into a structured dict.
    Handles common key: value lines and referral lines; normalizes key names.
    """
    out = {}
    lines = raw.splitlines()
    for line in lines:
        line = line.rstrip()
        if ":" in line and not line.startswith("%") and not line.startswith("#"):
            key, _, value = line.partition(":")
            key = key.strip().lower().replace(" ", "_").replace("-", "_")
            value = value.strip()
            if not key or not value:
                continue
            if key in ("referral", "whois", "whois_server"):
                out["whois_server"] = value
            elif key in out and isinstance(out[key], list):
                out[key].append(value)
            elif key in out:
                out[key] = [out[key], value]
            else:
                out[key] = value
    # Normalize some known multi-value keys to list
    for key in ("name_server", "nserver", "nameserver"):
        if key in out and isinstance(out[key], str):
            out["name_servers"] = [s.strip() for s in re.split(r"[\s,]+", out[key]) if s.strip()]
    if "name_servers" not in out and "nameservers" in out:
        out["name_servers"] = out["nameservers"] if isinstance(out["nameservers"], list) else [out["nameservers"]]
    return {k: v for k, v in out.items() if v}


def _get_tld_whois_server(tld: str) -> Optional[str]:
    """Resolve TLD to whois server via IANA (optional). Returns None on failure."""
    tld = tld.lstrip(".").lower()
    if not tld:
        return None
    try:
        r = requests.get(
            f"https://www.iana.org/domains/root/db/{tld}.json",
            timeout=10,
            headers={"User-Agent": "CyberSleuth/1.0"},
        )
        if r.status_code != 200:
            return None
        data = r.json()
        whois = data.get("whois")
        if isinstance(whois, str) and whois:
            return whois
        return None
    except Exception:
        return None


def get_whois_info(domain: str, server: Optional[str] = None) -> Dict:
    """
    Get WHOIS information for a domain or IP with optional WHOIS server selection.

    For IPs, the correct RIR (e.g. RIPE, ARIN) is chosen automatically when no server
    is specified. For domains, python-whois is tried first; on failure, the TLD whois
    server is queried when possible. When a specific server is used, the raw response
    is parsed into a consistent structured format.

    Args:
        domain (str): Domain name or IP to query
        server (str, optional): Specific WHOIS server (e.g., 'whois.arin.net', 'whois.ripe.net', 'whois.apnic.net')

    Returns:
        Dict: WHOIS information (structured). On error, includes an "error" key and optional "hint".
    """
    query = domain.strip()
    try:
        is_ip = False
        try:
            ipaddress.ip_address(query)
            is_ip = True
        except ValueError:
            pass

        # Explicit server: raw query and parse
        if server:
            server = server.strip()
            raw = _raw_whois_query(server, query)
            parsed = _parse_raw_whois(raw)
            result = {
                **parsed,
                "raw": raw,
                "server_used": server,
                "query_type": "custom_server",
            }
            return result

        # IP and no server: use RIR-specific whois
        if is_ip:
            rir_server = _get_rir_whois_server(query)
            if rir_server:
                raw = _raw_whois_query(rir_server, query)
                parsed = _parse_raw_whois(raw)
                result = {
                    **parsed,
                    "raw": raw,
                    "server_used": rir_server,
                    "query_type": "rir",
                }
                return result
            return {
                "error": f"WHOIS query failed for IP {query}",
                "hint": "Try specifying server= (e.g. whois.ripe.net, whois.arin.net) for your region.",
            }

        # Domain: try python-whois first
        try:
            w = whois.whois(query)
            if w is None:
                raise ValueError("whois returned None")
            result = {
                "domain_name": w.domain_name,
                "registrar": w.registrar,
                "whois_server": w.whois_server,
                "referral_url": w.referral_url,
                "updated_date": w.updated_date,
                "creation_date": w.creation_date,
                "expiration_date": w.expiration_date,
                "name_servers": w.name_servers,
                "status": w.status,
                "emails": w.emails,
                "dnssec": w.dnssec,
                "name": w.name,
                "org": w.org,
                "registrant_country": w.registrant_country,
                "query_type": "standard",
            }
            clean_result = {}
            for key, value in result.items():
                if value is not None:
                    if isinstance(value, (list, tuple)):
                        clean_result[key] = [str(v) for v in value if v is not None]
                    else:
                        clean_result[key] = str(value)
            return clean_result
        except Exception:
            pass

        # Domain fallback: resolve TLD and query TLD whois server
        tld = query.split(".")[-1] if "." in query else ""
        tld_server = _get_tld_whois_server(tld) if tld else None
        if tld_server:
            raw = _raw_whois_query(tld_server, query)
            parsed = _parse_raw_whois(raw)
            return {
                **parsed,
                "raw": raw,
                "server_used": tld_server,
                "query_type": "tld",
            }

        return {
            "error": f"WHOIS query failed for {query}",
            "hint": f"Consider specifying server= for this TLD (e.g. whois.ripe.net for EU, whois.arin.net for Americas).",
        }

    except socket.timeout:
        return {"error": "WHOIS query timed out", "hint": "Try again or specify server= for your region."}
    except Exception as e:
        err = str(e)
        out = {"error": f"WHOIS query failed: {err}"}
        if "connection" in err.lower() or "timed out" in err.lower():
            out["hint"] = "Try specifying server= (e.g. whois.ripe.net, whois.arin.net) for your region."
        return out


def get_dns_records(domain: str, record_types: Optional[List[str]] = None) -> Dict:
    """
    Get all DNS records for a domain.

    Args:
        domain (str): Domain name to query
        record_types (List[str], optional): Specific record types to query
                    (e.g., ['A', 'AAAA', 'MX', 'TXT'])

    Returns:
        Dict: DNS records by type
    """
    if record_types is None:
        record_types = ['A', 'AAAA', 'MX', 'NS',
                        'TXT', 'SOA', 'CNAME', 'PTR', 'SRV', 'CAA']

    resolver = dns.resolver.Resolver()
    results = {}

    try:
        for record_type in record_types:
            try:
                answers = resolver.resolve(domain, record_type)
                records = []

                for rdata in answers:
                    if record_type == 'MX':
                        records.append({
                            'preference': rdata.preference,
                            'exchange': str(rdata.exchange)
                        })
                    elif record_type == 'SOA':
                        records.append({
                            'mname': str(rdata.mname),
                            'rname': str(rdata.rname),
                            'serial': rdata.serial,
                            'refresh': rdata.refresh,
                            'retry': rdata.retry,
                            'expire': rdata.expire,
                            'minimum': rdata.minimum
                        })
                    elif record_type == 'SRV':
                        records.append({
                            'priority': rdata.priority,
                            'weight': rdata.weight,
                            'port': rdata.port,
                            'target': str(rdata.target)
                        })
                    else:
                        records.append(str(rdata))

                results[record_type] = records

            except dns.resolver.NoAnswer:
                continue
            except dns.resolver.NXDOMAIN:
                return {"error": f"Domain {domain} does not exist"}
            except Exception as e:
                results[record_type] = f"Error: {str(e)}"

        return results

    except Exception as e:
        return {"error": f"DNS query failed: {str(e)}"}


def reverse_dns_lookup(ip: str) -> Dict:
    """
    Perform reverse DNS lookup for an IP address.

    Args:
        ip (str): IP address to look up

    Returns:
        Dict: Reverse DNS information
    """
    try:
        # Validate IP address
        ipaddress.ip_address(ip)

        # Convert address to PTR
        addr = dns.reversename.from_address(ip)

        try:
            # Attempt reverse DNS lookup
            resolver = dns.resolver.Resolver()
            answers = resolver.resolve(addr, "PTR")

            return {
                "ip": ip,
                "hostnames": [str(answer) for answer in answers],
                "ptr_record": str(addr)
            }

        except dns.resolver.NXDOMAIN:
            return {
                "ip": ip,
                "error": "No reverse DNS record found",
                "ptr_record": str(addr)
            }

    except ValueError:
        return {"error": f"Invalid IP address: {ip}"}
    except Exception as e:
        return {"error": f"Reverse DNS lookup failed: {str(e)}"}


# Known hosting/cloud provider names (substring match, case-insensitive) for AS classification.
_AS_HOSTING_KEYWORDS = frozenset([
    "amazon", "aws", "google", "gcp", "google cloud", "microsoft", "azure",
    "cloudflare", "ovh", "digitalocean", "linode", "akamai", "hetzner",
    "vultr", "choopa", "incapsula", "fastly", "stackpath", "limelight",
    "leaseweb", "psychz", "buyvm", "frantech", "ramnode", "vps", "hosting",
    "serverion", "codero", "singlehop", "softlayer", "ibm cloud",
    "alibaba", "tencent cloud", "oracle cloud", "digital realty", "equinix",
    "coreweave", "scaleway", "contabo", "ionos", "1&1", "godaddy",
    "namecheap", "hostinger", "bluehost", "siteground", "wp engine",
])


def get_as_intelligence(domain_or_ip: str) -> Dict:
    """
    Get Autonomous System (AS) information for an IP or domain.

    Resolves domain to first A/AAAA record if needed, then looks up ASN and org
    via ip-api.com. Classifies whether the AS is likely a hosting/cloud provider
    so analysts can focus on "interesting" ASes (enterprise, ISP).

    Args:
        domain_or_ip (str): Domain name or IP address

    Returns:
        Dict: asn, as_org, country, is_hosting, is_cloud, provider_hint (optional),
              and a note when not hosting that the AS may be the real org.
    """
    ip = None
    domain_queried = None
    try:
        addr = ipaddress.ip_address(domain_or_ip.strip())
        ip = str(addr)
    except ValueError:
        domain_queried = domain_or_ip.strip().lower()
        if "://" in domain_queried:
            domain_queried = domain_queried.split("://", 1)[1]
        domain_queried = domain_queried.split("/")[0]
        if domain_queried.startswith("www."):
            domain_queried = domain_queried[4:]
        resolver = dns.resolver.Resolver()
        for rtype in ("A", "AAAA"):
            try:
                answers = resolver.resolve(domain_queried, rtype)
                if answers:
                    ip = str(answers[0])
                    break
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                continue
        if not ip:
            return {
                "error": f"Could not resolve domain to an IP: {domain_queried}",
                "query": domain_queried,
            }

    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,message,as,asname,org,country",
            timeout=10,
        )
        r.raise_for_status()
        data = r.json()
        if data.get("status") != "success":
            return {
                "error": data.get("message", "ip-api lookup failed"),
                "ip": ip,
                "query": domain_queried or ip,
            }
        as_str = data.get("as") or ""
        asname = (data.get("asname") or "").strip()
        org = (data.get("org") or "").strip()
        country = (data.get("country") or "").strip()
        combined = f"{asname} {org}".lower()
        is_hosting = False
        provider_hint = None
        for keyword in _AS_HOSTING_KEYWORDS:
            if keyword in combined:
                is_hosting = True
                if not provider_hint:
                    provider_hint = keyword
                break
        is_cloud = is_hosting and any(
            c in combined for c in ("cloud", "aws", "azure", "gcp", "google cloud")
        )
        out = {
            "ip": ip,
            "asn": as_str or None,
            "as_org": org or asname or None,
            "country": country or None,
            "is_hosting": is_hosting,
            "is_cloud": is_cloud,
            "query": domain_queried or ip,
            "query_info": {
                "timestamp": datetime.datetime.now().isoformat(),
            },
        }
        if provider_hint:
            out["provider_hint"] = provider_hint
        if not is_hosting and (org or asname):
            out["note"] = "AS is not a known hosting/cloud provider; AS org may be the actual organization (enterprise or ISP)."
        return out
    except requests.exceptions.RequestException as e:
        return {
            "error": f"AS lookup failed: {str(e)}",
            "ip": ip,
            "query": domain_queried or ip,
        }
    except (ValueError, KeyError) as e:
        return {
            "error": f"AS lookup response error: {str(e)}",
            "ip": ip,
            "query": domain_queried or ip,
        }


def normalize_url(url: str) -> str:
    """
    Normalize URL to ensure consistent format with proper scheme and path.
    Args:
        url (str): URL or domain to normalize
    Returns:
        str: Normalized URL with proper www and scheme
    """
    if not url:
        raise ValueError("URL cannot be empty")

    # Remove any whitespace and convert to lowercase
    url = url.strip().lower()

    # Remove any protocol specification first
    if '://' in url:
        url = url.split('://', 1)[1]

    # Remove any path or query parameters to get clean domain
    domain = url.split('/')[0]

    # Add www if not present (many sites redirect to www)
    if not domain.startswith('www.'):
        domain_with_www = f'www.{domain}'
    else:
        domain_with_www = domain

    # Try different combinations in order of preference
    test_urls = [
        f"https://{domain_with_www}",  # Try www with HTTPS first
        f"https://{domain}",           # Try non-www with HTTPS
        f"http://{domain_with_www}",   # Try www with HTTP
        f"http://{domain}"            # Try non-www with HTTP
    ]

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }

    for test_url in test_urls:
        try:
            response = requests.head(test_url,
                                     timeout=5,
                                     allow_redirects=True,
                                     headers=headers)
            if response.status_code < 400:
                # Return the final URL after any redirects
                return response.url
        except requests.RequestException:
            continue

    # If all attempts fail, return HTTPS www version as default
    return f"https://{domain_with_www}"


def find_favicons(url: str, verify_ssl: bool = True, timeout: int = 10) -> List[Dict]:
    """
    Find all favicons for a website using various methods.
    Args:
        url (str): Base URL to search for favicons
        verify_ssl (bool): Whether to verify SSL certificates
        timeout (int): Request timeout in seconds
    Returns:
        List[Dict]: List of found favicons with their details
    """
    if not verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Normalize input URL
    base_url = normalize_url(url)

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }

    # Common favicon locations to check
    common_paths = [
        '/favicon.ico',
        '/favicon.png',
        '/assets/favicon.ico',
        '/assets/images/favicon.ico',
        '/static/favicon.ico',
        '/static/images/favicon.ico',
        '/public/favicon.ico',
        '/img/favicon.ico',
        '/images/favicon.ico',
        '/favicon-32x32.png',
        '/favicon-16x16.png',
        '/apple-touch-icon.png',
        '/site.webmanifest',
    ]

    found_favicons = []

    try:
        # First try to get favicons from HTML
        response = requests.get(
            base_url, verify=verify_ssl, headers=headers, timeout=timeout)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')

        # Find all favicon links in HTML
        favicon_links = soup.find_all('link', rel=re.compile(
            r'(shortcut )?icon|apple-touch-icon', re.I))

        for link in favicon_links:
            favicon_url = link.get('href')
            if favicon_url:
                # Handle relative URLs
                if not favicon_url.startswith(('http://', 'https://')):
                    favicon_url = urljoin(base_url, favicon_url)

                try:
                    head_response = requests.head(
                        favicon_url, verify=verify_ssl, headers=headers, timeout=5)
                    if head_response.status_code == 200:
                        found_favicons.append({
                            'url': favicon_url,
                            'type': link.get('rel', ['icon'])[0],
                            'size': link.get('sizes', 'unknown'),
                            'source': 'html'
                        })
                except requests.RequestException:
                    continue

        # Then check common locations
        for path in common_paths:
            favicon_url = urljoin(base_url, path)
            try:
                head_response = requests.head(
                    favicon_url, verify=verify_ssl, headers=headers, timeout=5)
                if head_response.status_code == 200:
                    found_favicons.append({
                        'url': favicon_url,
                        'type': 'icon',
                        'size': 'unknown',
                        'source': 'common_path'
                    })
            except requests.RequestException:
                continue

        # Remove duplicates while preserving order
        seen_urls = set()
        unique_favicons = []
        for favicon in found_favicons:
            if favicon['url'] not in seen_urls:
                seen_urls.add(favicon['url'])
                unique_favicons.append(favicon)

        return unique_favicons

    except Exception as e:
        print(f"Error finding favicons: {str(e)}")
        return []


def get_favicon_hash(url: str, verify_ssl: bool = True) -> Dict:
    """
    Get all favicon hashes for Shodan searches.
    Args:
        url (str): Website URL or domain
        verify_ssl (bool): Verify SSL certificates
    Returns:
        Dict: Favicon information including hashes
    """
    try:
        favicons = find_favicons(url, verify_ssl)
        if not favicons:
            return {"error": "No favicons found"}

        results = []
        for favicon in favicons:
            try:
                response = requests.get(favicon['url'], verify=verify_ssl)
                if response.status_code == 200:
                    favicon_b64 = codecs.encode(response.content, "base64")
                    favicon_hash = mmh3.hash(favicon_b64)
                    results.append({
                        "hash": favicon_hash,
                        "location": favicon['url'],
                        "type": favicon['type'],
                        "size": favicon['size'],
                        "source": favicon['source'],
                        "shodan_query": f"http.favicon.hash:{favicon_hash}"
                    })
            except Exception as e:
                print(f"Error processing favicon {favicon['url']}: {str(e)}")
                continue

        return {
            "favicons": results,
            "total_found": len(results)
        }

    except Exception as e:
        return {"error": str(e)}


def search_shodan(api_key: str, query: str, limit: int = 5) -> Dict:
    """
    Search Shodan with aggregated results.

    Args:
        api_key (str): Shodan API key
        query (str): Search query
        limit (int): Number of detailed matches

    Returns:
        Dict: Search results with stats and matches
    """
    try:
        api = shodan.Shodan(api_key)
        results = api.search(query)

        # Get countries from valid results
        countries = collections.Counter()
        organizations = collections.Counter()
        ports = collections.Counter()

        for host in results.get('matches', []):
            # Extract country
            country = host.get('location', {}).get('country_name', 'Unknown')
            countries[country] += 1

            # Extract organization
            org = host.get('org', 'Unknown')
            organizations[org] += 1

            # Extract port
            port = host.get('port', 'Unknown')
            ports[port] += 1

        return {
            "total_results": results.get('total', 0),
            "matches": [
                {
                    "ip": host.get('ip_str', 'Unknown'),
                    "port": host.get('port', 'Unknown'),
                    "org": host.get('org', 'Unknown'),
                    "country": host.get('location', {}).get('country_name', 'Unknown'),
                    "domains": host.get('domains', []),
                    "hostnames": host.get('hostnames', []),
                    "product": host.get('product', 'Unknown'),
                    "version": host.get('version', 'Unknown'),
                    # Limit data length
                    "data": host.get('data', '').strip()[:500]
                }
                for host in results.get('matches', [])[:limit]
            ],
            "stats": {
                "countries": countries.most_common(5),
                "organizations": organizations.most_common(5),
                "ports": ports.most_common(5)
            }
        }
    except shodan.APIError as e:
        return {"error": f"Shodan API error: {str(e)}"}
    except Exception as e:
        return {"error": f"Error during Shodan search: {str(e)}"}


def search_urlscan_history(url: str, api_key: str, limit: int = 10) -> Dict:
    """
    Search URLScan.io's historical data.

    Args:
        url (str): URL or domain to search
        api_key (str): URLScan.io API key
        limit (int): Maximum results to return
    """
    headers = {'API-Key': api_key}

    try:
        search_url = f"https://urlscan.io/api/v1/search/?q={url}&size={limit}"
        response = requests.get(search_url, headers=headers)
        results = response.json()

        if not results.get('results'):
            return {"message": "No scans found"}

        return {
            "total_found": results.get('total', 0),
            "scans": [{
                "date": result.get('task', {}).get('time'),
                "url": f"https://urlscan.io/result/{result.get('_id')}/",
                "screenshot": f"https://urlscan.io/screenshots/{result.get('_id')}.png",
                "malicious": result.get('verdicts', {}).get('overall', {}).get('malicious', False)
            } for result in results.get('results', [])]
        }

    except Exception as e:
        return {"error": str(e)}


def scan_url(url: str, api_key: str) -> Dict:
    """
    Submit and retrieve URLScan scan.

    Args:
        url (str): URL to scan
        api_key (str): URLScan.io API key
    """
    headers = {
        'API-Key': api_key,
        'Content-Type': 'application/json'
    }

    try:
        # Submit scan
        submit = requests.post(
            'https://urlscan.io/api/v1/scan/',
            headers=headers,
            json={"url": url, "visibility": "public"}
        )

        if submit.status_code != 200:
            return {"error": "Scan submission failed"}

        scan_uuid = submit.json().get('uuid')
        print(f"Scan submitted. UUID: {scan_uuid}")

        # Wait for results
        for _ in range(6):  # Try for 3 minutes
            time.sleep(30)
            result = requests.get(
                f'https://urlscan.io/api/v1/result/{scan_uuid}/')
            if result.status_code == 200:
                data = result.json()
                return {
                    "scan_id": scan_uuid,
                    "url": data.get('page', {}).get('url'),
                    "domain": data.get('page', {}).get('domain'),
                    "ip": data.get('page', {}).get('ip'),
                    "server": data.get('page', {}).get('server'),
                    "malicious": data.get('verdicts', {}).get('overall', {}).get('malicious', False),
                    "report_url": f"https://urlscan.io/result/{scan_uuid}/",
                    "screenshot": f"https://urlscan.io/screenshots/{scan_uuid}.png"
                }

        return {"error": "Scan timeout"}

    except Exception as e:
        return {"error": str(e)}


def get_builtwith_free(domain: str, api_key: Optional[str] = None) -> Dict:
    """
    Get technology groups and categories for a domain via BuiltWith Free API.

    The Free API does not require a paid subscription; a free API key from
    builtwith.com signup is required. Rate limit: 1 request per second.

    Args:
        domain (str): Domain to look up (e.g. example.com). Subdomain lookups
            return root-domain results per BuiltWith API.
        api_key (str, optional): BuiltWith API key. If not set, returns a
            message directing the user to set BUILTWITH_API_KEY or use
            builtwith.com manually.

    Returns:
        Dict: Parsed result with domain, first_seen, last_seen, and groups
            (name, live, dead, latest, oldest, categories), or error message.
    """
    if not api_key or not api_key.strip():
        return {
            "error": "BUILTWITH_API_KEY is not set. Get a free key at https://builtwith.com/signup and set the environment variable, or use https://builtwith.com/<domain> manually.",
            "query_info": {"domain": domain}
        }

    # Normalize: strip protocol and path, lowercase
    domain = domain.strip().lower()
    if "://" in domain:
        domain = domain.split("://", 1)[1]
    domain = domain.split("/")[0]
    if domain.startswith("www."):
        domain = domain[4:]

    url = "https://api.builtwith.com/free1/api.json"
    params = {"KEY": api_key.strip(), "LOOKUP": domain}

    try:
        response = requests.get(url, params=params, timeout=15)
        if response.status_code == 429:
            return {
                "error": "BuiltWith rate limit exceeded (1 request per second). Retry later.",
                "query_info": {"domain": domain}
            }
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.RequestException as e:
        return {
            "error": f"BuiltWith request failed: {str(e)}",
            "query_info": {"domain": domain}
        }
    except ValueError as e:
        return {
            "error": f"BuiltWith invalid response: {str(e)}",
            "query_info": {"domain": domain}
        }

    # Free API response: result with domain, first, last (epoch), groups[]
    result = data.get("Result") or data.get("result") or data
    if not result or (result.get("Lookup") is None and "Domain" not in result and "domain" not in result):
        err_msg = (result or data).get("Errors") or (result or data).get("errors") or "No result for domain"
        if isinstance(err_msg, list):
            err_msg = err_msg[0] if err_msg else "Unknown BuiltWith error"
        return {
            "error": str(err_msg),
            "query_info": {"domain": domain}
        }

    domain_out = result.get("Domain") or result.get("domain") or domain
    first_ts = result.get("First") or result.get("first")
    last_ts = result.get("Last") or result.get("last")
    raw_groups = result.get("Groups") or result.get("groups") or []

    def epoch_to_iso(ts: Optional[int]) -> Optional[str]:
        if ts is None:
            return None
        try:
            return datetime.datetime.utcfromtimestamp(int(ts)).isoformat() + "Z"
        except (ValueError, OSError):
            return str(ts)

    groups_out = []
    for g in raw_groups:
        group = {
            "name": g.get("Name") or g.get("name", ""),
            "live": g.get("Live") if g.get("Live") is not None else g.get("live"),
            "dead": g.get("Dead") if g.get("Dead") is not None else g.get("dead"),
            "latest": epoch_to_iso(g.get("Latest") or g.get("latest")),
            "oldest": epoch_to_iso(g.get("Oldest") or g.get("oldest")),
        }
        raw_cats = g.get("Categories") or g.get("categories") or []
        group["categories"] = [
            {
                "name": c.get("Name") or c.get("name", ""),
                "live": c.get("Live") if c.get("Live") is not None else c.get("live"),
                "dead": c.get("Dead") if c.get("Dead") is not None else c.get("dead"),
                "latest": epoch_to_iso(c.get("Latest") or c.get("latest")),
                "oldest": epoch_to_iso(c.get("Oldest") or c.get("oldest")),
            }
            for c in raw_cats
        ]
        groups_out.append(group)

    return {
        "domain": domain_out,
        "first_seen": epoch_to_iso(first_ts),
        "last_seen": epoch_to_iso(last_ts),
        "first_epoch": first_ts,
        "last_epoch": last_ts,
        "groups": groups_out,
        "query_info": {
            "domain": domain,
            "timestamp": datetime.datetime.now().isoformat()
        }
    }


_VT_BASE = "https://www.virustotal.com/api/v3"


def get_vt_domain_report(domain: str, api_key: str) -> Dict:
    """
    Get VirusTotal report for a domain (reputation and last analysis stats).

    Args:
        domain (str): Domain to look up (e.g. example.com)
        api_key (str): VirusTotal API key (x-apikey header)

    Returns:
        Dict: last_analysis_stats (malicious, suspicious, harmless, undetected),
              reputation if present, categories; or error message.
    """
    if not api_key or not api_key.strip():
        return {"error": "VIRUSTOTAL_API_KEY is not set"}
    domain = domain.strip().lower()
    if "://" in domain:
        domain = domain.split("://", 1)[1]
    domain = domain.split("/")[0]
    if domain.startswith("www."):
        domain = domain[4:]
    if not domain or "." not in domain:
        return {"error": f"Invalid domain: {domain!r}"}
    url = f"{_VT_BASE}/domains/{domain}"
    headers = {"x-apikey": api_key.strip()}
    try:
        r = requests.get(url, headers=headers, timeout=30)
        if r.status_code == 401 or r.status_code == 403:
            return {"error": "Invalid or missing VirusTotal API key"}
        if r.status_code == 404:
            return {"message": "No VirusTotal report found for this domain", "domain": domain}
        r.raise_for_status()
        data = r.json()
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats") or {}
        out = {
            "domain": domain,
            "last_analysis_stats": stats,
            "reputation": attrs.get("reputation"),
            "categories": attrs.get("categories"),
            "query_info": {"domain": domain, "timestamp": datetime.datetime.now().isoformat()},
        }
        if attrs.get("last_analysis_date"):
            out["last_analysis_date"] = datetime.datetime.utcfromtimestamp(
                attrs["last_analysis_date"]
            ).isoformat() + "Z"
        return out
    except requests.exceptions.RequestException as e:
        return {"error": f"VirusTotal request failed: {str(e)}", "domain": domain}
    except (ValueError, KeyError) as e:
        return {"error": f"VirusTotal response error: {str(e)}", "domain": domain}


def get_vt_ip_report(ip: str, api_key: str) -> Dict:
    """
    Get VirusTotal report for an IP address (reputation and last analysis stats).

    Args:
        ip (str): IP address to look up
        api_key (str): VirusTotal API key (x-apikey header)

    Returns:
        Dict: last_analysis_stats, reputation, network/country if present; or error.
    """
    if not api_key or not api_key.strip():
        return {"error": "VIRUSTOTAL_API_KEY is not set"}
    ip = ip.strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {"error": f"Invalid IP address: {ip!r}"}
    url = f"{_VT_BASE}/ip_addresses/{ip}"
    headers = {"x-apikey": api_key.strip()}
    try:
        r = requests.get(url, headers=headers, timeout=30)
        if r.status_code == 401 or r.status_code == 403:
            return {"error": "Invalid or missing VirusTotal API key"}
        if r.status_code == 404:
            return {"message": "No VirusTotal report found for this IP", "ip": ip}
        r.raise_for_status()
        data = r.json()
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats") or {}
        out = {
            "ip": ip,
            "last_analysis_stats": stats,
            "reputation": attrs.get("reputation"),
            "network": attrs.get("network"),
            "country": attrs.get("country"),
            "query_info": {"ip": ip, "timestamp": datetime.datetime.now().isoformat()},
        }
        if attrs.get("last_analysis_date"):
            out["last_analysis_date"] = datetime.datetime.utcfromtimestamp(
                attrs["last_analysis_date"]
            ).isoformat() + "Z"
        return out
    except requests.exceptions.RequestException as e:
        return {"error": f"VirusTotal request failed: {str(e)}", "ip": ip}
    except (ValueError, KeyError) as e:
        return {"error": f"VirusTotal response error: {str(e)}", "ip": ip}


__all__ = [
    # Core functionality
    'get_favicon_hash',
    'search_shodan',
    'search_urlscan_history',
    'scan_url',
    'get_whois_info',
    'get_dns_records',
    'reverse_dns_lookup',
    'get_certificate_info',
    'get_builtwith_free',
    'get_vt_domain_report',
    'get_vt_ip_report',
    'get_as_intelligence',
]
