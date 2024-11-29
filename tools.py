import requests
import mmh3
import codecs
import shodan
import urllib3
import time
from typing import Optional, Dict, List
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import re
import collections
import whois
import dns.resolver
import dns.reversename
import ipaddress
from typing import List, Dict, Union
import requests
import datetime


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


def get_whois_info(domain: str, server: Optional[str] = None) -> Dict:
    """
    Get WHOIS information for a domain with optional WHOIS server selection.

    Args:
        domain (str): Domain name or IP to query
        server (str, optional): Specific WHOIS server (e.g., 'whois.arin.net', 'whois.ripe.net', 'whois.apnic.net')

    Returns:
        Dict: WHOIS information
    """
    try:
        # If a specific server is provided, use it
        if server:
            import socket
            import subprocess

            # Connect to specific WHOIS server
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((server, 43))
            s.send((domain + '\r\n').encode())

            response = ''
            while True:
                data = s.recv(4096)
                if not data:
                    break
                response += data.decode('utf-8', errors='ignore')
            s.close()

            return {
                "raw": response,
                "server_used": server,
                "query_type": "custom_server"
            }

        # Use python-whois for standard queries
        w = whois.whois(domain)

        # Process the response into a clean dictionary
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
            "query_type": "standard"
        }

        # Clean None values and convert dates to strings
        clean_result = {}
        for key, value in result.items():
            if value is not None:
                if isinstance(value, (list, tuple)):
                    clean_result[key] = [str(v)
                                         for v in value if v is not None]
                else:
                    clean_result[key] = str(value)

        return clean_result

    except Exception as e:
        return {"error": f"WHOIS query failed: {str(e)}"}


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


__all__ = [
    # Core functionality
    'get_favicon_hash',
    'search_shodan',
    'search_urlscan_history',
    'scan_url',
    'get_whois_info',
    'get_dns_records',
    'reverse_dns_lookup',
    'get_certificate_info'
]
