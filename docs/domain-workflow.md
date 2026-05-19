# Domain OSINT Lookup Workflow

**Purpose:** Dedicated domain and subdomain investigation — registration intel, DNS enumeration, subdomain discovery, technology fingerprinting, certificate transparency, and reputation assessment.

**Authorization Required:** Explicit authorization, defined scope, legal compliance confirmed.

---

## Phase 1: Authorization & Scope

**VERIFY BEFORE STARTING:**
- [ ] Explicit authorization from client or authorized party
- [ ] Clear scope definition (target domain(s), depth of enumeration, active vs. passive only)
- [ ] Legal compliance confirmed (authorized penetration testing scope if active scanning)
- [ ] Documented authorization in engagement paperwork

**STOP if any checkbox is unchecked.**

---

## Source Reference

| Investigation Area | Sources |
|-------------------|---------|
| **WHOIS/Registration** | DomainTools, WHOIS databases, ViewDNS |
| **DNS Enumeration** | SecurityTrails, DNSDumpster, Robtex, ViewDNS |
| **Subdomain Discovery** | crt.sh, SecurityTrails, DNSDumpster, subfinder, amass |
| **Technology/Hosting** | BuiltWith, Wappalyzer, Netcraft, Shodan, Censys |
| **Certificate Transparency** | crt.sh, CertStream, Cert Spotter |
| **Reputation/Threat Intel** | VirusTotal, URLScan.io, AbuseIPDB, GreyNoise, PhishTank |
| **Breach/Leak** | HIBP, Intelligence X |
| **Historical** | SecurityTrails (historical DNS), Wayback Machine |

---

## Phase 2: Domain Registration Intel

**WHOIS & Registrant Analysis:**
- WHOIS lookup (registrant name, org, email, dates)
- Registration date and expiration date
- Registrar identification
- Privacy/proxy service detection
- Registrant history (DomainTools historical WHOIS)
- Name server history

**Key Questions:**
- When was the domain registered?
- Has registrant info changed? How many times?
- Is there privacy protection? (May indicate legitimate business or evasion)
- Does the registrant own other domains? (Reverse WHOIS via DomainTools, ViewDNS)

---

## Phase 3: DNS Enumeration

**Complete DNS record collection:**
- A records (IPv4 addresses)
- AAAA records (IPv6 addresses)
- MX records (mail servers)
- TXT records (SPF, DKIM, DMARC, verification tokens)
- NS records (authoritative name servers)
- CNAME records (aliases)
- SOA record (zone authority)

**Historical DNS — SecurityTrails:**
- Previous IP addresses
- Previous name servers
- Previous MX records
- DNS change timeline

**Analysis:**
- Do DNS records point to known hosting providers?
- Are there dangling CNAME records (subdomain takeover risk)?
- What security records exist (SPF, DMARC, DKIM)?
- Has the domain changed hosting frequently?

---

## Phase 4: Subdomain Discovery

**Execute multiple enumeration techniques:**

1. **Certificate Transparency (crt.sh)** — All certificates ever issued for the domain
2. **DNS brute-force (subfinder)** — Common subdomain wordlists
3. **Passive DNS (SecurityTrails)** — Historical subdomain records
4. **DNS aggregator (DNSDumpster)** — Combined passive intelligence
5. **Amass passive** — Multi-source subdomain enumeration

**For each discovered subdomain:**
- Resolve to IP address
- Check if active (HTTP response)
- Identify hosting provider
- Note any interesting naming patterns (dev, staging, admin, api, vpn, mail)

**Quality Gate:**
- [ ] All 5 enumeration techniques executed
- [ ] Results deduplicated and merged
- [ ] Each subdomain resolved and status checked
- [ ] 95%+ confidence in subdomain coverage

---

## Phase 5: Technology & Hosting Fingerprint

**For the primary domain and key subdomains:**

**Web Technology — BuiltWith, Wappalyzer, Netcraft:**
- Web framework (React, Angular, Vue, etc.)
- CMS (WordPress, Drupal, etc.)
- Analytics (GA, Mixpanel, etc.)
- CDN (Cloudflare, Akamai, Fastly)
- Hosting provider
- Server software (nginx, Apache, etc.)
- JavaScript libraries
- Advertising/tracking

**Infrastructure — Shodan, Censys:**
- Open ports and services
- SSL/TLS certificate details (issuer, expiry, SAN entries)
- Server banners and versions
- Known vulnerabilities on exposed services

**IP Intelligence:**
- Geolocation
- ASN and network owner
- Reverse DNS
- Other domains on same IP (shared hosting detection)

---

## Phase 6: Certificate Transparency

**crt.sh Analysis:**
- All certificates ever issued for the domain
- Wildcard certificates (*.domain.com)
- SAN (Subject Alternative Name) entries — reveals related domains
- Certificate issuers (Let's Encrypt vs. commercial CA)
- Certificate timeline (when were certs first issued?)

**CertStream / Cert Spotter:**
- Real-time certificate issuance monitoring
- Newly registered subdomains via CT logs

**Analysis:**
- Do SAN entries reveal hidden subdomains or related domains?
- When was the first certificate issued? (Domain age indicator)
- Are there certificates for non-obvious domains? (Shadow IT)

---

## Phase 7: Reputation & Threat Intel

**VirusTotal:**
- Domain scan results
- Associated malware detections
- Community comments and votes
- URL scan history
- Related domains/IPs flagged

**URLScan.io:**
- Live page screenshot
- Technology detection
- Redirect chains
- Third-party requests

**AbuseIPDB:**
- Abuse reports for domain IPs
- Confidence of abuse score
- Report categories

**GreyNoise:**
- Is the domain's IP seen scanning the internet?
- Classification: benign, malicious, or unknown

**PhishTank:**
- Is the domain listed as a phishing site?
- Historical phishing reports

---

## Phase 8: Synthesis

**Infrastructure Map:**
- Domain → subdomains → IPs → hosting providers
- Technology stack per subdomain
- Certificate relationships
- DNS dependency chain

**Risk Assessment:**
- Domain age and stability
- Security posture (SPF, DMARC, DKIM, HTTPS, HSTS)
- Exposed services and vulnerabilities
- Abuse/threat intel flags
- Breach exposure

**Related Domains:**
- Same registrant
- Same IP/hosting
- Certificate SAN relationships
- Same name servers

**Report Structure:**
1. Domain Profile (registration, age, registrant)
2. DNS Infrastructure (records, name servers, mail)
3. Subdomain Map (with status and purpose)
4. Technology Stack
5. Certificate Analysis
6. Reputation & Threat Intel
7. Related Domains
8. Risk Assessment
9. Recommendations

---

## Checklist

- [ ] Authorization verified
- [ ] WHOIS/registration analyzed
- [ ] Complete DNS enumeration done
- [ ] Subdomain discovery (5 techniques)
- [ ] Technology fingerprinting complete
- [ ] Certificate transparency analyzed
- [ ] Reputation/threat intel checked
- [ ] Related domains mapped
- [ ] Risk score assigned
- [ ] Report drafted
