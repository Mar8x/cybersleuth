# Entity OSINT Lookup Workflow

**Purpose:** Technical intelligence gathering on domains, IPs, infrastructure, and threat entities.

**Authorization Required:** Explicit authorization, defined scope, legal compliance confirmed.

**Note:** "Entity" refers to domains, IPs, infrastructure, threat actors — NOT individuals.

---

## Phase 1: Entity Classification

**Entity Types:**
1. **Domains** - company.com, subdomain.company.com
2. **IP Addresses** - Single IPs or CIDR ranges
3. **ASN** - Autonomous System Numbers
4. **URLs** - Specific web addresses
5. **File Hashes** - MD5, SHA1, SHA256
6. **Threat Actors** - Known malicious groups
7. **Infrastructure** - C2 servers, botnets

**Extract base information:**
- Primary identifier
- Associated identifiers
- Initial reputation/context

---

## Source Reference

Use these specific sources per investigation phase:

| Investigation Area | Sources |
|-------------------|---------|
| **Domain/DNS** | SecurityTrails, DomainTools, crt.sh, DNSDumpster, ViewDNS, Robtex, CertStream |
| **IP Reputation** | Shodan, Censys, AbuseIPDB, GreyNoise, BinaryEdge, ZoomEye, Criminal IP, IPinfo |
| **Malware Analysis** | VirusTotal, Hybrid Analysis, ANY.RUN, MalwareBazaar, URLhaus, URLScan.io |
| **Vulnerability** | NVD, CVE, Exploit-DB, CISA KEV |
| **Threat Intel** | Pulsedive, IBM X-Force, Cisco Talos, AlienVault OTX, ThreatFox |
| **Dark Web/Leak** | Ahmia, HIBP, Intelligence X, DeHashed |
| **Frameworks** | MITRE ATT&CK, D3FEND, ATLAS |
| **Botnet/C2** | Feodo Tracker, SSL Blacklist |
| **Government** | CISA, UK NCSC, ENISA |

---

## Phase 2: Domain & URL Intelligence

**Domain Analysis:**
- WHOIS lookup (registrant, dates, name servers)
- DNS records (A, AAAA, MX, NS, TXT, CNAME)
- Subdomain enumeration (crt.sh, subfinder, amass)
- Historical DNS (SecurityTrails, Wayback)

**URL Analysis:**
- URLScan.io (screenshot, technologies, redirects)
- VirusTotal (reputation, scan results)
- Web technologies (Wappalyzer, BuiltWith)

---

## Phase 3: IP Intelligence

**Geolocation & Attribution:**
- IPinfo (location, ASN, organization)
- Hurricane Electric BGP Toolkit (routing, peers)
- RIPE Stat (network statistics)

**Reputation:**
- AbuseIPDB (abuse reports, confidence score)
- AlienVault OTX (threat intelligence)
- Blacklist checking (MXToolbox)

**Service Discovery:**
- Shodan (ports, services, vulnerabilities)
- Censys (certificates, protocols)

---

## Phase 4: Threat Intelligence

**Research areas to cover (run in parallel where possible):**

- **Malware Analysis** — VirusTotal, Hybrid Analysis, ANY.RUN, MalwareBazaar, URLhaus, URLScan.io: detection ratios, malware families, behavioral indicators
- **IP/Domain Reputation** — AbuseIPDB (abuse reports), GreyNoise (scanner classification), Shodan (exposed services), Censys, BinaryEdge, Criminal IP: confidence scores, historical flags
- **Threat Actor Profiling** — MITRE ATT&CK, Pulsedive, IBM X-Force, AlienVault OTX: TTPs, related IOCs, campaign timelines
- **Vulnerability & Exploit Intel** — NVD, CVE databases, Exploit-DB, CISA KEV: exploitability and active exploitation status
- **C2 & Botnet Detection** — Feodo Tracker, SSL Blacklist, Cisco Talos, ThreatFox: C2 indicators, botnet participation, known malicious infrastructure
- **Infrastructure Relationship Mapping** — SecurityTrails, DomainTools, Robtex, ViewDNS: co-hosted domains, shared infrastructure
- **Dark Web & Leak Exposure** — Ahmia, HIBP, Intelligence X, DeHashed: breach dates, data types exposed, underground forum mentions
- **Attribution Verification** — CISA advisories, UK NCSC, ENISA: classify findings as active vs. historical vs. false positive

---

## Phase 5: Network Infrastructure

**Network Mapping:**
- ASN and network blocks
- Hosting providers
- BGP routing information
- Traceroute analysis

**Cloud Detection:**
- AWS, Azure, GCP IP range checks
- Cloud storage enumeration (with authorization)
- CDN identification

---

## Phase 6: Email Infrastructure

**MX Analysis:**
- Mail server identification
- Email provider detection
- Security records (SPF, DMARC, DKIM)
- Blacklist status

---

## Phase 7: Correlation & Pivot Analysis

**Relationship Discovery:**
- Domains sharing same IP
- Domains sharing same registrant
- Certificate relationships
- ASN correlations

**Pivot Points:**
- WHOIS email → Other domains
- IP address → Other hosted domains
- Name servers → All hosted domains
- Certificate details → Similar certs

**Timeline Construction:**
- Registration dates
- First seen in threat intel
- Infrastructure changes
- Ownership changes

---

## Phase 8: Analysis & Reporting

**Threat Classification:**
- Legitimate / Suspicious / Malicious / Compromised / Sinkholed

**Confidence Levels:**
- High: Multiple independent confirmations
- Medium: Some supporting evidence
- Low: Speculative or single source

**Report Structure:**
1. Entity Profile
2. Technical Infrastructure
3. Reputation & Intelligence
4. Relationships & Connections
5. Threat Assessment
6. Timeline
7. Risk Assessment
8. Recommendations
9. IoCs (domains, IPs, hashes)

---

## Checklist

- [ ] Authorization verified
- [ ] Entity classified
- [ ] WHOIS/DNS completed
- [ ] IP intelligence gathered
- [ ] Threat intel consulted
- [ ] VirusTotal searched
- [ ] Historical data reviewed
- [ ] Relationships mapped
- [ ] Risk score assigned
- [ ] Report drafted
