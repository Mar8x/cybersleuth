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
| **Subdomain Discovery** | CertSpotter, Censys, SecurityTrails, DNSDumpster, subfinder, amass |
| **Technology/Hosting** | BuiltWith, Wappalyzer, Netcraft, Shodan, Censys |
| **Certificate Transparency** | CertSpotter (primary), Censys (secondary), CertStream |
| **Security Contact** | security.txt (RFC 9116) |
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

1. **Certificate Transparency (CertSpotter + Censys)** — All certificates ever issued for the domain
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

**Tech-Stack Intelligence — `career_sources`, `job_postings`, `github_recon`:**
- Run `career_sources(domain)` to find the ATS platform (Greenhouse, Lever, Ashby, Workable, Teamtailor, Personio, etc.); note ATS choice as a regional/stage signal
- Run `job_postings(board_url)` for each ATS with a public API — pass the `board_url` from `career_sources` output; the ATS and handle are identified automatically
- Run `github_recon(org)` if the company has a public GitHub organisation — languages, dep files, and CI workflow signals are high-confidence ground truth
- Corroborate: `kafka.*` or `data.*` CT log subdomains confirm data-platform claims; `auth0.*`/`okta.*` subdomains confirm identity provider claims; MX/TXT records confirm email and SSO tooling
- Methodology and confidence calibration: `cybersleuth://tech-stack-recon`

---

## Phase 6: Certificate Transparency

**CertSpotter + Censys (`certificate_info`):**
- All certificates ever issued for the domain (merged, deduplicated across both sources)
- Wildcard certificates (*.domain.com)
- SAN (Subject Alternative Name) entries — reveals related domains
- Certificate issuers (Let's Encrypt vs. commercial CA)
- Certificate timeline (when were certs first issued?)
- `sources_used` in results shows which CT sources responded

**Analysis:**
- Do SAN entries reveal hidden subdomains or related domains?
- When was the first certificate issued? (Domain age indicator)
- Are there certificates for non-obvious domains? (Shadow IT)

**Security Contact (`security_txt`):**
- Fetch and parse security.txt (RFC 9116) for the target domain
- Contact channels (email, URL, phone) for responsible disclosure
- Security policy URL, PGP encryption key link, disclosure deadline
- Check `is_expired` field — an expired security.txt is a maintenance red flag

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

## Phase 8: LLM / AI Surface Assessment

Run this phase whenever the target shows signs of AI/LLM usage — `chat.*`, `ai.*`, `copilot.*` subdomains in CT logs, AI SDK references in JS bundles, or AI-related job postings / GitHub repos. The methodology and signal catalogue live in `cybersleuth://llm-recon`.

**Three authorization tiers, three tools:**

| Tool | Scope | When to use |
|------|-------|-------------|
| `llm_fingerprint(url)` | Passive — observes headers, CSP, JS bundles, API path error shapes | Always safe; default for any LLM-related surface |
| `llm_probe_public_chat(url, query="Hello")` | Benign — one neutral user-style message | Public chat surfaces the target exposes to anonymous users; confirm liveness + capture model self-disclosure |
| `llm_security_probe(url, authorized=True, authorization_note=...)` | Authorization-gated — OWASP LLM01/02/07 probes | Only under written authorization (engagement, in-scope pentest) |

**What to record per finding:**
- Provider(s) and framework(s) detected, with source attribution (header / CSP / JS / api-path)
- Model strings and likely model family
- Leaked client-side credentials (redact in reports — record the kind, source URL, and last 4 chars only)
- Public LangSmith/Helicone trace URLs (LLM02)
- MCP exposure — any internet-reachable MCP server is **HIGH** until proven otherwise (CVE-2025-49596 reference)

**OWASP LLM Top 10:2025 mapping:** see `cybersleuth://llm-recon` for the full table.

**Quality Gate:**
- [ ] Passive fingerprint run against every LLM-related subdomain identified in Phases 4–6
- [ ] All leaked credentials documented (with redaction) and severity-rated
- [ ] MCP exposure separately recorded if detected
- [ ] Active probing (tiers 2–3) used only with documented justification

---

## Phase 9: Privacy & Data Handling Assessment

**`privacy_policy(domain)` + `tracker_scan(domain)`:**

1. **Document discovery** — privacy policy, ToS, cookie policy, DPA (if published)
2. **Jurisdiction detection** — GDPR, CCPA/CPRA, LGPD, PIPL, PIPEDA keyword markers
3. **OPP-115 practice categories** — data collection, use, sharing, retention, security,
   user rights, policy change, DNT, international audiences
4. **Compliance gap analysis** — mandatory disclosure elements per jurisdiction
   (GDPR Art. 13/14, CCPA 1798.135, etc.); missing elements flagged
5. **AI/LLM training clause detection** — red-flag phrases graded by severity;
   EU AI Act Art. 53 training data summary requirement (live Aug 2025)
6. **Tracker scan** — ~30 embedded tracker entries; advertising, analytics,
   session replay, fingerprinting, consent management, AI/LLM categories
7. **Contradiction analysis** — stated policy vs. detected trackers:
   - Meta Pixel + "no sharing" claim → CCPA/HIPAA flag
   - GA4 + "no EU transfer" claim → GDPR Art. 44 violation pattern
   - FingerprintJS + no consent banner → GDPR Recital 30 violation
   - Advertising trackers + no consent management platform → ePrivacy breach
8. **Cross-reference** with `tech_stack` findings, `certificate_info` subdomains
   (`analytics.*`, `pixel.*`), and `dns_records` TXT verification tokens

**Key Questions:**
- What jurisdictions does the policy claim to cover, and what elements are missing?
- Does the stated data sharing policy match the trackers embedded in the page?
- Is user data used for AI/ML training? Is this disclosed?
- Does the analytics/marketing stack corroborate or contradict privacy claims?

---

## Phase 10: Synthesis

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
- Privacy compliance posture (jurisdiction gaps, tracker contradictions)

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
7. LLM / AI Surface (when applicable)
8. Privacy & Data Handling
9. Related Domains
10. Risk Assessment
10. Recommendations

---

## Checklist

- [ ] Authorization verified
- [ ] WHOIS/registration analyzed
- [ ] Complete DNS enumeration done
- [ ] Subdomain discovery (5 techniques)
- [ ] Technology fingerprinting complete
- [ ] Certificate transparency analyzed
- [ ] Reputation/threat intel checked
- [ ] LLM/AI surface assessed (if applicable)
- [ ] Related domains mapped
- [ ] Risk score assigned
- [ ] Report drafted
