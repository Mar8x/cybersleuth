# Company OSINT Lookup Workflow

**Purpose:** Comprehensive business intelligence gathering for authorized research, due diligence, or security assessments.

**Authorization Required:** Explicit authorization, defined scope, legal compliance confirmed.

---

## Phase 1: Authorization & Scope

**VERIFY BEFORE STARTING:**
- [ ] Explicit authorization from client
- [ ] Clear scope (target company, information types, purpose)
- [ ] Legal compliance confirmed
- [ ] Documented in engagement paperwork

**STOP if any checkbox is unchecked.**

---

## Source Reference

Use these specific sources per investigation phase:

| Investigation Area | Sources |
|-------------------|---------|
| **Business Registration** | OpenCorporates, SEC EDGAR, Companies House, SAM.gov |
| **Financial Intel** | Crunchbase, PitchBook, D&B, AlphaSense |
| **Employee Intel** | LinkedIn, ZoomInfo, Apollo, RocketReach, Hunter.io |
| **Legal/Court** | PACER, CourtListener, UniCourt |
| **Patent/IP** | USPTO, Google Patents, Espacenet, Lens.org |
| **Tech Profiling** | BuiltWith, Wappalyzer, Netcraft |
| **Competitive** | SimilarWeb, SEMrush |
| **News/Media** | GDELT, MediaCloud, Google News |
| **Government Contracts** | USAspending, GovTribe |
| **Sanctions** | OFAC, EU Sanctions, OpenSanctions |
| **Corporate Ownership** | OpenOwnership, GLEIF LEI |
| **Startup/VC** | Dealroom, Tracxn, Owler, Wellfound |

---

## Phase 2: Entity Identification

**Collect initial identifiers:**
- Legal company name(s) and DBAs
- Known domains
- Known personnel (founders, executives)
- Geographic location
- Industry/sector
- Corporate structure

---

## Phase 3: Business Registration Research

**Corporate filings:**
- Secretary of State registrations (all relevant states)
- Federal registrations (SEC if applicable)
- Foreign qualifications
- DBA/fictitious name registrations

**Regulatory registrations:**
- Industry-specific licenses
- Professional certifications
- Securities registrations

---

## Phase 4: Domain & Digital Assets

**Domain enumeration (7 techniques):**
1. Certificate Transparency logs (crt.sh)
2. DNS enumeration (subfinder, amass)
3. Search engine discovery
4. Social media bio links
5. Business registration website fields
6. WHOIS reverse lookups
7. Related TLD checking

For detailed domain investigation, see `domain-workflow.md`.

---

## Phase 5: Technical Infrastructure

**For each discovered domain:**
- DNS records (A, MX, TXT, NS)
- IP resolution and geolocation
- Hosting provider identification
- SSL/TLS certificate analysis
- Technology stack (BuiltWith, Wappalyzer)
- Security posture (SPF, DKIM, DMARC)

---

## Phase 6: Intelligence Synthesis

**Consolidate findings:**
- Business legitimacy indicators
- Leadership credibility assessment
- Financial health signals
- Regulatory compliance status
- Reputation analysis
- Red flags identified

**Research areas to cover (run in parallel where possible):**
- Business Registration — verify legal entity name, jurisdiction, status, filing history
- Leadership & Key Personnel — founders, executives, career histories, board memberships
- Financial Intelligence — funding history, revenue signals, credit ratings
- Legal & Regulatory — court proceedings, enforcement actions, lawsuits
- Patent & Intellectual Property — patent portfolio, technology moat
- Tech Profiling & Infrastructure — frameworks, analytics, CDNs, hosting
- Media & News Coverage — earned vs. paid/promotional; sentiment over time
- Competitive Intelligence — market position, key competitors, web traffic
- Sanctions & Compliance — OFAC SDN list, EU Consolidated Sanctions, OpenSanctions
- Corporate Ownership — beneficial ownership structure, VC/investment history

**Report structure:**
- Executive summary
- Company profile
- Leadership analysis
- Financial assessment
- Regulatory status
- Risk assessment
- Sources consulted

---

## Quality Gates

**Before finalizing report:**
- [ ] All domains discovered and analyzed
- [ ] Business registrations verified
- [ ] Leadership backgrounds researched
- [ ] Multi-source verification (3+ sources per claim)
- [ ] Red flags investigated

---

**Related Workflows:** `domain-workflow.md` for detailed domain and infrastructure investigation.
