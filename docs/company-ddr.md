# Company Due Diligence Report (DDR) Workflow

**Purpose:** Full 5-phase OSINT due diligence producing a CyberSleuth DDR PDF.
**Format reference:** `reports.md` (DDR structure, confidence framework, eisvogel PDF template).
**Requires:** CyberSleuth MCP server running with relevant API keys set.

---

## Machine Portability

This workflow is self-contained and PAI-independent. It runs in any Claude Code session
with the CyberSleuth MCP server installed. Research parallelism uses Claude Code's native
`Agent` tool; persistence uses CyberSleuth `save_note` / `load_investigation` tools.

**Key substitutions vs. PAI playbook:**

| PAI construct | CyberSleuth-native equivalent |
|---|---|
| `Task({ subagent_type: "PerplexityResearcher" })` | `Agent({ subagent_type: "ClaudeResearcher" })` |
| `~/.claude/MEMORY/WORK/` paths | `save_note` / `load_investigation` MCP tools |
| Perplexity/Gemini/Grok API researcher agents | `research` MCP tool (Perplexity Sonar) + `web_search` |

---

## 5-Phase Overview

```
Phase 1: Domain Discovery (BLOCKING — quality gate before proceeding)
Phase 2: Infrastructure Reconnaissance (CyberSleuth MCP tools)
Phase 3: Parallel Research Fleet (Claude Code Agent calls)
Phase 4: Claims Verification + Risk Scoring
Phase 5: DDR Synthesis → PDF
```

---

## Phase 1: Domain Discovery (BLOCKING)

Run these in parallel before any other phase. Do not proceed until ≥95% confidence all
domains are found.

1. `certificate_info` — CT logs enumerate subdomains
2. `web_search` — search engine discovery of related domains and TLDs
3. `whois_lookup` — registrant correlation for related TLD discovery
4. Social media link extraction — pull all website links from LinkedIn, X, GitHub profiles
5. Business registration filings — extract website fields from official records
6. Check common TLD variants: `.com`, `.net`, `.io`, `.eu`, `.co`, `.partners`, `.capital`

**Quality gate:**
- [ ] All 6 techniques executed
- [ ] Investor/investor-facing portal found (or high confidence none exists)
- [ ] 95%+ confidence in domain coverage

**DO NOT PROCEED until gate passes.**

---

## Phase 2: Infrastructure Reconnaissance

Run all tools in parallel per discovered domain:

```python
# Per domain
dns_records(domain)                          # A, AAAA, MX, NS, TXT, SOA, CNAME
certificate_info(domain, include_expired=True)
as_intelligence(domain)                      # ASN, hosting flag
reverse_dns(ip)                              # per resolved IP
builtwith_lookup(domain)                     # tech stack
favicon_hash(domain)                         # → Shodan query input
vt_domain_report(domain)
urlscan_history(domain)

# After favicon hash
shodan_search(f"http.favicon.hash:{hash}")   # origin IP discovery

# M365 tenant discovery (manual — see cybersleuth.md §M365)
# GET https://login.microsoftonline.com/getuserrealm.srf?login=x@{domain}&xml=1
# GET https://login.microsoftonline.com/{domain}/.well-known/openid-configuration
```

Save infrastructure findings: `save_note(target, content)`

---

## Phase 3: Parallel Research Fleet

Spawn all agents in a single message (parallel execution). Each uses Claude Code's built-in
`WebSearch` — no external API keys required beyond what CyberSleuth already needs.

### Pod A — Business Legitimacy (4 agents)

```python
Agent(subagent_type="ClaudeResearcher", prompt="""
Search OpenCorporates, company registries (Companies House, SEC EDGAR, local jurisdiction),
and SAM.gov for all legal entities of [COMPANY]. Return: entity names, USREOU/company numbers,
jurisdiction, status, directors, founding dates, ownership structure.
""")

Agent(subagent_type="ClaudeResearcher", prompt="""
Check [COMPANY] against OFAC SDN list, EU Consolidated Sanctions, UN sanctions list,
UK OFSI, OpenSanctions.org, and Interpol notices. Also check all named executives.
Report any hits, near-matches, or associated entities.
""")

Agent(subagent_type="ClaudeResearcher", prompt="""
Research leadership of [COMPANY]: map founders, CEO, CTO, board members via LinkedIn,
company website, and news coverage. Verify career history, credentials, prior companies,
and any adverse findings (lawsuits, failed companies, regulatory actions).
""")

Agent(subagent_type="ClaudeResearcher", prompt="""
Search for legal proceedings involving [COMPANY] — court records, regulatory enforcement
actions, bankruptcy filings, IP disputes. Check Google for "[company] lawsuit", "[company]
fraud", "[company] regulatory". Check Racket.report and similar databases.
""")
```

### Pod B — Reputation & Market (4 agents)

```python
Agent(subagent_type="ClaudeResearcher", prompt="""
Analyze media coverage of [COMPANY]: volume, sentiment, earned vs. promotional. Search
Google News, search "[company] review", "[company] problems", "[company] scam". Check
Glassdoor for employee sentiment. Flag any negative patterns.
""")

Agent(subagent_type="ClaudeResearcher", prompt="""
Research [COMPANY] historical timeline via Wayback Machine, LinkedIn founding date, domain
registration, earliest web presence. Identify any rebrands, pivots, name changes, or
predecessor entities. Note any discrepancies between claimed and evidenced founding dates.
""")

Agent(subagent_type="ClaudeResearcher", prompt="""
Map corporate ownership and investment history of [COMPANY]: parent companies, investors,
acquisition history, subsidiary relationships. Check Crunchbase, OpenOwnership, GLEIF LEI
registry, and press releases. Identify any holding company chains or opaque structures.
""")

Agent(subagent_type="ClaudeResearcher", prompt="""
Assess technology and security posture of [COMPANY]: tech stack signals from job postings,
GitHub presence, open source contributions, developer community engagement. Check for
GDPR/ISO/SOC2 certifications on official certification registries (not self-reported).
""")
```

### Pod C — Verification + Threat Intel (4 agents)

```python
Agent(subagent_type="ClaudeResearcher", prompt="""
Verify key claims made by [COMPANY]: partnerships (check partner directories, joint press
releases), certifications (check issuing body registries), customer logos (search for
independent confirmation), headcount claims (cross-ref LinkedIn). Flag unverifiable claims.
""")

Agent(subagent_type="ClaudeResearcher", prompt="""
Check [COMPANY] domain(s) and IP infrastructure against threat intelligence: search
ransomware.live for any mentions, check Hudson Rock Cavalier for infostealer/breach records,
search HIBP for domain exposure. Report any hits with dates and severity.
""")

Agent(subagent_type="ClaudeResearcher", prompt="""
Research [COMPANY] competitive landscape and market position: identify main competitors,
market share signals, customer references, analyst coverage. Assess whether the company
is a credible player in its stated market.
""")

Agent(subagent_type="ClaudeResearcher", prompt="""
Final sweep for [COMPANY]: search for any findings not covered above. Check BBB complaints,
FTC enforcement database, state AG actions, industry-specific regulators. Search "[company]
CEO name fraud", "[company] complaints", "[company] warning". Return anything notable.
""")
```

Use `research(question)` for any question that benefits from Perplexity Sonar synthesis
(web-grounded, cited answers). Use `web_search(query)` for raw source-level results.

---

## Phase 4: Claims Verification + Risk Scoring

Compile all Phase 2–3 findings. For each material claim in the target's marketing/website:

| Claim | Source | Verified? | Notes |
|-------|--------|-----------|-------|
| Founding year | Registry vs. Wayback | ✓/✗ | |
| Headcount | LinkedIn vs. claimed | ✓/✗ | |
| Certifications | Issuing body registry | ✓/✗ | |
| Key partnerships | Partner directories | ✓/✗ | |

**Risk scoring — 5 dimensions (1–5 each, 25 = max):**

| Dimension | Score | Rationale |
|-----------|-------|-----------|
| Corporate Transparency | /5 | Registration, ownership, beneficial owner clarity |
| Claims Integrity | /5 | Verified vs. unverified/misleading claims |
| Security Posture | /5 | DNSSEC, certs, breach history, MX hygiene |
| Threat Exposure | /5 | Ransomware, infostealer, sanctions, court records |
| Operational Maturity | /5 | History depth, tech stack signals, team tenure |

Score bands: 20–25 LOW · 14–19 MEDIUM · 8–13 HIGH · 1–7 CRITICAL

---

## Phase 5: DDR Synthesis → PDF

Write the DDR markdown following `reports.md` exactly:

- YAML frontmatter: `titlepage-color: "1a1a2e"`, `titlepage-rule-color: "e94560"`
- Section order: Subject Overview {-}, Executive Summary, Risk Advisory (ASSESSED),
  Corporate Structure (HIGH), People Intelligence (MEDIUM), Claims Verification (MEDIUM),
  Assessment Framework (ASSESSED), Pattern Analysis (ASSESSED),
  Infrastructure Intelligence (HIGH), Sources Index {-}, Disclaimer {-}
- Confidence tag on every section header: `[HIGH]` / `[MEDIUM]` / `[ASSESSED]`
- Risk Advisory box with overall risk level + recommendation sentence
- Assessment Framework table using the Phase 4 scores

Render:
```bash
pandoc YYYY-MM-DD_<Target>_DDR.md -o YYYY-MM-DD_<Target>_DDR.pdf \
  --template eisvogel --pdf-engine=xelatex
```

Save final notes: `save_note(target, "DDR complete — <file path>")`

---

## Checklist

- [ ] Phase 1 domain quality gate passed
- [ ] All CyberSleuth MCP tools run (Phase 2)
- [ ] 12 research agents completed (Phase 3)
- [ ] Every material claim checked (Phase 4)
- [ ] Confidence tag on every DDR section
- [ ] Risk Advisory present
- [ ] Assessment Framework scored
- [ ] PDF rendered and file size >50K (indicates successful render)
- [ ] `save_note` called with completion reference
