# CyberSleuth Report Generation Guide

This document defines the full investigation workflow: from structured input (Investigation Briefing), through OSINT execution, to final report output. It is the authoritative reference for how investigations are initiated, how findings are organized, and how reports are formatted and delivered.

---

## Investigation Briefing (Input Document)

Every investigation starts with a **briefing document** -- a structured input that captures preliminary research, identifies targets, and defines specific OSINT tasks. The briefing is typically prepared by a human analyst (or by an AI from web research) *before* the OSINT tools are engaged. It front-loads context so the investigation is focused and efficient.

### Purpose

The briefing is **not** a report. It is a working document that:
- Organizes what is already known from preliminary web research
- Identifies what needs to be verified or investigated further with OSINT tools
- Defines specific, actionable tasks for each tool category
- Flags red flags and patterns already observed
- Provides a URL/source inventory so nothing is missed

### Briefing Structure Template

```markdown
# [SUBJECT] INVESTIGATION BRIEFING
## Context Document for Claude Code + Cybersleuth MCP Investigation
**Date:** YYYY-MM-DD
**Status:** Preliminary research complete via web search. OSINT tool validation needed.

---

## 1. EXECUTIVE SUMMARY

[2-3 paragraph overview of the subject. What is it? Why is it being investigated?
What preliminary concerns have been identified? Keep factual but flag the core
hypothesis or concern driving the investigation.]

---

## 2. ENTITY MAP

### Primary Entities
| Entity | Jurisdiction | Registration | Status |
|---|---|---|---|
| [Entity name] | [Country/region] | [Reg number, founded date] | [Active/Dormant/Liquidated] |

### Corporate Structure
[Describe ownership chain, parent-subsidiary relationships, share capital,
directors, and any structural observations (e.g., virtual offices, shell
entities, multi-jurisdiction complexity).]

---

## 3. KEY PEOPLE

### [Person Name] -- [Role]
- **Nationality:** [Known or presumed]
- **Location:** [Current known location(s)]
- **LinkedIn:** [URL if known]
- **Background:** [What is claimed -- employment history, credentials, expertise]
- **Classification:** [Your assessment: technical founder / sales exec / dealmaker / unknown]
- **Red flags:** [Any concerns: unverifiable claims, missing credentials, gaps]
- **OSINT needed:** [Specific tasks: Companies House search, patent search, LinkedIn verification, etc.]

[Repeat for each key person.]

---

## 4. DOMAINS TO INVESTIGATE

### Primary Targets
| Domain | Purpose | Priority |
|---|---|---|
| [domain.com] | [Main website / token site / parent company] | HIGH |

### Secondary Targets
| Domain | Purpose | Priority |
|---|---|---|
| [domain.net] | [Possibly related / unrelated -- verify] | LOW |

---

## 5. CLAIMS REQUIRING OSINT VALIDATION

### Claim N: "[Exact claim text]"
- **Source:** [Where the claim appears -- website, LinkedIn article, marketing materials]
- **Status:** [Unverified / Partially verified / Contradicted]
- **OSINT angle:** [How to verify: which databases, registries, archives to check]

[Repeat for each extraordinary or material claim.]

---

## 6. SPECIFIC CYBERSLEUTH INVESTIGATION TASKS

### Domain Intelligence
```
For each domain ([list domains]):
- WHOIS history (registration dates, registrant changes, registrar transfers)
- DNS records (A, MX, NS, TXT/SPF/DKIM/DMARC)
- SSL/TLS certificate history (who issued, when, SANs)
- IP geolocation and hosting provider (AS intelligence)
- Subdomain enumeration (via CT logs)
- Technology stack fingerprinting (BuiltWith, URLScan)
```

### Wayback Machine Analysis
```
Priority snapshots needed:
- [domain]: Earliest available snapshot (verify claimed founding date)
- [domain]: Content changes over time (did claims appear/disappear?)
- [domain]: Historical customer references, case studies, partner logos
- [new-domain]: First appearance date (when did the pivot begin?)
```

### Patent Search
```
Search EPO Espacenet, WIPO PATENTSCOPE, USPTO, [jurisdiction patent office] for:
- Inventor: "[Name]" + [technology keywords]
- Applicant: "[Company name]"
- Keywords: [relevant technical terms] in [jurisdictions]
```

### Certificate Transparency Logs
```
Search crt.sh for:
- *.[domain1]
- *.[domain2]
Check certificate issue dates, CAs used, SANs, and cross-domain certificates.
```

### People OSINT
```
[Person Name]:
- UK Companies House directorship search
- [Jurisdiction] commercial registry search
- LinkedIn verification (employment dates, endorsements)
- Academic publication search ([university])
- Patent inventor search
- GitHub / code repository presence
- Conference speaker databases
```

### Social Footprint Analysis
```
For all key names:
- Twitter/X presence and history
- GitHub presence
- Conference speaker databases (BSides, DEF CON, Black Hat, RSA, etc.)
- Published CVEs, security advisories, or responsible disclosures
- Academic papers (Google Scholar, IEEE, ACM)
```

---

## 7. PATTERN ANALYSIS -- WHAT WE'RE LOOKING FOR

### Red Flag Indicators (already identified)
1. [Flag 1 -- e.g., unverifiable military-grade claims]
2. [Flag 2 -- e.g., original technical founder departed]
3. [Flag N]

### Historical Pattern Matches
[Name similar historical cases and explain the pattern match.
E.g., KodakCoin (legacy brand + token), Sirin Labs (crypto hardware promise),
Long Island Blockchain (name pivot for hype).]

### What OSINT Could Confirm or Refute
- [Question 1 -- e.g., does domain history go back to claimed founding date?]
- [Question 2 -- e.g., do patents actually exist?]
- [Question N]

---

## 8. ASSESSMENT FRAMEWORK

Rate findings on a 1-5 scale across these dimensions:

| Dimension | Question |
|---|---|
| **Technical Legitimacy** | Does the core technology demonstrably exist and work? |
| **Commercial Viability** | Is there evidence of real customers paying for the product? |
| **Team Capability** | Can this team build, maintain, and evolve the product? |
| **Claims Integrity** | Do the extraordinary claims have any supporting evidence? |
| **[Domain-specific]** | [Add dimensions relevant to the specific investigation] |

---

## 9. KEY URLS AND SOURCES

### Company Sites
- [URLs with brief purpose annotations]

### Registry and Corporate Records
- [URLs to registry pages]

### LinkedIn Profiles
- [URLs to key people and company pages]

### Media Appearances
- [Podcasts, articles, press releases]

### Review Platforms
- [Note presence or ABSENCE on Gartner, G2, Trustpilot, etc.]

---

*End of briefing. Feed this document as context to Claude Code with
Cybersleuth MCP for OSINT validation of claims and entities.*
```

### Key Design Principles

1. **Front-load context.** The investigator (human or AI) should be able to read the briefing and immediately understand the subject, the concern, and what needs to be done.
2. **Be specific about OSINT tasks.** Don't just say "investigate domains" -- list the exact domains, the exact record types, and what you're looking for.
3. **Separate claims from facts.** The briefing explicitly marks claims as unverified and defines the OSINT angle to verify each one.
4. **Include the URL inventory.** Every URL found during preliminary research goes in Section 9. This prevents the investigation from missing sources that were found but not yet analyzed.
5. **Flag patterns early.** Section 7 primes the investigator to look for specific patterns. This is hypothesis-driven investigation, not random data collection.

---

## Investigation Workflow

### Phase 1: Briefing Preparation

Collect preliminary intelligence via web search, public registries, and manual review. Organize into the Investigation Briefing template above. This phase does **not** use Cybersleuth OSINT tools -- it uses web search, web fetch, and human analysis.

**Prompt to prepare a briefing:**
> I need to investigate [subject]. Here's what I know so far: [paste initial context, URLs, concerns]. Prepare an Investigation Briefing document following the Cybersleuth briefing template. Research the subject via web search to fill in the entity map, key people, domains, claims, and URLs. Flag red flags and define specific OSINT tasks for each tool category.

### Phase 2: OSINT Investigation

Feed the briefing to Claude Code with Cybersleuth MCP. Execute the OSINT tasks defined in the briefing systematically.

**Prompt to start an investigation from a briefing:**
> Read the briefing file at [path]. Execute the investigation tasks defined in Section 6 using Cybersleuth MCP tools. For each domain, run WHOIS, DNS, certificate transparency, AS intelligence, VirusTotal, Shodan, and URLScan. For people, use web search to verify credentials against Companies House, patent databases, LinkedIn, and conference records. For claims, cross-reference against independent sources. Document all findings.

**Prompt to generate the DDR from investigation findings:**
> Based on the investigation findings, create an OSINT Due Diligence Report following the Cybersleuth report structure. Use the zoom-in methodology: Subject Overview, Executive Summary, Risk Advisory, then analytical sections ordered from high-level (corporate, people, claims) to atomic (infrastructure, DNS, WHOIS). Tag every section with a confidence level (HIGH/MEDIUM/ASSESSED). Include pandoc YAML frontmatter for PDF generation (see report template). End with Sources Index and Disclaimer.

### Phase 3: Benchmarking (optional)

If the DDR reveals claims that need industry context, create a companion benchmarking report.

**Prompt to generate a benchmarking report:**
> Based on the completed Due Diligence Report at [path], create a companion Industry Benchmarking Report. Place the DDR findings in competitive context: identify the market the subject claims to occupy, name real competitors, compare technology generations, certifications, R&D investment, and infrastructure. Reference DDR findings as [DDR, Section N]. Use the same pandoc YAML frontmatter style. The goal is to show what the subject *is not* by measuring it against what the industry expects.

### Phase 4: PDF Delivery

Build PDFs using pandoc with the [eisvogel template](https://github.com/Wandmalfarbe/pandoc-latex-template) and XeLaTeX.

```bash
# Basic build:
pandoc report.md --from markdown --pdf-engine=xelatex \
  --template eisvogel -o report.pdf

# With additional variables:
pandoc report.md --from markdown --pdf-engine=xelatex \
  --template eisvogel -V colorlinks=true -V urlcolor=blue \
  -o report.pdf
```

Watermarks, auto-open, and other convenience features can be wrapped in a local shell function or build script -- but that is outside the scope of this repository.

---

## Report Types

### OSINT Due Diligence Report (DDR)

A comprehensive investigation of an entity (company, individual, product, or token offering) using OSINT tools and web research. The DDR establishes **what the subject is** through intelligence gathering: corporate structure, people, claims verification, patent/IP status, infrastructure analysis, and threat intelligence.

**When to use:** When investigating a company, acquisition target, investment opportunity, vendor, or partnership candidate for credibility, legitimacy, and risk.

**Typical scope:**
- Corporate structure and ownership chain
- Key people and their verifiable credentials
- Claims verification against independent sources
- Patent and intellectual property investigation
- Domain and infrastructure intelligence (DNS, WHOIS, CT logs, Shodan, VirusTotal)
- Assessment framework with scored dimensions
- Pattern analysis comparing findings to known fraud/risk patterns

### Industry Benchmarking Report

A companion report that places DDR findings in competitive and industry context. The benchmarking report establishes **what the subject is not** by measuring it against the state of the art, competitor capabilities, certification standards, and infrastructure norms in its claimed market.

**When to use:** When a DDR has been completed and the reader needs industry context to interpret the findings -- especially when the subject's claims seem disproportionate to observable evidence.

**Typical scope:**
- Market positioning and claimed segment
- Technology generation comparison (then vs. now)
- Competitive landscape with named competitors
- R&D investment comparison
- Industry standard markers (certifications, testing, frameworks)
- Infrastructure comparison against peers
- Patent landscape in the relevant technology area
- Summary scoring table

**Cross-referencing:** The benchmarking report cites findings from the companion DDR using the format `[DDR, Section N]`. It does not repeat the DDR's analysis but leverages it as established fact.

### Other Report Types (extend as needed)

- **Threat Assessment** -- focused on threat landscape for a specific entity or sector
- **Infrastructure Assessment** -- purely technical analysis of domains, hosting, email security, and attack surface
- **Incident Response OSINT** -- rapid OSINT collection in response to a security incident

---

## Report Structure: Zoom-In Methodology

Reports follow a **high-level to atomic-level** structure. The reader starts with conclusions and recommendations (what matters), then progressively zooms into supporting analysis (why it matters), and finally reaches the raw intelligence data (the evidence).

This is deliberate: a CISO or decision-maker can stop reading after the executive summary and risk advisory. An analyst can continue into the detailed sections. A technical reviewer can verify every claim against the atomic-level data and sources.

### Structure Template -- Due Diligence Report

```
Title Page (pandoc/eisvogel YAML frontmatter)
Metadata Page (classification table)
Table of Contents

# Subject Overview {-}              -- What is the entity? Neutral description.
                                       Unnumbered. Includes confidence level guide.

# Executive Summary                 -- Key findings. Written for decision-makers.
                                       2-3 paragraphs + bullet list of key findings.

# Risk Advisory                     -- Overall risk rating and recommendation.
  Confidence: ASSESSED                 Actionable: engage/don't engage/conditional.
                                       Breaks risk into dimensions (technology,
                                       counterparty, investment, claims integrity).

# [Analytical sections]             -- Mid-level analysis. Ordered from most
  Confidence: HIGH or MEDIUM           reader-relevant to most technical.
                                       Examples: Corporate Structure & Timeline,
                                       People Intelligence, Claims Verification,
                                       Patent Investigation.

# Assessment Framework              -- Scored dimensions table (1-5 ratings).
  Confidence: ASSESSED                 Synthesizes all findings into a quantified
                                       framework.

# Pattern Analysis                  -- Compares findings to known historical
  Confidence: ASSESSED                 patterns (fraud typologies, red flags).

# [Atomic/infrastructure sections]  -- Raw OSINT data: WHOIS, DNS, CT logs,
  Confidence: HIGH                     Shodan, VirusTotal, URLScan, AS intel.
                                       Highest confidence. Reproducible queries.

# Sources Index {-}                 -- Tools used (with counts), web sources.
                                       Unnumbered.

# Disclaimer {-}                    -- Model, tooling, methodology, limitations.
                                       Unnumbered.
```

### Structure Template -- Benchmarking Report

```
Title Page (pandoc/eisvogel YAML frontmatter)
Metadata Page (classification table, companion report reference)
Table of Contents

# Preface {-}                       -- Relationship to companion DDR.
                                       Unnumbered.

# Executive Summary                 -- Central finding. Industry context in brief.

# [Market and technology sections]  -- Ordered from broad context to specific
                                       comparisons. Examples: Market Definition,
                                       Technology Generations, Competitive Landscape.

# [Standards and certification]     -- Industry standard markers, testing bodies,
                                       certification requirements.

# [Infrastructure comparison]       -- Side-by-side infrastructure analysis
                                       against named competitors.

# Summary Table                     -- Comparison matrix: subject vs. competitors
                                       across all dimensions.

# Conclusion                        -- Synthesis. Answers the core question.

# Sources {-}                       -- Competitor data, testing bodies, standards,
                                       DDR section references. Unnumbered.

# Disclaimer {-}                    -- Model, tooling, methodology, limitations.
                                       Unnumbered.
```

### Section Ordering Principle

**Zoom in from context to evidence:**

1. **What should the reader do?** (Executive Summary, Risk Advisory / Conclusion)
2. **Why?** (Analytical sections -- corporate, people, claims, patents)
3. **How do we know?** (Assessment scoring, pattern analysis)
4. **Show me the data.** (Infrastructure, DNS, WHOIS, CT logs, Shodan)
5. **Where did it come from?** (Sources, Disclaimer)

Analytical and assessed sections come *before* raw data sections. This is counterintuitive for an engineer ("show me the data first") but correct for the audience (decision-makers who need the "so what" before the evidence).

---

## Confidence Framework

Every major section must carry a confidence tag immediately below its heading. Use italicized text:

```markdown
*Confidence: HIGH -- derived from [source description].*
```

### Confidence Levels

| Level | Meaning | Typical sources |
|-------|---------|-----------------|
| **HIGH** | Verifiable facts from authoritative public records. Reproducible queries. | Corporate registries, patent databases, DNS/WHOIS records, Certificate Transparency logs, Shodan, VirusTotal |
| **MEDIUM** | Cross-referenced web research where sources are credible but some ambiguity remains. Absence of records does not prove non-existence. | LinkedIn profiles, news articles, conference databases, review platforms, procurement records, Wayback Machine |
| **ASSESSED** | Analytical conclusions synthesized from multiple findings. Represents the investigator's reasoned judgement. Should be reviewed by a qualified human analyst. | Risk ratings, pattern analysis, assessment frameworks, executive summaries, recommendations |

### How to Apply

- Tag every `#` level section (not subsections)
- Include a brief note on what sources underpin the confidence level
- The Subject Overview and Disclaimer are unnumbered `{-}` sections and do not need confidence tags
- The Executive Summary synthesizes findings and is implicitly ASSESSED
- Infrastructure/OSINT data sections are almost always HIGH

### Confidence Note in Subject Overview

Include the confidence guide in the Subject Overview so the reader understands the framework before reading the report:

```markdown
\bigskip
\noindent\textit{Note on confidence levels -- sections in this report are tagged
with a confidence indicator reflecting the nature of the underlying evidence:}

- **HIGH** -- findings derived directly from authoritative public records
  (corporate registries, patent databases, DNS/WHOIS records, certificate
  transparency logs). These are verifiable facts.
- **MEDIUM** -- findings derived from web research where sources could be
  cross-referenced but some ambiguity remains (e.g., absence of records in
  a database does not prove non-existence).
- **ASSESSED** -- analytical conclusions synthesized from multiple findings.
  These represent the investigator's reasoned judgement and should be reviewed
  by a qualified human analyst.
```

---

## PDF Frontmatter Templates

Reports are rendered to PDF using [pandoc](https://pandoc.org/) with the [eisvogel LaTeX template](https://github.com/Wandmalfarbe/pandoc-latex-template) and XeLaTeX engine. The YAML frontmatter controls the title page, typography, headers/footers, and layout.

**Prerequisites:** pandoc, a TeX distribution with XeLaTeX (e.g., TeX Live, MacTeX), and the eisvogel template installed per [its README](https://github.com/Wandmalfarbe/pandoc-latex-template#installation).

### Due Diligence Report Frontmatter

```yaml
---
title: "OSINT Due Diligence Report"
subtitle: |
  [Subject entity name]\
  [Parent/related entities]\
  [Token/product name if applicable]
author:
  - "Cybersleuth MCP + Claude Code"
date: "YYYY-MM-DD"
subject: "OSINT Due Diligence"
keywords: [OSINT, due diligence, cybersecurity, ...]
lang: en
titlepage: true
titlepage-color: "1a1a2e"
titlepage-text-color: "e0e0e0"
titlepage-rule-color: "e94560"
titlepage-rule-height: 4
toc: true
toc-own-page: true
numbersections: true
colorlinks: true
linkcolor: NavyBlue
urlcolor: NavyBlue
citecolor: NavyBlue
header-left: "OSINT Due Diligence -- [Subject short name]"
header-right: "RESTRICTED"
footer-left: "Cybersleuth MCP + Claude [model name]"
footer-right: "YYYY-MM-DD"
table-use-row-colors: true
classoption:
  - a4paper
geometry:
  - margin=25mm
mainfont: "Helvetica Neue"
sansfont: "Helvetica Neue"
monofont: "Menlo"
fontsize: 10pt
block-headings: true
---
```

### Benchmarking Report Frontmatter

```yaml
---
title: "Industry Benchmarking Report"
subtitle: |
  [Subject product/technology name]\
  Competitive Positioning & State-of-the-Art Analysis
author:
  - "Cybersleuth MCP + Claude Code"
date: "YYYY-MM-DD"
subject: "Competitive Benchmarking"
keywords: [OSINT, benchmarking, ...]
lang: en
titlepage: true
titlepage-color: "1a1a2e"
titlepage-text-color: "e0e0e0"
titlepage-rule-color: "e94560"
titlepage-rule-height: 4
toc: true
toc-own-page: true
numbersections: true
colorlinks: true
linkcolor: NavyBlue
urlcolor: NavyBlue
citecolor: NavyBlue
header-left: "Industry Benchmarking -- [Subject short name]"
header-right: "RESTRICTED"
footer-left: "Cybersleuth MCP + Claude [model name]"
footer-right: "YYYY-MM-DD"
table-use-row-colors: true
classoption:
  - a4paper
geometry:
  - margin=25mm
mainfont: "Helvetica Neue"
sansfont: "Helvetica Neue"
monofont: "Menlo"
fontsize: 10pt
block-headings: true
---
```

### Title Page Design Notes

- **Dark theme:** `titlepage-color: "1a1a2e"` (near-black), `titlepage-text-color: "e0e0e0"` (light gray), `titlepage-rule-color: "e94560"` (red accent). This produces a professional dark cover page.
- **Fonts:** Use system fonts available on the build machine. `Helvetica Neue` + `Menlo` work on macOS. Adjust for Linux (`Liberation Sans`, `DejaVu Sans Mono`) or use any installed font -- XeLaTeX supports arbitrary system fonts.
- **Color names:** xcolor (used by eisvogel) requires named LaTeX colors for link colors. Use `NavyBlue`, `Blue`, `Red`, etc. -- not hex values.

---

## Metadata Page

Immediately after the frontmatter closing `---`, insert a metadata table on its own page. This provides a quick-reference card for the report.

### Due Diligence Report Metadata

```markdown
\newpage

|                    |                                                                 |
|--------------------|-----------------------------------------------------------------|
| **Classification** | Restricted                                                      |
| **Report type**    | OSINT Due Diligence Assessment                                  |
| **Subject**        | [Full subject description]                                      |
| **Jurisdictions**  | [Countries involved]                                            |
| **Date**           | YYYY-MM-DD                                                      |
| **Status**         | Complete                                                        |
| **Model**          | Claude [model] ([model-id], [context]) -- Anthropic             |
| **Tooling**        | Cybersleuth MCP ([list key tools used])                         |
| **Risk rating**    | **[HIGH/MEDIUM/LOW]**                                           |
| **Recommendation** | **[One-line actionable recommendation]**                        |

\newpage
```

### Benchmarking Report Metadata

```markdown
\newpage

|                    |                                                                 |
|--------------------|-----------------------------------------------------------------|
| **Classification** | Restricted                                                      |
| **Report type**    | Industry Benchmarking Assessment                                |
| **Subject**        | [Subject] -- Competitive & Technology Analysis                  |
| **Date**           | YYYY-MM-DD                                                      |
| **Status**         | Complete                                                        |
| **Companion**      | [Companion report title] (date, classification)                 |
| **Model**          | Claude [model] ([model-id], [context]) -- Anthropic             |
| **Tooling**        | Cybersleuth MCP, Claude Code subagents, web research            |

\newpage
```

---

## Classification

Reports default to **RESTRICTED** classification. This is appropriate because:

- Reports aggregate and analyze publicly available data, but the *synthesis* creates intelligence value not present in any single source
- Reports may contain personal information about individuals (directors, employees) in their professional capacity
- Analytical conclusions and risk ratings could affect commercial decisions
- The aggregation of infrastructure data (IPs, hosting, email config) into a single document creates a targeting value

RESTRICTED means: share only with named recipients; do not publish or distribute openly. It is *not* CONFIDENTIAL (which implies classified/government data) or SECRET.

### Watermark

Watermarks should be applied at build time via pandoc's `--include-in-header` mechanism, **not** in the YAML frontmatter. This allows per-recipient watermarks without modifying the source document.

To add a watermark, create a temporary `.tex` file with the watermark LaTeX and pass it to pandoc:

```latex
% watermark.tex -- include via: pandoc --include-in-header watermark.tex ...
\usepackage{eso-pic}
\usepackage{graphicx}
\usepackage{xcolor}
\makeatletter
\newcommand\eisvwm{%
  \put(\LenToUnit{.5\paperwidth},\LenToUnit{.5\paperheight}){%
    \makebox(0,0){%
      \rotatebox{45}{%
        \resizebox{0.7\paperwidth}{!}{%
          \textcolor[gray]{0.92}{Prepared for: Jane Smith}%
        }%
      }%
    }%
  }%
}
\AddToShipoutPictureBG{%
  \ifnum\value{page}>1\relax\eisvwm\fi
}
\makeatother
```

```bash
pandoc report.md --from markdown --pdf-engine=xelatex \
  --template eisvogel --include-in-header watermark.tex \
  -o report.pdf
```

The `\ifnum\value{page}>1` conditional skips the title page. The `\resizebox{0.7\paperwidth}{!}` scales the text to fit regardless of string length. Do **not** put watermark configuration in the YAML frontmatter -- pandoc template variable substitution does not work inside `header-includes` raw LaTeX blocks.

---

## Disclaimer Template

Every report must end with a Disclaimer section. This is an unnumbered section `{-}` covering:

1. **Model** -- which Claude model and context window was used
2. **Tooling** -- Claude Code, Cybersleuth MCP (list tools), subagents, web research
3. **Methodology** -- OSINT only, no unauthorized access, public sources only
4. **Limitations and caveats:**
   - AI-generated analysis (LLM synthesis should be human-reviewed)
   - Tool reliability (third-party APIs may have gaps, outages, rate limits)
   - Negative findings (absence of evidence is not evidence of absence)
   - Point-in-time snapshot (findings reflect investigation date only)
   - No legal opinion (not legal, financial, or investment advice)
   - Potential for error (LLMs can hallucinate; readers should verify key claims)

Adapt the specifics to each report. For benchmarking reports, add:
- **Competitor data currency** -- figures reflect most recent public data
- **Scope limitation** -- what the report does and does not assess
- **No product testing** -- comparisons are based on documentation, not hands-on testing

---

## Sources Index

The Sources Index is an unnumbered section `{-}` at the end of the report (before Disclaimer). It serves as a verifiability record.

### For Due Diligence Reports

Organize sources into:
- **Domain/Infrastructure Tools Used** -- list each OSINT tool with query counts (e.g., "WHOIS lookups (7 domains)", "Certificate Transparency (crt.sh) -- 5 domains")
- **Web Research** -- list registries, databases, and sources consulted (e.g., "UK Companies House", "Swiss Zefix", "Google Patents")

### For Benchmarking Reports

Organize sources into:
- **Competitor Data** -- SEC filings, GitHub repos, vendor documentation
- **Testing & Certification Bodies** -- MITRE, AV-TEST, Common Criteria Portal, etc.
- **Standards & Frameworks** -- NIST SPs, ISO standards, ASD Essential Eight
- **Due Diligence Report References** -- list all `[DDR, Section N]` citations with descriptions

---

## Unnumbered Sections

Use `{-}` after the heading to exclude a section from automatic numbering. Use this for:

- **Subject Overview** -- introductory context, not part of the analytical body
- **Preface** -- relationship to companion reports
- **Sources Index** -- reference material
- **Disclaimer** -- legal/methodological boilerplate

All other sections (Executive Summary, Risk Advisory, analytical sections, infrastructure sections) should be numbered to enable cross-referencing.

---

## Pandoc Build Command

Reports are built with pandoc using the eisvogel template and XeLaTeX:

```bash
# Basic build:
pandoc report.md --from markdown --pdf-engine=xelatex \
  --template eisvogel -V colorlinks=true -V urlcolor=blue \
  -o report.pdf

# With watermark (see Classification section for watermark.tex):
pandoc report.md --from markdown --pdf-engine=xelatex \
  --template eisvogel -V colorlinks=true -V urlcolor=blue \
  --include-in-header watermark.tex \
  -o report.pdf
```

Most layout is controlled by the YAML frontmatter in the `.md` file itself. The `-V` flags override or supplement frontmatter values. See the [eisvogel documentation](https://github.com/Wandmalfarbe/pandoc-latex-template#usage) for all available variables.

---

## Writing Style

- **Tone:** Professional, neutral, analytical. Written for a CISO, board member, or investment committee. Avoid hyperbole, speculation, and loaded language.
- **Voice:** Third person. "The investigation found..." not "We found..." or "I found..."
- **Findings vs. opinions:** Clearly separate verifiable findings (with sources) from assessed conclusions (with confidence tags). Never state an opinion as a fact.
- **Negative findings:** Always state what was searched and what was not found, rather than just "no results." Example: "No patent was found in EPO Espacenet, WIPO PATENTSCOPE, or USPTO under the names [Inventor], [Company A], or [Company B]" -- not just "no patents found."
- **Actionable language:** Risk advisories and recommendations must be concrete and actionable. "Do not engage commercially" is actionable. "Exercise caution" is not.
- **Length:** Let the evidence dictate length. A 30-page DDR is appropriate for a complex multi-entity investigation. A 5-page infrastructure assessment is appropriate for a single domain. Do not pad or compress.
