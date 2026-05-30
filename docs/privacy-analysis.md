# Privacy Policy & Data Handling Analysis

Methodology for discovering, parsing, and assessing how a company handles user data
across privacy policies, Terms of Service, and cookie policies — cross-referenced against
technical evidence (trackers, tech stack, subdomains) and jurisdictional compliance frameworks.

**Research basis:** OPP-115 corpus (Wilson et al., ACL 2016), PoliGraph (USENIX Security 2023,
arXiv 2210.06746), PolicyChecker (ACM CCS 2023), WhoTracksMe (arXiv 1804.08959),
Disconnect.me taxonomy, EU AI Act Art. 53 (live Aug 2025), NIST SP 800-122.

---

## Document Discovery

Privacy-related documents are found by crawling common paths:

```
/privacy-policy  /privacy  /legal/privacy  /data-protection  /datenschutz
/terms  /terms-of-service  /tos  /legal/terms
/cookie-policy  /cookies  /gdpr  /ccpa  /legal/dpa
```

If direct paths fail, the homepage is scanned for anchor tags matching
`privacy`, `datenschutz`, `cookie`, `terms`, or `legal`.

---

## OPP-115 Data-Practice Categories

The canonical label schema from Wilson et al. (ACL 2016) — 115 policies, 23K annotations.
Used to classify what a policy says across ten dimensions:

| Category | What it covers |
|----------|---------------|
| `data_collection` | What data is collected and how |
| `data_use` | Purposes for which data is processed |
| `data_sharing` | Third-party recipients, partners, data brokers |
| `data_retention` | How long data is kept, deletion conditions |
| `data_security` | Technical/organisational measures, certifications |
| `user_choice_control` | Opt-out, opt-in, consent withdrawal, cookie settings |
| `user_access_rights` | Right to access, correct, delete, port data |
| `policy_change` | How users are notified of policy updates |
| `do_not_track` | DNT signal and GPC (Global Privacy Control) response |
| `international_audiences` | Cross-border transfers, adequacy decisions, COPPA |

Detection is regex-based against cleaned policy text. LLM accuracy: F1 > 93% on
OPP-115 categories using zero-shot GPT-4 (arXiv 2405.20900, 2024).

---

## Jurisdiction Detection and Compliance Gap Analysis

The tool detects five frameworks and checks for their mandatory disclosure elements:

### GDPR (EU/EEA) — Articles 13/14

| Required element | Legal basis |
|-----------------|-------------|
| Identity of controller | Art. 13(1)(a) |
| DPO contact | Art. 13(1)(b) if DPO appointed |
| Purposes and legal basis | Art. 13(1)(c) |
| Legitimate interests description | Art. 13(1)(d) |
| Recipients or categories | Art. 13(1)(e) |
| Retention periods | Art. 13(2)(a) |
| Data subject rights | Art. 13(2)(b): access, rectification, erasure, portability, objection |
| Right to withdraw consent | Art. 13(2)(c) |
| Right to lodge complaint | Art. 13(2)(d) |
| Cross-border transfers | Art. 13(1)(f): SCCs, adequacy decision |

**Benchmark:** PolicyChecker (ACM CCS 2023) found 99.3% of 206K Android app policies
failed at least one mandatory GDPR Art. 13/14 element.

### CCPA/CPRA (California)

| Required element | Legal basis |
|-----------------|-------------|
| Categories of PI collected | Cal. Civ. Code 1798.100 |
| Purposes of use | 1798.100 |
| Categories shared or sold | 1798.120 |
| "Do Not Sell or Share" homepage link | 1798.135 |
| "Limit Sensitive PI" homepage link | CPRA 1798.121 |
| CA data subject rights | access, deletion, correction, portability |
| Retention periods | CPRA addition |

**Sensitive PI under CPRA:** SSN/state ID, account credentials, precise geolocation,
racial/ethnic origin, religious beliefs, union membership, private communications,
genetic data, biometric ID, health data, sex life/sexual orientation.

### LGPD (Brazil), PIPL (China), PIPEDA (Canada)

Each framework has its own required-element checklist. Key differences:
- **LGPD:** 10 legal bases (mirrors GDPR + additional); extends rights to deceased persons
- **PIPL:** Strict data localisation; cross-border transfers need MIIT standard contract
- **PIPEDA:** Consent-centric, implied consent permissible for less sensitive data

---

## AI/LLM Training Data Clause Detection

Active since EU AI Act Art. 53(1)(d) enforcement (August 2, 2025): GPAI providers
must publish a training data summary using the EC mandatory template.

**Red-flag phrase patterns (by severity):**

| Severity | Pattern | Context |
|----------|---------|---------|
| HIGH | "train our models", "AI training", "fine-tuning" | Explicit training disclosure |
| MEDIUM | "improve our products and services", "product improvement" | Classic legitimate-interest catch-all |
| MEDIUM | AI opt-out buried in Account Settings → Data Controls | LinkedIn 2024 pattern |
| LOW | "aggregate and anonymized data" for improvements | Anonymisation claim without methodology |
| INFO | "training data summary", "EU AI Act", "GPAI" | Compliance disclosure |

**Key gap:** Cookie TCF consent signals do NOT cover AI training data collection.
These operate on separate legal bases and require separate opt-out mechanisms.
Current privacy policies rarely surface this distinction — flag it explicitly.

---

## Tracker Risk Database

~30 embedded tracker entries covering:

| Category | Examples | Risk |
|----------|---------|------|
| Advertising | Meta Pixel, Google Ads, TikTok Pixel, Criteo | HIGH |
| Analytics | GA4, Adobe Analytics, Mixpanel, Amplitude | HIGH / LOW |
| Session replay | Hotjar, FullStory, Microsoft Clarity | MEDIUM |
| Fingerprinting | FingerprintJS / Fingerprint Pro | HIGH |
| Tag management | Google Tag Manager | MEDIUM |
| CRM/marketing | HubSpot, Salesforce Pardot, Intercom | LOW–MEDIUM |
| Consent management | OneTrust, Cookiebot, Usercentrics, Osano | INFO |
| AI / LLM | OpenAI embedded widget | HIGH |
| Observability | Sentry, Datadog RUM | LOW |

Risk levels are escalated for high-risk page contexts:

| Context detected | Trackers escalated |
|-----------------|-------------------|
| Healthcare keywords | All MEDIUM → HIGH; Meta Pixel triggers HIPAA flag |
| Finance keywords | All MEDIUM → HIGH |
| Children's content | All → mandatory COPPA disclosure check |

---

## Contradiction Patterns (Enforcement-Backed)

Policy text vs. technical evidence contradictions with documented precedents:

| Finding | Contradiction | Enforcement precedent |
|---------|--------------|----------------------|
| Meta Pixel + "no third-party sharing" claim | Pixel constitutes "sharing" under CCPA/CPRA; AAM captures form PII | FTC/HHS Jul 2023; Novant $6.6M; Mass General $18.4M |
| GA4 + "no EU data transfer" claim | GA4 routes data to Google US | CNIL Feb 2022; Austrian, Italian, Danish DPAs 2022–2023 |
| FingerprintJS + no disclosure | Persistent pseudonymous ID under GDPR Recital 30 | GDPR enforcement; no cookie banner covers fingerprinting |
| Advertising trackers + no consent banner | Trackers fire before consent under ePrivacy Directive | GDPR Art. 5(3); DPA enforcement across EU |
| Session replay + no disclosure | Captures keystrokes/form data without OPP-115 data-collection disclosure | GDPR Art. 13; multiple DPA rulings |
| Segment routing to ad platforms + "analytics only" claim | Segment routes to downstream ad-tech destinations not disclosed as recipients | GDPR Art. 13(1)(e) |

---

## Cross-Reference with Other CyberSleuth Tools

| Tool | What to cross-reference |
|------|------------------------|
| `tracker_scan()` | Challenge "no third-party sharing" claims; detect consent mechanism gaps |
| `builtwith_lookup()` | Corroborate trackers; detect advertising stack not visible in HTML |
| `dns_records()` | TXT records: SaaS verification tokens (Google Workspace, HubSpot, Salesforce) reveal tools in use |
| `certificate_info()` | Subdomains: `analytics.*`, `pixel.*`, `tracking.*`, `segment.*` confirm tool presence |
| `tech_stack()` | Cross-check AI/ML claims (job postings mention OpenAI/Anthropic → expect training data clauses) |
| `llm_fingerprint()` | LLM API exposure = likely AI training data use; check for EU AI Act Art. 53 compliance |

---

## PII Classification

**NIST SP 800-122** context-dependent PII: a ZIP code alone may be non-PII; combined
with health status it becomes sensitive. OSINT tools should flag inference chains.

**GDPR Article 9 special categories** (prohibited without explicit consent/derogation):
racial/ethnic origin, political opinions, religious/philosophical beliefs, trade union
membership, genetic data, biometric data for unique identification, health data,
sex life/sexual orientation.

**Note on inferred special categories:** Location data is NOT Article 9 but can infer
Article 9 categories (hospital visits → health; place of worship → religion).
Flag this inference risk when precise geolocation is collected.

**CPRA sensitive PI additions** (beyond GDPR Art. 9): precise geolocation, account
credentials, private communications contents.

---

## Confidence Calibration

| Evidence | Confidence |
|---------|-----------|
| Tracker detected in HTML source | HIGH — active at time of scan |
| Policy text matches required element | MEDIUM — text may be templated/outdated |
| Contradiction: tracker + policy claim | HIGH — cross-source validation |
| Jurisdiction detected via keyword | MEDIUM — verify by reading full text |
| AI training flag — explicit phrase | HIGH |
| AI training flag — broad catch-all phrase | LOW — requires human review |
| No consent banner + advertising trackers | HIGH — ePrivacy violation if EU traffic |

**PolicyChecker finding (ACM CCS 2023):** 99.3% of 206K app policies failed at least
one mandatory GDPR element. Treat policy gaps as the norm, not the exception —
the absence of a required element is actionable intelligence, not a detection error.
