# People OSINT Methodology

## Jurisdiction Data Availability

Public data availability varies significantly by country. Use this as a guide for scope-setting before investigation, not as a hard rule — availability changes and sources appear and disappear.

| Jurisdiction | Availability | Notes |
|---|---|---|
| Nordic (SE/NO/DK/FI) | HIGH | Company registers fully public; population address registration; income/property data (Sweden: Skatteverket); GDPR applies but transparency tradition carves out public company data |
| UK | MEDIUM-HIGH | Companies House director search; electoral roll via paid aggregators; free company filings with director history |
| Germany | LOW-MEDIUM | Handelsregister (handelsregister.de); strict GDPR enforcement; low phone/address directory coverage |
| France | LOW-MEDIUM | INPI/Sirene (annuaire-entreprises.data.gouv.fr); RGPD constraints limit address and personal data |
| US | HIGH | PACER (federal courts); Secretary of State; county assessors; voter rolls; people-search aggregators; no federal GDPR equivalent |

**Source discovery pattern:** For any jurisdiction not listed here, search: `"[country] company register person search OSINT [year]"`. Always discover current sources at investigation time — do not rely on hardcoded URLs.

---

## CV Claim Scorecard

A structured method for verifying claims made in a CV, LinkedIn profile, or interview.

### Verdicts

| Verdict | Meaning |
|---|---|
| **CONFIRMED** | Verified against an authoritative source (company register, public record, credential database) |
| **PLAUSIBLE** | Consistent with available evidence but not directly verifiable |
| **UNVERIFIED** | No corroborating evidence found; absence of evidence is not evidence of absence |
| **EMBELLISHED** | Claim is materially exaggerated or misleading relative to the verifiable record |

### Table Format

| ID | Claim | Verdict | Confidence | Evidence |
|---|---|---|---|---|
| C1 | [claim text] | CONFIRMED | HIGH | [source] |

### Embellishment Distinctions

When assigning EMBELLISHED, document which type:
- **Fabrication** — entirely false (no supporting record exists)
- **Title inflation** — real role exists but the title claimed implies greater seniority or authority than the legal record supports; company or corporate register is authoritative on actual role and voting rights
- **Date manipulation** — real role but dates adjusted to cover a gap or extend tenure

---

## Content Character Profiling

Assessment of a subject's online voice and public content as a character indicator.

### Channel Identification

Check channels in order of signal richness:
1. **Personal blog or personal domain** — least filtered; most candid; subject controls the platform
2. **YouTube** — audio/visual voice; comment sections add context; subscription/upload dates reveal activity timeline
3. **Social media** (LinkedIn, Twitter/X, Facebook, Instagram) — check both professional and personal/alias accounts

### Language Register Signals

- **Professional restraint** (real name, employer-affiliated account, LinkedIn): formal language, measured opinions, employer-safe content
- **Candid voice** (alias, personal domain, hobby forum, gaming platform): more authentic; strong language, personal opinions, identity-linked community membership

When a significant gap exists between the professional persona and the alias persona, the alias channel is typically more representative of character.

### Absence of Adverse Findings

Absence of adverse content is a positive data point and should be stated explicitly with a confidence level, e.g.:

> "No adverse content or problematic platform presence found across [channels checked]. Confidence: MEDIUM (public-facing content only; private channels not assessed)."
