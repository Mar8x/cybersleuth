# People OSINT Methodology

**Scope:** Identifying and verifying company leadership — executives, board members, directors, and key decision-makers — as part of company due diligence or corporate intelligence. This is not a general people-finding guide.

---

## Jurisdiction Data Availability

Company registers are the primary source for leadership identification. Coverage and depth vary by jurisdiction.

| Jurisdiction | Availability | Notes |
|---|---|---|
| Nordic (SE/NO/DK/FI) | HIGH | Company registers fully public; board and director roles listed with personal identity numbers in some cases; income data (Sweden: Skatteverket); GDPR applies but transparency tradition carves out public company data |
| UK | MEDIUM-HIGH | Companies House: full director history, appointment/resignation dates, other directorships, date of birth (partial); free and searchable |
| Germany | LOW-MEDIUM | Handelsregister (handelsregister.de): directors listed but strict GDPR limits personal detail; paid access for some documents |
| France | LOW-MEDIUM | INPI/Sirene (annuaire-entreprises.data.gouv.fr): legal representatives listed; RGPD constraints limit personal data |
| US | HIGH | Secretary of State (varies by state): registered agent and officers; SEC EDGAR for public companies (proxy statements, Form 4, 8-K name officer changes); no federal GDPR equivalent |

**Source discovery pattern:** Search `"[country] company register director search [year]"` to find current authoritative sources — do not rely on hardcoded URLs.

---

## Leadership Identification Workflow

### Step 1 — Company register

Start with the official register for the target jurisdiction:
- Retrieve current board composition (chair, members, alternates)
- Note appointment dates — recent changes are intelligence
- Check for cross-directorships: the same person on multiple boards may indicate holding structure or key influence
- Verify legal role title precisely — `suppleant` (alternate), `ledamot` (member), `VD` (CEO) each carry different authority; claimed titles should match the register

### Step 2 — LinkedIn

Cross-reference register names against LinkedIn:
- Confirm current role and employer match register data
- Map career history — prior employers and roles reveal industry background and network
- Note connection density in target sector (strong signal for domain expertise or insider relationships)

### Step 3 — Username → domain pivot

For each executive found, search for personal domains and online presence:
- Check `[firstname][lastname].com`, `[handle].com`, `[handle].se`, `[handle].eu`, `[handle].io`
- Run `whois_lookup` + `dns_records` on any that resolve
- Cross-reference WHOIS registrant with known identity to confirm ownership

### Step 4 — Adverse and sanctions checks

For each key individual:
- OFAC SDN list, EU Consolidated Sanctions, OpenSanctions
- PEP (Politically Exposed Person) databases
- Court and litigation records (PACER for US; national court registers)
- Adverse media search: `"[full name]" site:news.google.com OR "[full name]" fraud OR scandal`

---

## Role Verification

When a claimed title needs verification against the register, use this verdict framework:

| Verdict | Meaning |
|---|---|
| **CONFIRMED** | Verified against company register or official filing |
| **PLAUSIBLE** | Consistent with available evidence but not directly verifiable |
| **UNVERIFIED** | No corroborating record found |
| **EMBELLISHED** | Materially exaggerated relative to the legal record |

**Embellishment types:**
- **Title inflation** — real role exists but claimed title implies greater authority than the legal record supports; company register is authoritative on actual role and voting rights
- **Date manipulation** — real role but tenure dates adjusted to cover a gap or extend apparent experience
- **Fabrication** — no supporting record exists

---

## Content & Professional Presence

For executive-level subjects, assess public professional presence:

- **LinkedIn activity** — posting frequency and topics signal genuine domain engagement vs. a dormant profile
- **Compartmentalization signal** — gap between a polished professional persona (real name, LinkedIn) and an alias-based personal persona; the alias channel is typically more candid
- **Published work** — articles, conference talks, patents, or board advisory roles corroborate claimed expertise

### Absence of Adverse Findings

Absence of adverse content is a positive data point — state it explicitly with a confidence level:

> "No adverse media, sanctions listings, or litigation records found for [role]. Confidence: MEDIUM (public sources only)."
