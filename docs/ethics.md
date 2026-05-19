# OSINT Ethics

## The Core Rule

OSINT collects **publicly available information** — no authorization is required to look up WHOIS records, company registers, DNS data, CT logs, public social media, or news. The ethical line is not about whether data is public, but about **how you collect it** and **what you do with it**.

---

## What Never Requires Authorization

- WHOIS, DNS, certificate transparency logs
- Company registers (allabolag.se, Companies House, SEC EDGAR, etc.)
- Shodan, VirusTotal, URLScan on public IPs and domains
- Public social media, websites, news, job postings
- Court records and government databases open to the public

---

## What Does Require Care

### Active scanning
Port scans, fuzzing, and active probing of systems cross from passive OSINT into territory covered by the CFAA (US) and equivalent laws in other jurisdictions. Passive collection from aggregators (Shodan, Censys) is fine; running your own nmap against a target you don't own is not.

### Regulated uses
In the US, if OSINT findings feed into an **employment, credit, or tenancy decision**, FCRA compliance is a legal requirement regardless of whether the underlying data is public. Similarly, GDPR applies when processing personal data of EU residents — public ≠ freely repurposable for any purpose.

### Professional engagements
When producing a report for a client used in a consequential decision (hiring, M&A, litigation), document your scope and methodology. This protects the client and demonstrates the findings are fit for purpose.

---

## Always

- Use only publicly available sources — no pretexting, impersonation, or social engineering
- Distinguish **fact** from **inference** in all outputs
- Cite sources; don't assert without evidence
- Apply proportionality — collect what is necessary for the stated purpose
- Handle collected personal data responsibly; don't retain or share beyond the investigation scope

## Never

- Access private systems or accounts without authorization
- Circumvent access controls or scrape in violation of platform ToS for critical findings
- Stalk, harass, or surveil individuals beyond the investigation scope
- Purchase illegally obtained data
