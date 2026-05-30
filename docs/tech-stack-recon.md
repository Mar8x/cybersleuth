# Tech-Stack Intelligence from Job Postings, GitHub, and Public Signals

Methodology for inferring a company's technology stack from job postings, GitHub
organisation repositories, public dependency files, and CI configuration — without
requiring any authenticated access beyond what the target voluntarily publishes.

---

## Why this works

Companies advertise the tools they need candidates to know. Job descriptions are
unusually candid about internal stack choices because vague postings attract poor
applicants. The signal is amplified across three independent surfaces:

| Source | Signal quality | Lag |
|--------|---------------|-----|
| Job postings | High — direct disclosure of required skills | Days to weeks |
| GitHub org repos | Very high — actual code, not marketing | Commits, typically current |
| Dependency files | Exact — names and sometimes versions | Per-commit |
| CI/CD workflows | High — reveals cloud provider, deployment tooling | Per-commit |
| LinkedIn posts | Moderate — selective, marketing-flavoured | Variable |

---

## ATS Discovery methodology

Applicant Tracking Systems (ATS) host job boards on vendor-controlled subdomains
or via API-backed embeds. The ATS choice itself is a signal (Workday/iCIMS/Taleo →
enterprise; Ashby/Lever/Greenhouse → growth-stage US tech; Teamtailor → Nordic/EU;
Personio → DACH/EU SME; Recruitee → EU).

**Step 1 — Crawl common careers paths on the target domain:**

```
/careers  /jobs  /career  /join-us  /work-with-us  /open-positions
/openings  /opportunities  /vacancies  /hiring  /about/careers
/company/careers  /team
```

Follow redirects. Check the final URL against known ATS URL patterns.

**Step 2 — Scan page HTML for ATS embed patterns:**

ATS boards are often embedded via `<iframe>`, `<script>`, or redirect links.
Check all `href` and `src` attributes in the fetched page.

**Step 3 — Web archive fallback:**

If the domain has no live careers page (company may have changed domain, or the
page is behind auth), query the Wayback Machine CDX API for historical snapshots:

```
https://web.archive.org/cdx/search/cdx?url={domain}/careers*&output=json&
  fl=timestamp,statuscode,original&filter=statuscode:200&collapse=urlkey&limit=5
```

Return archive URLs for manual inspection.

---

## ATS coverage and regional distribution

| ATS | Regions of prevalence | Public JSON API |
|-----|----------------------|-----------------|
| Greenhouse | US, global tech | ✓ `boards-api.greenhouse.io` |
| Lever | US, global tech | ✓ `api.lever.co` |
| Ashby | US, global (growing) | ✓ `api.ashbyhq.com` |
| Workable | EU, global | ✓ `apply.workable.com` |
| Recruitee | EU, global | ✓ `{handle}.recruitee.com/api` |
| SmartRecruiters | Global (enterprise) | ✓ `api.smartrecruiters.com` |
| Personio | DACH, EU | ✓ `{handle}.jobs.personio.de/api/v1/jobs` |
| BambooHR | US | ✓ `{handle}.bamboohr.com/careers/list` |
| Teamtailor | Nordic, EU | ✗ (no public JSON; HTML scrape) |
| Workday | Enterprise, global | ✗ (complex proprietary API) |
| iCIMS | US, enterprise | ✗ |
| Taleo (Oracle) | Enterprise | ✗ |

All public JSON APIs listed above are unauthenticated — they are designed to be
public so third-party aggregators (Indeed, LinkedIn Jobs) can index them.

---

## GitHub organisation reconnaissance

GitHub org pages expose significant infrastructure intelligence at no cost:

- **Repository list** — names often reveal products, services, and internal tooling
- **Language distribution** — aggregate bytes-per-language across all repos
- **Dependency manifests** — `package.json`, `requirements.txt`, `pyproject.toml`,
  `go.mod`, `Cargo.toml`, `Gemfile`, `pom.xml`, `composer.json`
- **CI/CD workflows** — `.github/workflows/*.yml` reveal cloud provider integrations,
  deployment tooling (Terraform, Helm, ArgoCD), security scanning (Snyk, Trivy,
  SonarCloud), and container registries
- **Contributor activity** — commit frequency, active maintainers, star/fork counts

Rate limits: 60 req/h unauthenticated; 5000 req/h with a `GITHUB_TOKEN`. Set the
env var for any serious investigation.

### Files to fetch per repo

Fetching all files in all repos is impractical. Prioritise:

1. Repos with highest star count (most maintained public-facing projects)
2. Repos with most recent commit activity (active development)
3. Files: dependency manifests first, then CI workflows

---

## LinkedIn — methodology only (no automated tool)

Automated scraping of LinkedIn violates their ToS and triggers aggressive bot
detection. Use manual dork queries instead:

```
site:linkedin.com/in/ "software engineer at {company}" "we use"
site:linkedin.com/company/{handle}/posts
site:linkedin.com/in/ "{company}" "built with" OR "stack" OR "infrastructure"
intitle:"{company}" site:linkedin.com/jobs/
```

Employee skill endorsements and posts from engineering/infrastructure roles are
particularly high-signal. Archive.org can surface deleted LinkedIn posts.

---

## Tech-keyword extraction

Keywords are matched against job description text and dependency file contents.
Categories and representative keywords:

| Category | Examples |
|----------|---------|
| Languages | Python, TypeScript, Go, Rust, Kotlin, Scala, Elixir |
| Frontend | React, Vue.js, Next.js, Svelte, Tailwind CSS, Vite |
| Backend | Django, FastAPI, Spring Boot, Rails, Gin, NestJS |
| Databases | PostgreSQL, MongoDB, Redis, ClickHouse, DynamoDB, Snowflake |
| Cloud | AWS, Azure, GCP, Cloudflare, Hetzner, OVHcloud |
| DevOps | Kubernetes, Terraform, Helm, ArgoCD, Pulumi, GitHub Actions |
| Observability | Datadog, Grafana/Prometheus, OpenTelemetry, Sentry, Honeycomb |
| Data platform | Kafka, dbt, Databricks, BigQuery, Airflow, Flink, Iceberg |
| Security tools | Vault, Snyk, Trivy, Okta, Auth0, Wiz |
| LLM / AI | OpenAI, Anthropic, LangChain, Hugging Face, PyTorch, RAG |
| Messaging | Kafka, RabbitMQ, SQS, NATS, Temporal, Celery |
| Mobile | React Native, Flutter, SwiftUI, Jetpack Compose |

Each keyword match is attributed to its source (job posting title + ATS handle,
or repo name + file).

---

## Confidence calibration

| Evidence type | Confidence |
|--------------|-----------|
| Required skill in job posting | HIGH — actively used |
| Listed in dependency manifest | HIGH — in production or dev |
| Referenced in CI workflow | HIGH — in deployment pipeline |
| Nice-to-have in job posting | MEDIUM — aspirational or legacy |
| Founder/engineer LinkedIn post | MEDIUM — may be personal opinion |
| Inferred from ATS choice alone | LOW — meta-signal only |

Always note the number of independent sources confirming a technology. A tool
appearing in job postings AND dependency files AND CI workflows is near-certain.

---

## Integration with other CyberSleuth tools

- **CT logs / `certificate_info`**: subdomains like `api.*`, `data.*`, `mlops.*`,
  `search.*` corroborate stack claims. `kafka.*` strongly confirms Kafka usage.
- **DNS / `dns_records`**: MX records reveal email provider; TXT records often
  include verification tokens for SaaS tools (Google Workspace, Salesforce, Atlassian)
- **`llm_fingerprint`**: confirms LLM/AI claims from job postings at the HTTP layer
- **BuiltWith / `builtwith_lookup`**: front-end tech stack (CDN, analytics, CMS)
  complementary to job-posting signal which skews backend/infra

Run `tech_stack_profile` as part of Phase 5 (Technology & Hosting Fingerprint)
in `docs/domain-workflow.md`. GitHub org recon is especially rich for engineering-
focused companies that publish open source or open their infrastructure tooling.
