# Threat-Surface Deep Recon (Shodan)

Widen the attack surface of a target and enumerate as much exposed infrastructure as
possible. Start from a single seed — a **domain**, **IP**, **ASN**, or **CIDR netblock** —
and pivot outward through Shodan until the picture stops growing. Authorized OSINT only:
this is passive observation of internet-facing data Shodan already indexes. Never probe,
authenticate, or exploit.

## Objective
Map the target's externally reachable surface: every host, open port, service/product,
TLS certificate, and known vulnerability that belongs to the same entity — even when it
spans multiple IPs, netblocks, and autonomous systems.

## Seed expansion — where to start per type

| Seed type | First moves |
|-----------|-------------|
| **domain** | Lead with **`shodan_domain`** — it runs `hostname:<domain>` ∪ `ssl.cert.subject.cn:<domain>` (the high-signal union; the cert query catches domain-joined boxes with exposed RDP that hostname misses). **Do not search the resolved apex IP** — for shared hosting / CDN / parked domains the apex belongs to the provider, returning provider noise + unrelated co-tenants. Also `certificate_info` for CN/org/SAN, `favicon_hash` → `http.favicon.hash:<hash>`. Resolve A/AAAA + subdomains, but only `ip:`/`net:` IPs confirmed to belong to the org (its own ASN/org from `as_intelligence`). |
| **ip** | `shodan_search` with `ip:<ip>` for that host's services, then sweep the neighborhood: `net:<ip>/24`. Pull PTR (`reverse_dns`) and the cert org for pivots. |
| **asn** | `shodan_search` with `asn:AS<number>` (deep `limit`) to enumerate the whole AS. Use `as_intelligence` for the org name and announced prefixes, then sweep each prefix with `net:`. |
| **range / CIDR** | `shodan_search` with `net:<cidr>` (deep `limit`). Facet on `port`/`product`/`org` to profile the block, then drill into the interesting hosts. |

## Pivot chains (how the surface widens)
Each fact you learn becomes the next query. Chase every strong pivot until it stops
producing new hosts:

- **Favicon** → `http.favicon.hash:<murmur3>` (from `favicon_hash`) — finds every host
  serving the same app/branding, often across unrelated netblocks.
- **TLS certificate** → `ssl.cert.subject.cn:<cn>`, `ssl.cert.subject.o:"<org>"`,
  `ssl:"<org>"` — co-located and sibling hosts sharing a cert identity.
- **Organization** → `org:"<org name>"` — everything Shodan attributes to that org.
- **Autonomous system** → `asn:AS<n>` — full AS enumeration.
- **Netblock** → `net:<cidr>` — sweep a prefix discovered from a cert, ASN, or a hot IP.
- **Product/banner** → combine with `product:`, `http.title:`, `http.html:` to cluster
  identical deployments (e.g. a self-hosted admin panel) across the surface.

## Deep enumeration — what to capture on each host
Open ports and the **product/version** behind them · TLS posture (issuer, expiry,
weak/eol versions) · hostnames/domains/PTR · `vuln:` (known CVEs Shodan flags) ·
exposed-by-default risk: admin panels, databases (`port:27017,3306,5432,6379,9200,11211`),
remote access (`port:3389` RDP, `port:5900` VNC, `port:23` telnet), ICS/SCADA, object
storage, dev/staging, default credentials banners.

Use **facets** for breadth before depth — one faceted query profiles the whole result
set cheaply:
`shodan_search(query="asn:AS13335", facets="port,product,org,vuln,asn", limit=200)`.

## Depth & credit discipline
Deep sweeps consume Shodan query credits (≈1 per 100 results) and agent tokens. Default
to **moderate**: `limit≈200` per query, follow only **strong** pivots (favicon, exact
cert CN/org, ASN, hot netblocks), and stop a branch once it returns mostly already-seen
IPs. The operator's **focus note** overrides this — honor explicit instructions like
"aggressive" (raise `limit`, chase weaker pivots, facet everything) or "conservative"
(small `limit`, favicon+cert only), and any scoping ("only TLS/email infra", "exclude
CDN ranges", "find exposed databases / RDP / ICS").

## Tagging (apply to the entities you create)
Tag discovered hosts so the surface is filterable:
`exposed-service`, `risky-port`, `database-exposed`, `rdp-exposed`, `ics`, `eol-tls`,
`self-signed-cert`, `cdn`, `cve` (when `vuln:` hits), plus an `<asn>`/`<org>` cluster tag.
Keep tags lowercase and reuse existing vocabulary.

## Output
A connected surface: every discovered host linked back to the seed, with services, ports,
certs, and vulns recorded. Summarize the externally exposed footprint, the riskiest
findings (exposed admin/DB/RDP, flagged CVEs, eol TLS), the AS/netblock clusters it spans,
and the open questions a follow-up sweep should resolve.
