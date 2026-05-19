# CyberSleuth with PAI

CyberSleuth works as a standalone MCP server — but when connected to a [Personal AI Infrastructure (PAI)](https://github.com/danielmiessler/Personal_AI_Infrastructure) layer, the same tools produce significantly deeper results.

## Standalone (Claude Desktop / Claude Code)

- MCP tools run sequentially: one WHOIS lookup, one DNS query, one Shodan search at a time
- Resources (`cybersleuth://instructions`, `cybersleuth://reports`, `cybersleuth://people-osint`) are auto-loaded as methodology context
- Claude investigates step by step, synthesising as it goes
- No memory between sessions — each conversation starts fresh

This is capable and useful. For a quick domain recon or a single company lookup it is entirely sufficient.

## With PAI

PAI adds an orchestration layer on top of the same tools:

### Parallel research fleet
While the main agent runs MCP tools (DNS, WHOIS, crt.sh, Shodan), PAI simultaneously deploys 8–32 specialised researcher agents across multiple AI models — each hitting different web sources in parallel. Business intelligence, adverse media, sanctions checks, job posting analysis, and competitive research all run concurrently with the technical recon. A full company DDR that would take 30+ sequential steps finishes in one coordinated pass.

### Structured investigation
Every investigation is driven by a PRD (Problem/Research Definition) with explicit ISC (Ideal State Criteria) — a checklist of what must be confirmed before the investigation is complete. Each finding is tracked to a criterion. Nothing is declared done until all criteria are met or documented as gaps.

### Persistent memory
Findings, methodology learnings, and source discoveries persist across sessions. A resumed investigation picks up exactly where it left off. Learnings from one investigation improve the next.

### Outcome
The gap is not just speed — it is coverage. A standalone session might surface 60–70% of available intelligence on a target. PAI with CyberSleuth routinely reaches 90%+ by exhausting technical, web, registry, and open-source channels in parallel before synthesising.
