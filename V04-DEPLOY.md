# ZeroDay Radar v0.4 — dev release instructions

## What's new

- Sticky 'Jump to section' navigation.
- Correlated **Intelligence Priorities**: KEV evidence, EPSS likelihood and momentum, NVD CVSS where available, reasons, evidence, and suggested analyst next steps.
- Search and pagination in Intelligence Priorities and Emerging Vulnerabilities (10 and 25 items per page respectively).
- Recent NVD discovery now paginates the publication-date window before selecting up to 250 newest non-KEV CVEs. Collection bounded by `NVD_DISCOVERY_MAX_PAGES` (default 4 at 2,000 records each). Coverage is disclosed in the UI; partial collection is NOT a complete recent-CVE feed.
- Emerging records include EPSS where available. No claim of verified exploitation for emerging-only records.
- Vulnerability Explorer heading capitalised.
- Source-health, RSS, baseline and NVD resilience features retained.

## Deploy safely

1. In GitHub Desktop, clone/pull `potentialsailboat/zeroday-radar`, then select the **dev** branch.
2. Make a backup of your local repository if you have uncommitted modifications.
3. Extract this archive and **copy the contents of its `zeroday-radar/` folder** into the repository folder, allowing source files to be replaced. Do not delete historical files in `data/`.
4. Commit `feat: v0.4 correlated intelligence and section navigation` and push to **dev**.
5. Open GitHub **Actions → Validate ZeroDay Radar** and check all tests pass. Manually run **Update threat intelligence** selecting **dev** for an API integration smoke test. It does not deploy Pages or commit collected datasets on dev.
6. Review the run logs, particularly NVD responses and the number of scanned results. A 503 is an upstream source error, not success. If many 503s appear, try an NVD API key or decrease API requests.
7. Create a pull request **dev → main**, review changes, then merge. On **main**, manually run **Update threat intelligence** to create `data/priorities.json` and deploy Pages. The six-hour schedule continues.
8. Check the public dashboard; click the sticky section links, try searching priorities, expanding an evidence panel and paginating emerging CVEs. Check the RSS view and source-health statuses.

## Important limitations

- Triage tiers are **heuristic analyst prompts**, not definitive organisational risk rankings.
- NVD CVSS enrichment for KEV is still bounded, so CVSS is often missing.
- Emerging CVEs are a **bounded recent discovery set**, not all CVEs. Pagination in the UI only pages *downloaded* records.
- Emerging EPSS momentum currently compares to the prior successfully stored emerging snapshot; KEV EPSS momentum uses retained daily baselines. They are not a uniform time window. The collection records only the newest 250 emerging non-KEV CVEs, and older ones fall out of scope.
- No GitHub exploit/advisory trend ingestion, public-PoC validation, or vendor mitigation-delta alerts yet. These are future enhancements.
- Browser runs entirely from GitHub Pages; source credentials remain in GitHub Actions secrets, never client JavaScript.
