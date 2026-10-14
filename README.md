# ZeroDay Radar

Open-source, analyst-focused dashboard for **CISA KEV** records, enriched with **FIRST EPSS** and selected **NIST NVD** severity data. Version 0.1.

## Deploy on GitHub Pages (no coding required)

1. Download and unzip the project archive.
2. On GitHub, click **+ → New repository**. Name it `zeroday-radar`, select **Public**, and click **Create repository**. Do **not** initialise it with a README (this project includes one).
3. In the new repository, select **uploading an existing file** (or **Add file → Upload files**). Upload the **contents** of the unzipped `zeroday-radar` folder, keeping the folder structure. **Important:** GitHub's web uploader may not accept hidden `.github` directories reliably. If `.github/workflows/update.yml` is missing after upload, create it using **Add file → Create new file**, enter `.github/workflows/update.yml` as the filename and paste the file's contents. Also create `.nojekyll` if missing.
4. Go to **Settings → Actions → General → Workflow permissions** and select **Read and write permissions**, then save. This lets the collector commit its JSON data.
5. Go to **Settings → Pages → Build and deployment**, set **Source** to **GitHub Actions**.
6. Go to **Actions → Update threat intelligence → Run workflow**. The first run collects the data and deploys the site. It may take several minutes because the NVD API is rate-limited.
7. Once the workflow succeeds, visit `https://YOUR-USERNAME.github.io/zeroday-radar/` (replace YOUR-USERNAME). If the page shows no data, inspect the workflow logs and verify `data/vulnerabilities.json` exists in the repository.

GitHub Actions also attempts scheduled updates every six hours. Scheduled runs may be delayed; GitHub can disable schedules on inactive public repositories. Check the **Last updated** indicator.

## Optional NVD API key

The collector enriches only the newest 15 KEV records per run, to respect NVD rate limits. You can request an NVD API key from NIST and add it under **Settings → Secrets and variables → Actions → New repository secret** named `NVD_API_KEY`. Never commit the key. Increasing `NVD_ENRICH_LIMIT` is possible but increases runtime and API use.

## Run locally

Install Python 3.10+ and run:

```bash
python scripts/collect.py
python -m http.server 8000
```

Visit `http://localhost:8000`. Opening `index.html` directly via `file://` won't reliably load the JSON file.

## Data and limitations

- **Coverage:** only vulnerabilities in the CISA KEV catalogue; **not** all CVEs, not a comprehensive zero-day detector.
- **EPSS:** FIRST estimates probability of exploitation over the next 30 days. KEV confirms known exploitation; EPSS alone does not.
- **NVD:** severity is enriched for the most recent 15 KEV records each run. Missing CVSS is displayed as unavailable. Historical records may remain without CVSS until a later enrichment strategy is implemented.
- **Priority tiers:** Critical = KEV + EPSS >= 0.50; High = KEV + EPSS >= 0.10; Elevated = all other KEV records. These are simple triage labels, **not** asset-aware risk ratings. Missing EPSS defaults to Elevated and should be treated as unknown probability.
- The feed is public and sourced from third parties. No uptime, completeness, or freshness guarantee. Do not rely on this dashboard as the sole security decision source.
- The workflow writes refreshed public JSON into Git history. At large scale, consider moving snapshots to object storage.

## Planned RSS milestone

Rules agreed for the next release:
1. New CISA KEV catalogue entry.
2. EPSS increases by **25 percentage points or more**, measured against the prior successful daily baseline.
3. Newly observed public PoC reference (distinguish first observed from original publication).
4. New or materially changed vendor patch/mitigation guidance.

Primary channel: RSS/Atom. Implement with source attribution, change detection, deduplication, and persistent history. **These rules are not active in v0.1.**

## Security

Never add credentials to public files. External text is rendered as text (not HTML) to reduce script injection risk. Links to NVD are generated from CVE IDs. GitHub Pages is public; do not upload internal asset inventories or sensitive organisational data.

## License

MIT — see LICENSE.
