# ZeroDay Radar v0.4

**Correlated vulnerability intelligence for security analysts and SOC teams.**

ZeroDay Radar is not another CVE feed. It combines CISA KEV exploitation evidence, FIRST EPSS exploitation-likelihood estimates and their changes, and NVD severity/metadata where available. The **Intelligence Priorities** view explains why to investigate each candidate, links to authoritative evidence, and provides analyst next steps. It does not scan your network or know your assets.

**Quick start:** see [V04-DEPLOY.md](V04-DEPLOY.md) for `dev` testing and safe deployment into `main`. The hosted site has a sticky "Jump to section" navigation; use Intelligence Priorities first, then What Changed, Vulnerability Explorer, Emerging Vulnerabilities and Source Health.

**Coverage:** CISA KEV catalogue plus up to 250 of the newest NVD CVEs discovered within a bounded recent seven-day publication window (up to 8,000 scanned by default). Discovery can be incomplete if more results exist or NVD fails. EPSS coverage and missing CVSS data are shown as unavailable, not as zero. Confirmed exploitation (KEV), predicted exploitation (EPSS) and technical severity (CVSS) must not be conflated.

**RSS:** `feed.xml` and `alerts.html` retain new KEV / EPSS +25 percentage-point alerts, after an initial baseline has been established. PoC and vendor patch-change feeds are on the roadmap. A GitHub-focused trend and advisory feed is explicitly planned for a later release, with trustworthy attribution and deduplication.

**Updates:** the GitHub Actions update workflow runs every six hours on `main`, and on demand on `dev` or `main`. Only `main` writes data back to the repository and deploys Pages.

## Scope limitations and methodology

This is a transparent, rules-based analyst triage system, *not* a calibrated threat risk model. A KEV vulnerability is confirmed exploited; an emerging-only CVE is not. An EPSS estimate is a prediction, not verification. A high CVSS score measures technical impact, not likelihood. Use authoritative sources and your own asset inventory before remediation decisions. Collection snapshots may be stale, incomplete or subject to API outages. No PoC or vendor-change alerts in this release.

## Licences and sources

MIT licensed project. Source information from CISA KEV, FIRST EPSS and NIST NVD; refer to their respective reuse and attribution terms.

---

# ZeroDay Radar v0.2

**Live dashboard:** https://potentialsailboat.github.io/zeroday-radar/  
**RSS feed (after the upgraded collector runs on `main`):** https://potentialsailboat.github.io/zeroday-radar/feed.xml

ZeroDay Radar is an open-source, static cybersecurity intelligence dashboard for security analysts, SOC teams and vulnerability-management practitioners. It correlates CISA **Known Exploited Vulnerabilities (KEV)** with FIRST **Exploit Prediction Scoring System (EPSS)** probabilities and bounded **NIST NVD** enrichment.

It is **not a vulnerability scanner**, an inventory management system, or a verified catalogue of previously unknown zero-day vulnerabilities. It focuses on CVEs in CISA KEV, which CISA has identified as exploited in the wild. It does not determine if your organisation uses an affected product.

## Using the dashboard

1. **Start with the overview** to check the last collection time, coverage and triage categories.
2. **Review Intelligence changes** for new KEV additions or substantial EPSS probability increases; subscribe to the RSS feed in your preferred reader.
3. **Search or filter** by CVE, product, vendor and priority; sort by date, EPSS or available CVSS.
4. **Validate the source** by opening the NVD details and relevant vendor/CISA advisories.
5. **Check applicability** against your actual assets, affected versions, internet exposure and compensating controls. Raise remediation work only with supporting evidence.

### How the metrics should be interpreted

- **KEV**: evidence of exploitation in the wild as assessed by CISA, not necessarily exploitation against *your* environment.
- **EPSS**: probability from 0 to 1 estimating exploitation in the next 30 days, not an impact score or confirmed attack activity.
- **CVSS**: technical severity, available only for records enriched in NVD; missing is not zero.
- **Priority** (transparent heuristic, *not* asset-aware): Critical = KEV and EPSS ≥ 0.50; High = KEV and EPSS ≥ 0.10; otherwise Elevated. All records are CISA KEV and warrant investigation based on exposure.
- **Momentum**: change in EPSS **percentage points** between the two most recent stored daily observations for that CVE; blank until two observations exist.

## v0.2 RSS alerts

The `/feed.xml` feed supports two implemented event types:

| Alert | Condition | Notes |
|---|---|---|
| Newly observed CISA KEV | CVE appears that did not exist in the previous successful collection | First ever collection creates a baseline and emits **zero** alerts |
| EPSS rise | Current probability minus previous UTC-day baseline is **at least 0.25 (25 percentage points)** | A CVE can alert once per UTC day; this is a signal, *not* exploitation confirmation |

**Reserved for future releases (not implemented):** newly observed public PoC references and new vendor patches or mitigations. These require independent source integration and validation; neither is inferred from arbitrary text.

### Collector cadence and data history

- GitHub Actions runs on **`main` every six hours** at `17 */6 * * *` UTC (not guaranteed exact).
- The first successful collection in a UTC day freezes the **daily EPSS baseline** for that date; future runs do not rewrite that baseline.
- Up to 45 UTC days of snapshots and 200 RSS alerts are retained in the repository. These are bounded limits, not permanent archival.
- KEV changes are assessed against the last successful collection, not the previous daily baseline.
- Alerts are deduplicated by **CVE + category + UTC date**. This deliberately suppresses repeated alerts in the same UTC day.
- Each GitHub Pages site serves static JSON and RSS files. No server, accounts, secrets or email notification service is involved.

## Deploying via `dev` → `main` (recommended)

**Important:** GitHub Pages currently serves `main`. Changes placed on `dev` are not deployed. Do not change the Pages source to `dev`.

1. Download the v0.2 ZIP and **extract it**. It contains a `zeroday-radar/` directory with all source files.
2. In https://github.com/potentialsailboat/zeroday-radar, use the branch selector on the Code tab and choose **`dev`**. Double-check that `dev` is visible before editing or uploading.
3. Upload the files and folders from inside `zeroday-radar/` to the **root of `dev`**, keeping `.github/workflows/update.yml` and `.github/workflows/validate.yml` in their exact directories. Files with the same names must be *replaced*, not duplicated in a second folder.
4. Commit the changes to `dev`. GitHub's web UI may not reliably overwrite nested files through bulk upload. For files that already exist, edit them individually through GitHub's pencil icon, **or use the GitHub Desktop method below**.
5. Check **Actions → Validate ZeroDay Radar** for successful unit and syntax tests on `dev`. It uses no API credentials and does not deploy the production website.
6. Optionally use **Actions → Update threat intelligence → Run workflow**, selecting `dev` in the branch dropdown. This does a live collection and validates output, but deliberately **does not commit data or deploy** from `dev`.
7. Create a pull request: **base `main` ← compare `dev`**. Review the diff and ensure the validation workflow passed. Merge it into `main`.
8. On `main`, go to **Actions → Update threat intelligence → Run workflow** and select `main` for the first v0.2 collection. Check that the collection, commit and Pages deployment succeeded.
9. Visit the dashboard and `/feed.xml`. Your first collection should show **no new alerts**, because it creates the baseline. On subsequent successful collections meaningful changes will appear.

### Easier uploading with GitHub Desktop

1. Install GitHub Desktop and **Clone a repository** for `potentialsailboat/zeroday-radar`.
2. Select **Current Branch → dev** (fetch origin first if necessary).
3. Copy the *contents* of the downloaded `zeroday-radar` folder into the local cloned repository. Allow replacement of matching files; keep the `.git` folder untouched.
4. Review changed files in GitHub Desktop. Add a commit message such as `feat: v0.2 intelligence history and RSS`.
5. Click **Commit to dev**, then **Push origin**, and create a pull request from `dev` to `main`.

### Important workflow configuration

- GitHub repository **Settings → Pages → Source: GitHub Actions**.
- The `update.yml` workflow uses `contents: write` to commit refreshed data to `main`. Repository Settings → Actions → General → Workflow permissions must allow writes; branch protection settings must also permit your chosen automation strategy.
- `NVD_API_KEY` is optional. If used, store it in **Settings → Secrets and variables → Actions**. Never commit credentials.
- A GitHub-hosted scheduled workflow normally runs only on the **default branch**. A manual run on `dev` is for testing only, and no production Pages deployment occurs.
- After updating `update.yml`, verify the new workflow permissions and output in the Actions logs.

## Repository structure

```
.github/workflows/update.yml      Scheduled collection & main-only deployment
.github/workflows/validate.yml    Push/PR tests (no deployment)
scripts/collect.py                Live CISA/EPSS/NVD collector
scripts/intelligence_history.py   Snapshots, change detection and RSS
tests/test_history.py             Offline unit tests
index.html, style.css, app.js     Dashboard UI
data/vulnerabilities.json         Generated current records (not bundled)
data/history.json                 Generated daily EPSS baselines
data/alerts.json                  Generated alert log
feed.xml                          Generated RSS feed
```

## Run tests locally

With Python 3.12+:

```bash
python -m unittest discover -s tests -v
python scripts/collect.py
```

The second command calls public external APIs and may take minutes due to NVD rate limits. Only run it when you intend to replace local generated datasets.

## Current limitations

- KEV-only coverage, not all published CVEs. No PoC or vendor-update alert integrations yet.
- Only the newest 15 KEV entries receive NVD enrichment per refresh by default; other CVSS values may be unavailable.
- Snapshot history starts when v0.2 first runs. Historical EPSS trajectories from earlier days are **not backfilled**.
- EPSS day-over-day change is a probability estimate; large increases are leads for investigation, not evidence of exploitation.
- Feed readers fetch RSS on their own schedules. RSS isn't push/instant notification delivery.
- GitHub scheduled workflows can start late or become disabled due to inactivity.
- A compromised upstream source, collection outage, or missing enrichment may affect coverage. Inspect the generated warnings and GitHub Actions logs.
- Public Pages data is visible to anyone. Do not add private asset inventories, secrets or internal CVE annotations to this repository.

## Roadmap

- Verified exploit-reference/PoC detection and vendor mitigation changes.
- CVEs outside KEV, technology watchlists and affected-product matching.
- More detailed daily change visualisation and source health tracking.
- Optional user-specific risk overlays without disclosing internal inventories.

## License

MIT. Source inputs remain subject to their respective source terms and attribution.

## v0.3 — RSS, source health and emerging CVE sample

- `/alerts.html` offers a human-readable alert history. `/feed.xml` remains the RSS endpoint; `feed.xsl` adds a browser preview for browsers supporting XSLT.
- Source health distinguishes complete, partial, unavailable and cached NVD discovery results. Collection timestamps indicate *fetch time*, not source publication time.
- Recent NVD CVE discovery is a limited first-page sample of up to 100 CVEs in the preceding seven days. **Recently published does not mean actively exploited**, and not all CVEs are included. NVD data may be temporarily unavailable.
- Existing KEV + EPSS prioritisation remains the only prioritised table. An NVD discovery item has no KEV status unless the independent KEV catalogue confirms it.
- The expected PoC and vendor-remediation event feeds are not yet implemented; no unsupported source assertions or fake alert events are generated.
- See [v0.3 deployment guide](V03-DEPLOY.md) for `dev` → PR → `main` steps.
