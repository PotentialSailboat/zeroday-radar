# ZeroDay Radar v0.3 — dev deployment guide

## What changed
- RSS now has a browser-readable XSLT stylesheet (`feed.xsl`) and retains valid RSS 2.0 / Atom self-link semantics.
- `alerts.html` and `alerts.js` display alert history and subscription instructions.
- Source health panels show CISA, EPSS, NVD enrichment, and NVD discovery states.
- A *bounded* NVD published-window query retrieves up to 100 records for the preceding seven days into `data/emerging.json`, excluding entries already listed in KEV. It is a **sample**, not an exhaustive listing and **not evidence of active exploitation**.
- Cached enrichment and NVD outage handling from the previous hotfix are included.

## Deploy safely
1. Back up or pull the latest `dev` branch. This ZIP is based on the released v0.2 source plus the NVD hotfix; reconcile any newer repository-specific edits before replacing files.
2. Extract this ZIP. With GitHub Desktop, switch to **dev** and copy the **contents** of `zeroday-radar` over the cloned repository. Do **not** delete an existing `data/vulnerabilities.json`, `data/history.json`, or `data/alerts.json` during the copy. This package contains no generated datasets.
3. Commit and push `dev` (`feat: v0.3 discovery and source-health dashboard`).
4. On GitHub Actions, verify **Validate ZeroDay Radar** succeeds, including `tests/test_v03.py`.
5. Optionally run **Update threat intelligence** manually on **dev**. It runs data collection checks, **does not commit dev data or deploy GitHub Pages**. Note that dev runs start without production historical data if it is absent from dev; that is expected.
6. Open a pull request: **base main**, **compare dev**. Review changes and merge.
7. Run **Update threat intelligence** on **main** once, or let its existing six-hour schedule run. Verify the actions are green and that all JSON files and feed.xml are published.
8. Check dashboard, `/alerts.html`, `/feed.xml`, and the NVD discovery section. `feed.xml` will show an HTML preview in browsers that support XSLT, while remaining XML for RSS readers. Other browsers may show raw XML; the dedicated `/alerts.html` always provides a human-readable view.

## Troubleshooting
- If NVD is unavailable, the discovery panel will report stale/unavailable and NVD enrichment may be cached. Inspect workflow logs for source warnings.
- On the first collection, a feed with zero items is **expected**. New alerts only occur after baseline creation.
- `data/emerging.json` is a **first page only** NVD query (max 100). No claim of full NVD coverage should be made.
- We have not enabled public PoC or vendor remediation alerts: these require trustworthy, independently validated source integration.
- GitHub Actions `schedule` operates only from the default branch, and may run late; manual `workflow_dispatch` remains available.
