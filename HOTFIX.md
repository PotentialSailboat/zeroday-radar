# NVD HTTP 503 hotfix for ZeroDay Radar v0.2

## What changed
- Existing retry behaviour remains (3 attempts with delays).
- After three consecutive NVD HTTP 503 failures (after retries), the collector skips the remaining NVD lookups in that run.
- Previously collected CVSS, severity, and NVD timestamps are retained from `data/vulnerabilities.json` when NVD cannot be reached.
- Detailed source errors are printed in GitHub Actions logs.
- Includes two new offline regression tests.

## Apply to dev
1. Check out your `dev` branch locally (GitHub Desktop works).
2. Copy `scripts/collect.py` and `tests/test_nvd_recovery.py` into the corresponding locations in the repository, preserving the directory names. DO NOT delete any existing files.
3. Commit and push to `dev`.
4. Check Actions > Validate ZeroDay Radar; it should run six tests.
5. Optional: run Update threat intelligence manually selecting `dev` to check API behaviour. It must not deploy Pages from dev.
6. Open a pull request from `dev` to `main`, review and merge after the tests pass.
7. Run Update threat intelligence on main and check the warnings and resulting dataset.

## Important
- HTTP 503 is an upstream service-unavailable response; this hotfix cannot guarantee that NVD will recover.
- The displayed dashboard can still show a partial-source warning when NVD is down. That is appropriate.
- Previously cached NVD values may become outdated; source freshness should be considered during analysis.
- To benefit from caching, `data/vulnerabilities.json` must already exist in the checked-out branch. The production workflow commits this dataset on main.
- No NVD API key is required for the hotfix, but configuring one may improve access reliability; it will not fix a genuine NVD outage.
