#!/usr/bin/env python3
"""Run every view this realm ships against a LIVE host, and check the claims.

Counting rows is not enough here. This realm's characteristic failure is not an
empty table — it is a FULL one that overstates exposure, because a dependency
whose version GitHub could not resolve makes OSV answer about the package in
general rather than the version in use (80 vulnerabilities rather than 7 for one
package tested). A harness that only asserted "rows came back" would pass on
exactly the bug that matters most.

So the ground-truth section asserts the guarantees, not the volume:

  * no finding is EVER reported against an unversioned purl;
  * every actively-exploited finding carries a CVE and a CISA listing date;
  * the estate summary's arithmetic agrees with itself;
  * a warning is never silently swallowed — in this realm a failed fetch that
    renders as an empty table reads as "you are safe".

    export EMBABEL_TOKEN=...
    python3 scripts/test-views.py [http://127.0.0.1:11043]
"""

import json
import os
import re
import sys
import urllib.error
import urllib.request

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:11043").rstrip("/")
TOKEN = os.environ.get("EMBABEL_TOKEN")

# A view with no case here is an untested view.
VIEWS = {
    "ActivelyExploited":      {"limit": 50},
    "RiskRanked":             {"limit": 40},
    "RepoExposure":           {"limit": 50},
    "BlastRadius":            {"limit": 25},
    "UnresolvedDependencies": {"limit": 40},
    "RansomwareExposure":     {"limit": 25},
    "LicenceMix":             {"limit": 25},
    "ExposureBriefing":       {"limit": 20},
}

# Views that may legitimately be empty — and WHY, so nobody widens this set by
# reflex. An empty exploited-list is the good outcome, not a broken join; the
# estate views below prove the join itself works.
MAY_BE_EMPTY = {
    "ActivelyExploited":      "no confirmed-exploited vulnerability is the desired state",
    "RansomwareExposure":     "ransomware-linked exposure is rare and its absence is good news",
    "UnresolvedDependencies": "an estate where every version resolved is fully covered",
    "ExposureBriefing":       "written from exploited findings; empty shortlist, empty briefing",
}

failures, notes = [], []


def run_view(name, params):
    req = urllib.request.Request(
        f"{BASE}/api/v1/admin/kg/views/{name}/run",
        data=json.dumps(params).encode(),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {TOKEN}"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=300) as r:
        return json.load(r)


def check_views():
    results = {}
    for name, params in VIEWS.items():
        try:
            res = run_view(name, params)
        except urllib.error.HTTPError as e:
            failures.append(f"{name}: HTTP {e.code} {e.read()[:200]!r}")
            continue
        except Exception as e:  # noqa: BLE001 — a harness reports; it does not raise
            failures.append(f"{name}: {e}")
            continue
        results[name] = res
        rows, warns = res.get("rows") or [], res.get("warnings") or []
        if not rows and name not in MAY_BE_EMPTY:
            failures.append(f"{name}: ZERO ROWS — a join that never fires looks exactly like this")
        for w in warns:
            notes.append(f"{name}: {str(w)[:200]}")
        why = f"  ({MAY_BE_EMPTY[name]})" if not rows and name in MAY_BE_EMPTY else ""
        print(f"  {name:<24}{len(rows):>4} rows{why}")
    return results


VERSIONED = re.compile(r"@[^@/]+$|@[^@/]+\?")


def check_ground_truth(results):
    # 1. THE guarantee. Nothing is ever reported against an unpinned dependency.
    for name in ("ActivelyExploited", "RiskRanked", "RansomwareExposure"):
        for row in (results.get(name) or {}).get("rows") or []:
            v = row.get("version")
            if v in (None, "", "null"):
                failures.append(
                    f"ground truth: {name} reported {row.get('package')} with NO resolved "
                    f"version — OSV answers a versionless purl about the whole package, so "
                    f"this row may overstate exposure by an order of magnitude"
                )
    print("  no finding is reported against an unversioned dependency")

    # 2. An exploited finding without a CVE and a listing date is not evidence.
    for row in (results.get("ActivelyExploited") or {}).get("rows") or []:
        if not row.get("cve"):
            failures.append(f"ground truth: exploited finding for {row.get('package')} carries no CVE")
        if not row.get("confirmedExploitedSince"):
            failures.append(f"ground truth: {row.get('cve')} claims exploitation with no CISA date")
    print("  every exploited finding carries a CVE and a CISA listing date")

    # 3. The estate summary must agree with itself.
    for row in (results.get("RepoExposure") or {}).get("rows") or []:
        deps, res_, unres = row.get("dependencies"), row.get("versionResolved"), row.get("versionUnresolved")
        if None not in (deps, res_, unres) and res_ + unres != deps:
            failures.append(
                f"ground truth: {row.get('repo')} says {res_} resolved + {unres} unresolved "
                f"!= {deps} dependencies"
            )
        if (row.get("activelyExploited") or 0) > (row.get("vulnerabilities") or 0):
            failures.append(
                f"ground truth: {row.get('repo')} reports more exploited "
                f"({row.get('activelyExploited')}) than vulnerabilities ({row.get('vulnerabilities')})"
            )
    print("  estate arithmetic reconciles")

    # 4. Reach can never exceed the estate.
    estate = len((results.get("RepoExposure") or {}).get("rows") or [])
    for row in (results.get("BlastRadius") or {}).get("rows") or []:
        if estate and (row.get("repositoriesAffected") or 0) > estate:
            failures.append(
                f"ground truth: {row.get('cve')} claims {row['repositoriesAffected']} "
                f"repositories affected out of {estate} watched"
            )
    print("  blast radius never exceeds the watched estate")


def main():
    if not TOKEN:
        sys.exit("EMBABEL_TOKEN is not set — this harness needs an admin bearer token. It "
                 "refuses to run rather than report a green that only means it never asked.")
    print(f"realm-exposure against {BASE}\n\nviews:")
    results = check_views()
    print("\nground truth:")
    check_ground_truth(results)

    if notes:
        print("\nwarnings from the host — READ THESE. In this realm a failed fetch renders as")
        print("an empty table, which reads as 'you are safe':")
        for n in notes:
            print(f"  {n}")
    if failures:
        print(f"\nFAILED ({len(failures)}):")
        for f in failures:
            print(f"  {f}")
        sys.exit(1)
    print("\nOK — every view answered and every guarantee holds.")


if __name__ == "__main__":
    main()
