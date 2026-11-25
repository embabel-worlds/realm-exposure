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


# A figure the engine marks short is not the realm's figure, and a battery that counts it reports
# drift that is the source's. short(d) reads an answer's own error, reason, warnings and outcome and
# is None when the answer is whole, else the line that stands in for the figure: "REFUSED: <why>"
# or "PARTIAL <n>: <the engine's reason>". It reads both wires: a query answer (`rows`, `warnings`
# as strings opening with the engine's code) and a view envelope (`status`, `outcome`, `warnings`
# as {code, message}).
# Raw warning codes that mean rows or values may be missing (the engine's incompleteness kinds).
# Cost notes (FILTERED_IN_GRAPH, AGGREGATE_NOT_PUSHED, EMPTY_NOT_KEPT, PUSHDOWN_VALUE_UNMATCHED),
# FILTER_STARVED (an honest empty), STALE_COPY, FIELDS_WITHHELD and UNKNOWN_VIA leave every row in place.
SHORT_CODES = (
    "PARTIAL_RESULT", "PRODUCER_ERROR", "NEEDS_FILTER", "NEEDS_PRODUCER", "FILTER_REJECTED",
    "UNPUSHED_FILTER", "AMBIGUOUS_LABEL", "INCOMPLETE_TRAVERSAL", "INCOMPLETE_RANKING",
    "INCOMPLETE_AGGREGATE", "INCOMPLETE_INPUT", "MATERIALIZATION_FAILED", "REDUCTION_FAILED",
    "UNPARSEABLE_ANSWER", "TERMS_UNAVAILABLE", "COMPUTE_FAILED", "PROPERTY_NOT_STORED",
    "FOLLOW_CAPPED", "UNLINKED_CHILDREN", "RESOLUTION_DROPPED", "AGENTIC_DEGRADED",
    "SOURCE_UNANSWERED",
)
# The typed `reason` a query result carries when it is not a clean answer and not an honest empty.
SHORT_REASONS = ("UNBOUNDED", "PARTIAL_NOT_MATCHED", "UNPUSHED_FILTER", "DISCONNECTED",
                 "INTERNAL_ERROR", "WRITE_IN_PROGRESS", "KILLED", "TOO_EXPENSIVE")
# Public warning codes on a view envelope that mean the same.
SHORT_PUBLIC = ("PARTIAL", "REDUCTION_FAILED", "COMPUTE_FAILED", "PROPERTY_NOT_STORED",
                "AGENTIC_DEGRADED", "RATE_LIMITED", "SOURCE_UNAVAILABLE", "SOURCE_REJECTED",
                "INVALID_FILTER", "UNPUSHED_FILTER", "TOO_BROAD", "FETCH_CAPPED",
                "INDEX_UNAVAILABLE", "ARGUMENT_REFUSED")


def short(d, figure=None):
    tag = "PARTIAL" if figure is None else "PARTIAL %s" % (figure,)
    if not isinstance(d, dict):
        return "REFUSED: not an engine answer: " + str(d)[:160]
    if "outcome" in d or "status" in d:  # a view envelope
        err = d.get("error") or {}
        if d.get("status") != "SUCCEEDED":
            return "REFUSED: %s %s" % (d.get("status"), (err.get("code", "") + " " + err.get("message", "")).strip()[:160] if isinstance(err, dict) else str(err)[:160])
        ws = [w for w in d.get("warnings") or [] if isinstance(w, dict) and w.get("code") in SHORT_PUBLIC]
        if d.get("outcome") not in ("OK", "EMPTY") or ws:
            why = ws[0]["code"] + ": " + ws[0].get("message", "") if ws else "outcome " + str(d.get("outcome"))
            return "%s: %s" % (tag, why[:200])
        return None
    if d.get("error"):
        return "REFUSED: " + str(d["error"])[:160]
    if d.get("run"):
        return "%s: the run had not finished (%s)" % (tag, d["run"])
    ws = [w for w in d.get("warnings") or [] if isinstance(w, str) and w.split(":", 1)[0].strip() in SHORT_CODES]
    if ws:
        return "%s: %s" % (tag, ws[0][:200])
    if d.get("reason") in SHORT_REASONS:
        return "%s: reason %s" % (tag, d["reason"])
    return None


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
        # A warning that says rows are missing fails the view: its table is not the answer, however
        # plausible it looks. Every other warning stays a note to read.
        s = short(res, len(rows))
        if s:
            failures.append(f"{name}: {s}")
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
