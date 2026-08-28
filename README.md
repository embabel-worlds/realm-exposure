# realm-exposure

**What your software is actually exposed to — and which of it is being exploited right now.**

```
WatchedRepo ──HAS_DEPENDENCY──▶ Dependency ──HAS_VULNERABILITY──▶ Vulnerability ──ON_KEV────▶ KevListing
   (yours)         (GitHub)        (purl)          (OSV)             (CVE)      ──HAS_EPSS──▶ EpssScore
                                                                                    (CISA / FIRST)
```

Name the repositories you care about. Everything else is fetched when a query asks for it
and rolled back after — there is no ingest, no nightly job, and no copy of your dependency
tree going stale in a database.

Four independent organisations' data, none of which knows about the others, joined into one
row that says *fix this*:

> `WebGoat/WebGoat` depends on `com.thoughtworks.xstream:xstream 1.4.5`, which carries
> **CVE-2021-39144** — remote code execution, confirmed by CISA as actively exploited since
> 2023-03-10, federal remediation deadline 2023-03-31.

## Why this is not "we already have Dependabot"

Dependabot tells you a package is vulnerable, per repository, in a silo. It does not tell you
which vulnerabilities are being **exploited in the wild**, does not price **likelihood**, does
not rank across the whole estate, and cannot join a finding to the **service** it is, the
**team** that owns it, or whether it is **internet-facing**. Severity alone cannot triage
anything: it scores how bad something would be *if* exploited, which is why 40% of every
backlog reads "high" and why the backlog never shrinks.

This realm ranks by what is actually happening: CISA-confirmed exploitation first, then the
EPSS probability of exploitation in the next thirty days, and only then severity.

## Sources — all open, none requiring an account

| Source | Gives | Auth |
|---|---|---|
| [GitHub dependency graph](https://docs.github.com/en/rest/dependency-graph) | the real resolved tree, transitive, as SPDX with purls | **none** for public repos |
| [OSV](https://osv.dev) | vulnerabilities for one exact version, with the CVE alias | none |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | which CVEs are confirmed exploited | none |
| [FIRST EPSS](https://www.first.org/epss/) | probability of exploitation in 30 days | none |

**No build file is ever parsed.** GitHub has already resolved the tree and emits a purl; OSV
consumes the same purl byte for byte, qualifiers and all. That is the whole reason this realm
contains no string handling — and why it does not break when a build tool changes its format.

## Getting an answer

```javascript
gateway.repository.createEntry({ type: "WatchedRepo", data: {
  fullName: "acme/checkout", owner: "acme", repo: "checkout",
  service: "Checkout API", team: "payments", internetFacing: "true", tier: "critical",
}})
```

Then run `ActivelyExploited`, or open **Blast Radius** (`apps/blast-radius.html`).

## The trap this realm exists to avoid

GitHub cannot always resolve an exact version, and says so with a purl carrying no `@version`.
Ask OSV about one of those and it returns every vulnerability the package has **ever** had:

```
pkg:maven/com.fasterxml.jackson.core/jackson-databind          → 80 vulnerabilities
pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.18.2   →  7 vulnerabilities
```

Reporting the 80 would overstate exposure elevenfold in a table indistinguishable from a real
one. Every view therefore carries `WHERE d.purl CONTAINS '@'`, and `UnresolvedDependencies`
reports what that excludes — because a security report with a quietly wrong denominator is
worse than no report. `coverageAudit` states the denominator on a schedule.

## Cost, honestly

The first read of a repository asks OSV about every resolved dependency — 543 for one repo
tested here, taking about 20 seconds. After that it is cached for a day, **including the
clean answers**, which is the part that matters: most dependencies have nothing against
them, and a clean answer is an empty one. A producer caches only its positive results
unless it asks otherwise, so `vulnsForPurl` sets `negativeTtlSeconds` alongside `seconds`.

Measured here, same query twice with nothing changed between:

| | time | OSV calls |
|---|---|---|
| without `negativeTtlSeconds` | 19.1 s | 581 |
| with it, warm | 5.8 s | 2 |

If you fork this realm and drop that one setting, it will still work and will be thirty
times more expensive, every single query.

## Testing

```bash
export EMBABEL_TOKEN=...
python3 scripts/test-views.py http://127.0.0.1:11043
```

Runs every view, fails on zero rows, surfaces every warning, and reconciles against the
sources — including the assertion that no finding is ever reported against an unversioned purl.

## Licence

Apache 2.0. Source data is each publisher's: CISA KEV and EPSS are public domain / free to
use, OSV is CC-BY-4.0.
