---
name: exposure
description: Answer questions about software supply-chain risk in the repositories this world watches — which vulnerabilities are actively being exploited, which services and teams own them, how far a vulnerability reaches, what licences the estate carries, and how much of the estate can actually be seen. Use for "are we exposed", "what should we fix first", "are we affected by CVE-x", "what are we running", "which team owns this", or any question about dependencies, CVEs or security posture.
---

# Supply-chain exposure

This realm answers one question properly: **of everything that could be wrong, what is
actually being used against people right now, and who owns it.**

## The rule that outranks everything else here

**Never report a vulnerability for a dependency whose purl has no `@version`.**

GitHub emits a versionless purl when it cannot resolve an exact version. OSV answers a
versionless purl with *every vulnerability the package has ever had* — 80 for one package
this realm was tested against, against 7 for the version actually in use. Reporting those
80 tells someone they have eleven times the exposure they have, in a table that looks
exactly like a real one.

Every shipped view carries `WHERE d.purl CONTAINS '@'`. If you write a query by hand, carry
it too. `UnresolvedDependencies` exists so the excluded dependencies are reported as a
visible gap rather than silently dropped.

## Run a view

| The question | The view |
|---|---|
| Are we exposed right now? | `ActivelyExploited` — the shortlist |
| What do we fix first? | `RiskRanked` — KEV, then EPSS, then severity |
| How are we doing overall? | `RepoExposure` — one row per service |
| Which fix buys the most? | `BlastRadius` — reach per vulnerability |
| Is anything ransomware-linked? | `RansomwareExposure` |
| What can't we see? | `UnresolvedDependencies` |
| What licences are we carrying? | `LicenceMix` |
| Write it up for the board | `ExposureBriefing` — costs a model call |

Two scheduled agents run without being asked: `kevSweep` each morning (CISA's catalog
changes even when your code does not — a CVE triaged as "not exploited" on Monday can be
on the list by Thursday) and `coverageAudit` on Mondays.

## Saying it properly

- **Severity is not urgency.** CVSS and CRITICAL/HIGH score how bad something would be *if*
  exploited, which is why most of any backlog reads high. Lead with KEV and EPSS. If you
  quote a severity, quote it as impact, never as priority.
- **`activelyExploited: 0` is a real and good answer** — and it is a different statement from
  "no vulnerabilities". Say which one you mean. A clean KEV result alongside 40 known
  vulnerabilities is a healthy posture, not a clean bill of health.
- **EPSS is a probability, not a score out of 100.** `0.94` means a 94% modelled chance of
  exploitation activity in the next thirty days. The percentile is usually the more legible
  number for someone meeting EPSS for the first time.
- **`knownRansomwareCampaignUse: Known` ends the argument.** Lead with it.
- **Always name the owner.** A finding without a team is a finding nobody will action. If
  `team` is null, say that the repository has no recorded owner — that is itself a finding.
- **Internet-facing changes the sentence.** The same CVE in a public API and in a nightly
  batch job are different risks, and the views carry the flag so you can say which.

## Warnings are the difference between partial and clean

A `PRODUCER_ERROR` naming `repoSbom` means a repository could not be read at all — usually
its dependency graph is disabled, and GitHub returns a 404 that must never be reported as
"no dependencies". Name the repositories that failed. In this realm above all others, an
empty table caused by a fetch failure reads as "you are safe", and that is the worst
possible way to be wrong.
