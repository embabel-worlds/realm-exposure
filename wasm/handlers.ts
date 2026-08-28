/*
 * Scheduled agents over the exposure graph.
 *
 * A view answers when someone asks. These run whether or not anyone asks, which
 * is the difference that matters for security: the estate does not change when
 * you look at it, but CISA's catalog does — a CVE you triaged as "severe but not
 * exploited" on Monday can be on the actively-exploited list by Thursday without
 * a single line of your code changing. Nobody re-runs a dashboard on the day the
 * world changes underneath it. A schedule does.
 *
 * A handler reads the graph with ctx.gateway.cypher.query — NOT a global gateway,
 * which does not exist here, and not gateway.kg.query, which is the code_mode
 * surface rather than the wasm one. The granted host tools inside wasm are
 * cypher_query, sql_query and sql_update; cypher_query takes no bound parameters,
 * so anything variable is filtered in TypeScript over a bounded read rather than
 * concatenated into the query string.
 */

type Row = Record<string, any>

async function read(ctx: any, cypher: string): Promise<Row[]> {
  const res = await ctx.gateway.cypher.query({ cypher })
  if (!res) return []
  if (Array.isArray(res)) return res
  if (Array.isArray(res.rows)) return res.rows
  if (res.data && Array.isArray(res.data.rows)) return res.data.rows
  return []
}

/*
 * The morning sweep: everything CISA has confirmed is being exploited, across
 * every watched repository, with the owner attached.
 *
 * The `d.purl CONTAINS '@'` guard is not optional here either. GitHub emits a
 * purl with no version when it cannot resolve one, and OSV answers a versionless
 * purl with every vulnerability the package has ever had — eighty rather than
 * seven, for one package this realm was tested against. A digest built without
 * the guard would report an order of magnitude more exposure than exists, every
 * morning, with total confidence.
 */
export async function kevSweep(args: { minSeverity?: string }, ctx: any) {
  const findings = await read(ctx, `
    MATCH (w:WatchedRepo)-[:HAS_DEPENDENCY]->(d:Dependency)
    WHERE d.purl CONTAINS '@'
    MATCH (d)-[:HAS_VULNERABILITY]->(v:Vulnerability)-[:ON_KEV]->(k:KevListing)
    RETURN w.fullName AS repo, w.service AS service, w.team AS team,
           w.internetFacing AS internetFacing, w.tier AS tier,
           d.packageName AS package, d.version AS version,
           v.cveId AS cve, v.severity AS severity,
           k.vulnerabilityName AS knownAs,
           k.knownRansomwareCampaignUse AS ransomware,
           k.dateAdded AS listedOn
    LIMIT 200
  `)

  const wanted = (args && args.minSeverity ? args.minSeverity : '').toUpperCase()
  const rank: Record<string, number> = { LOW: 0, MODERATE: 1, HIGH: 2, CRITICAL: 3 }
  const kept = wanted
    ? findings.filter(f => (rank[String(f.severity || '').toUpperCase()] ?? -1) >= (rank[wanted] ?? 0))
    : findings

  const ransomware = kept.filter(f => f.ransomware === 'Known')
  const facing = kept.filter(f => String(f.internetFacing) === 'true')

  /* Owners, not counts: a digest that says "14 findings" is read once and filed.
     One that says which team owns what gets forwarded. */
  const byTeam: Record<string, number> = {}
  for (const f of kept) {
    const t = f.team || 'unowned'
    byTeam[t] = (byTeam[t] || 0) + 1
  }

  const worst = ransomware[0] || facing[0] || kept[0] || null

  return {
    checkedAt: new Date().toISOString(),
    activelyExploited: kept.length,
    usedInRansomware: ransomware.length,
    onInternetFacingServices: facing.length,
    byTeam,
    /* The one line a human should read first, already written. */
    headline: worst
      ? `${worst.service} depends on ${worst.package} ${worst.version}, which carries ${worst.cve}` +
        ` — confirmed exploited since ${worst.listedOn}` +
        (worst.ransomware === 'Known' ? ', and used in ransomware campaigns' : '') +
        `. Owner: ${worst.team || 'nobody recorded'}.`
      : 'Nothing in the watched estate is on CISA’s actively-exploited list.',
    findings: kept.slice(0, 25),
  }
}

/*
 * Coverage, as a fact rather than a hope.
 *
 * Every number the other handler reports is conditional on the estate being
 * visible, and it silently is not when a repository has no dependency graph or a
 * dependency cannot be pinned to a version. A security report whose denominator
 * is quietly wrong is worse than no report, so this states the denominator.
 */
export async function coverageAudit(args: {}, ctx: any) {
  const rows = await read(ctx, `
    MATCH (w:WatchedRepo)
    OPTIONAL MATCH (w)-[:HAS_DEPENDENCY]->(d:Dependency)
    WITH w, count(d) AS deps,
         count(CASE WHEN d.purl CONTAINS '@' THEN 1 END) AS resolved
    RETURN w.fullName AS repo, w.service AS service, w.tier AS tier,
           deps, resolved
    LIMIT 500
  `)

  const invisible = rows.filter(r => Number(r.deps) === 0)
  const partial = rows.filter(r => Number(r.deps) > 0 && Number(r.resolved) < Number(r.deps))
  const totalDeps = rows.reduce((n, r) => n + Number(r.deps || 0), 0)
  const totalResolved = rows.reduce((n, r) => n + Number(r.resolved || 0), 0)

  return {
    checkedAt: new Date().toISOString(),
    repositoriesWatched: rows.length,
    repositoriesWithNoDependencyGraph: invisible.map(r => r.repo),
    repositoriesWithUnresolvedVersions: partial.map(r => ({
      repo: r.repo, resolved: Number(r.resolved), of: Number(r.deps),
    })),
    dependenciesSeen: totalDeps,
    dependenciesVersionResolved: totalResolved,
    /* Percentage of the estate any vulnerability claim can actually speak about. */
    coveragePercent: totalDeps === 0 ? 0 : Math.round((totalResolved / totalDeps) * 1000) / 10,
    verdict: invisible.length === 0 && totalDeps === totalResolved
      ? 'Full visibility: every watched repository resolved, every dependency pinned.'
      : `Partial visibility. ${invisible.length} repositor${invisible.length === 1 ? 'y has' : 'ies have'}` +
        ` no dependency graph and ${totalDeps - totalResolved} dependenc${totalDeps - totalResolved === 1 ? 'y is' : 'ies are'}` +
        ' unpinned — nothing can be claimed about those.',
  }
}

/* Before the working day, so the first thing anyone reads is current. */
defineSchedule('kevSweep', '0 0 7 * * *')
/* Weekly is the right cadence for a denominator: it changes when someone adds a
   repository or fixes a build, not hourly. Monday, ahead of the sweep. */
defineSchedule('coverageAudit', '0 30 6 * * MON')
