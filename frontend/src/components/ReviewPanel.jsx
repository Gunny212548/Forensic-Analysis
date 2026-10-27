import { useCallback, useEffect, useState } from 'react'
import { aiReviewAgain, getFindings, postReview } from '../api.js'
import { LEVEL_EN, REVIEW_CLASS, fmtNum, shortTs } from '../format.js'
import { Empty, MitreTags } from './common.jsx'
import FindingEvents from './FindingEvents.jsx'
import RuleCard from './RuleCard.jsx'
import { useAccess } from '../permissions.js'
import AiReview from './AiReview.jsx'
import { Section } from './cards.jsx'

// Unreviewed first, whatever its confidence: a high-confidence finding
// nobody has looked at must never sit above a reviewed one (NFR-9).
const ORDER = { Unreviewed: 0, Modified: 1, Accepted: 2, Rejected: 3 }

/** The review unit is the collapsed finding (rid|srcip|username), not the
 *  row - one case has 20,063 finding rows and 4 reviewable findings, and
 *  reviewing rows one at a time is a requirement that cannot be met
 *  (CLAUDE.md gotcha #19). Decisions are append-only server-side. */
export default function ReviewPanel({ caseId, focus, onlyKey = null, relatedHref = null, onChanged = null }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const [rejecting, setRejecting] = useState(null) // finding key awaiting a reason
  // Reviewing is an analyst's or a manager's (IAI-14); an admin reads only.
  const { can, why } = useAccess()
  const mayReview = can('finding:review')
  const [reasonCode, setReasonCode] = useState('')
  const [reasonNote, setReasonNote] = useState('')
  const [busyKey, setBusyKey] = useState('')
  const [openRule, setOpenRule] = useState('') // finding key whose rule card is open
  const [openEvents, setOpenEvents] = useState(onlyKey || '') // finding key whose source events are open

  const load = useCallback(async () => {
    setError('')
    try {
      setData(await getFindings(caseId))
    } catch (err) {
      setError(err.message)
    }
  }, [caseId])

  useEffect(() => {
    load()
  }, [load])

  // The AI review runs after the case is ready (triage.py): while it does, its advice arrives
  // batch by batch, so the list is read again every 20 s until it is done.
  const aiStatus = data?.ai_review?.status
  useEffect(() => {
    if (aiStatus !== 'queued' && aiStatus !== 'running') return undefined
    const t = setInterval(load, 20000)
    return () => clearInterval(t)
  }, [aiStatus, load])
  const [aiBusy, setAiBusy] = useState(false)
  async function reviewAgain() {
    setAiBusy(true)
    try {
      await aiReviewAgain(caseId)
      await load()
    } catch (err) {
      setError(err.message)
    } finally {
      setAiBusy(false)
    }
  }

  // A narrative citation asked for this finding (Result.jsx): bring it into
  // view and mark it briefly. After a frame, because the tab it lives in is
  // made visible in the same render that set `focus`.
  const [flash, setFlash] = useState('')
  // Bring one finding of this case into view and mark it briefly - also for a
  // chip that names a related finding.
  const reveal = useCallback((key) => {
    scrollToItem(key)
    setFlash(key)
    setTimeout(() => setFlash(''), 2500)
  }, [])
  useEffect(() => {
    if (!focus || !data) return undefined
    const raf = requestAnimationFrame(() => {
      scrollToItem(focus.key)
      setFlash(focus.key)
    })
    const t = setTimeout(() => setFlash(''), 2500)
    return () => {
      cancelAnimationFrame(raf)
      clearTimeout(t)
    }
  }, [focus, data])

  async function submit(key, action, extra = {}) {
    setBusyKey(key)
    try {
      await postReview(caseId, { finding_key: key, action, ...extra })
      setRejecting(null)
      setReasonCode('')
      setReasonNote('')
      await load()
      onChanged?.() // the case's step bar counts these decisions
    } catch (err) {
      setError(err.message)
    } finally {
      setBusyKey('')
    }
  }

  if (error && !data) return <Empty>{error}</Empty>
  if (!data) return <Empty>Loading...</Empty>

  const s = data.review_summary || {}
  const unreviewed = s.Unreviewed || 0
  // Within each review status, work in progress first (Investigating /
  // Contained), then Open, then Resolved, then findings outside the
  // workflow - and a fixed tie-break, so a finding does not jump away from
  // under the analyst when the list reloads after a change.
  const flowRank = (f) =>
    !f.lifecycle?.tracked ? 3 : { Investigating: 0, Contained: 0, Open: 1, Resolved: 2 }[f.lifecycle.status] ?? 1
  const findings = (data.findings || []).slice().sort((a, b) => {
    const d = ORDER[a.review.status] - ORDER[b.review.status]
    return (
      d ||
      flowRank(a) - flowRank(b) ||
      b.lvl - a.lvl ||
      b.cnt - a.cnt ||
      (a.key < b.key ? -1 : a.key > b.key ? 1 : 0)
    )
  })
  const reasonCodes = data.reason_codes || {}

  // One finding on its own page (FindingDetail): only that finding, without the
  // case-wide gate, history banner and workflow totals around it.
  const single = onlyKey != null
  const shown = single ? findings.filter((f) => f.key === onlyKey) : findings
  if (single && !shown.length) return <Empty>This finding is not in the case (it may have been re-processed away).</Empty>

  return (
    <>
      {!single && (
        <>
      {/* The export gate is stated up front, not discovered at export time:
          under a deadline an analyst needs to know what is still blocking. */}
      <div className={`rv-gate ${data.ready_for_report ? 'ok' : 'blocked'}`}>
        {data.ready_for_report
          ? 'Every finding has been reviewed - the final report can be issued'
          : `${unreviewed} finding(s) still unreviewed - the final report cannot be issued yet`}
        <span className="rv-counts">
          Accepted {s.Accepted || 0} · Modified {s.Modified || 0} · Rejected {s.Rejected || 0} ·
          Unreviewed {unreviewed}
        </span>
      </div>

      {/* The AI explains every suggestion (specs/ai_review_coverage.md): how far it is, and the
          ones without an explanation - a failed call, or advice written before the AI stopped
          suggesting decisions (specs/ai_triage_verdicts.md) - which Review again sends. */}
      {(() => {
        const missing = (data.findings || []).filter((f) => !f.ai_review?.what_happened).length
        // A case processed before the review ran in the background has no `ai_review`: shown
        // as stopped when suggestions lack advice, so Review again is offered for it too.
        const a = data.ai_review || (missing ? { status: 'failed', total: (data.findings || []).length } : null)
        if (!a || a.status === 'off') return null
        return (
          <div className={`rv-chain ${a.status === 'done' && !missing ? 'ev-ok' : 'rv-chain-warn'}`}>
            {a.status === 'queued' && 'AI review queued - it starts when the model is free.'}
            {a.status === 'running' &&
              `AI explaining every suggestion: ${a.done ?? 0} of ${a.total ?? '?'} done${a.model ? ` (${a.model})` : ''}` +
                (a.failed ? `, ${a.failed} failed so far` : '') + ' - explanations appear as they arrive.'}
            {a.status === 'done' && !missing && `AI explained all ${a.total} suggestions${a.model ? ` (${a.model})` : ''}.`}
            {(a.status === 'failed' || (a.status === 'done' && missing > 0)) &&
              `AI explanation on ${(a.total ?? 0) - missing} of ${a.total ?? '?'} suggestions; ${missing} without one` +
                (a.error ? ` (${a.error})` : '') + '.'}
            {(a.status === 'failed' || (a.status === 'done' && missing > 0)) && can('case:reprocess') && (
              <button type="button" className="rv-btn" style={{ marginLeft: 8 }} disabled={aiBusy} onClick={reviewAgain}>
                {aiBusy ? 'Starting...' : 'Review again'}
              </button>
            )}
          </div>
        )
      })()}

      {/* The decisions above are only as good as their history: the review
          log is hash-chained (hashchain.py), and an edited or deleted
          decision shows here. Decisions made before chaining existed are
          sealed by the first chained one, and say so. */}
      {data.review_chain && data.review_chain.entries > 0 && (
        <div
          className={`rv-chain ${
            !data.review_chain.intact
              ? 'ev-bad'
              : data.review_chain.entries === data.review_chain.sealed_legacy
                ? 'rv-chain-warn'
                : 'ev-ok'
          }`}
        >
          {!data.review_chain.intact
            ? `Decision history altered: ${data.review_chain.problem}`
            : data.review_chain.entries === data.review_chain.sealed_legacy
              ? `${data.review_chain.entries} decision(s) recorded before the history was hash-chained - ` +
                'not protected yet; the next decision seals them.'
              : `Decision history intact: ${data.review_chain.entries} entr${
                  data.review_chain.entries === 1 ? 'y' : 'ies'
                }, hash-chained` +
                (data.review_chain.sealed_legacy
                  ? ` (the first ${data.review_chain.sealed_legacy} predate chaining and are sealed by the next).`
                  : '.')}
        </div>
      )}

        </>
      )}

      {error && <Empty>{error}</Empty>}

      {single ? shown.map(item) : <ByArea findings={shown} areas={data.areas || []} item={item} />}
    </>
  )

  function item(f) {
    const st = f.review.status
    const busy = busyKey === f.key
    return (
      <div
        className={`rv-item ${REVIEW_CLASS[st] || ''} ${flash === f.key ? 'rv-flash' : ''}`}
        id={`rv-${f.key}`}
        key={f.key}
      >
        <div className="rv-head">
          {f.fd && (
            <span className="rv-fd" title="Finding id (FD-year-number, numbered per customer)">
              {f.fd}
            </span>
          )}
          {f.level && (
            <span
              className={`sev-tag sev-tag-${f.level}`}
              title={f.base_level && f.base_level !== f.level ? `Rule level: ${LEVEL_EN[f.base_level]}` : undefined}
            >
              {LEVEL_EN[f.level]}
            </span>
          )}
          <span className="rv-status">{st}</span>
          <span className={`rv-conf rv-conf-${f.confidence}`}>confidence: {f.confidence}</span>
          {/* Admiralty Code (confidence.py): letter = how far the log
              source as read can be trusted, number = how well-supported
              the finding is. The reasons are on hover - one sentence
              each, so the grade can be checked rather than believed. */}
          {f.admiralty && (
            <span
              className="rv-admiralty"
              title={
                `${f.admiralty.reliability.grade} - ${f.admiralty.reliability.name}: ` +
                `${f.admiralty.reliability.why.join('; ')}\n` +
                `${f.admiralty.credibility.grade} - ${f.admiralty.credibility.name}: ` +
                `${f.admiralty.credibility.why.join('; ')}\n(Admiralty Code / NATO 6x6)`
              }
            >
              {f.admiralty.code}
            </span>
          )}
          {(f.flags || []).map((x) => (
            <span className="rv-flag" key={x}>
              {x}
            </span>
          ))}
          <button
            type="button"
            className="rv-rid rv-rid-btn"
            title="What this rule detects, its false positives and blind spots"
            aria-expanded={openRule === f.key}
            onClick={() => setOpenRule(openRule === f.key ? '' : f.key)}
          >
            {f.rid} {openRule === f.key ? '▴' : '▾'}
          </button>
          <span className="rv-n">{fmtNum(f.cnt)} events</span>
        </div>
        <div className="rv-desc">
          {f.descr || ''} <MitreTags list={f.mitre} />
        </div>
        {openRule === f.key && <RuleCard rid={f.rid} />}
        <AiReview r={f.ai_review} state={f.ai_state} error={f.ai_error} />
        {/* Where the finding comes from (FR-4.1): the events behind it with
            their source file, and the other findings of the same attack
            chain (related.py: linked through pivot hosts, never through a
            shared final target). */}
        <div className="rv-trace">
          <button
            type="button"
            className="rv-rid rv-rid-btn"
            title="The events this finding stands for, and the file each came from"
            aria-expanded={openEvents === f.key}
            onClick={() => setOpenEvents(openEvents === f.key ? '' : f.key)}
          >
            Source events ({fmtNum(f.cnt)}) {openEvents === f.key ? '▴' : '▾'}
          </button>
          {f.related_count > 0 && (
            <span className="rv-related">
              Same attack chain ({f.related_count}):
              {f.related.map((r) => (
                relatedHref ? (
                  <a
                    className="rv-chip"
                    key={r.key}
                    href={relatedHref(r.key)}
                    title={`Open ${r.rid} ${r.srcip || r.username || ''}`}
                  >
                    {r.rid} {r.srcip || r.username}
                  </a>
                ) : (
                  <button
                    type="button"
                    className="rv-chip"
                    key={r.key}
                    title={`Go to ${r.rid} ${r.srcip || r.username || ''}`}
                    onClick={() => reveal(r.key)}
                  >
                    {r.rid} {r.srcip || r.username}
                  </button>
                )
              ))}
              {f.related_count > f.related.length && ` +${f.related_count - f.related.length} more`}
            </span>
          )}
        </div>
        {openEvents === f.key && <FindingEvents caseId={caseId} findingKey={f.key} />}
        {/* Why the level is above what the rule says on its own - an
            attack-path pattern (severity.py) - so the analyst can check
            the escalation instead of taking it on trust. */}
        {(f.escalation || []).map((e) => (
          <div className="rv-escalation" key={e.pattern}>
            Raised to {LEVEL_EN[e.level]}: {e.reason}
            {e.evidence?.length > 0 && (
              <>
                {' '}
                - {f.srcip ? `${f.srcip}: ` : ''}
                {e.evidence.map((r) => `${r.label} (${r.rid})`).join(' + ')}
              </>
            )}
          </div>
        ))}
        <div className="rv-meta">
          {f.ts_first || ''}
          {f.ts_last && f.ts_last !== f.ts_first ? ` → ${f.ts_last}` : ''}
        </div>
        {f.review.actor && (
          <div className="rv-who">
            {f.review.actor} · {shortTs(f.review.ts)}
            {f.review.reason_code ? ` · ${f.review.reason_code}` : ''}
          </div>
        )}

        {/* No status workflow or assignee here since story 1: Respond was
            removed (case_flow_design.md revision 3) and the owner of a
            decision is the signed-in account (revision 2). The lifecycle
            log stays on disk as an audit record. */}

        {rejecting === f.key ? (
          // FR-4.6: a rejection carries a structured reason, so mapping
          // quality can be measured later instead of guessed at. The API
          // returns 400 without one, so it is collected here rather than
          // discovered at submit time.
          <form
            onSubmit={(e) => {
              e.preventDefault()
              if (!reasonCode) return
              submit(f.key, 'reject', { reason_code: reasonCode, note: reasonNote })
            }}
          >
            <label htmlFor={`reason-${f.key}`}>Reason for rejecting (required)</label>
            <select
              id={`reason-${f.key}`}
              value={reasonCode}
              onChange={(e) => setReasonCode(e.target.value)}
            >
              <option value="">- choose a reason -</option>
              {Object.entries(reasonCodes).map(([code, label]) => (
                <option value={code} key={code}>
                  {label} ({code})
                </option>
              ))}
            </select>
            <textarea
              placeholder="Note (optional)"
              value={reasonNote}
              onChange={(e) => setReasonNote(e.target.value)}
            />
            <div className="rv-actions">
              <button className="rv-btn rv-reject" type="submit" disabled={!reasonCode || busy}>
                Confirm rejection
              </button>
              <button
                className="rv-btn"
                type="button"
                onClick={() => {
                  setRejecting(null)
                  setReasonCode('')
                  setReasonNote('')
                }}
              >
                Cancel
              </button>
            </div>
          </form>
        ) : (
          <div className="rv-actions" title={why('finding:review')}>
            <button
              className="rv-btn rv-accept"
              disabled={busy || !mayReview}
              onClick={() => submit(f.key, 'accept')}
            >
              Accept
            </button>
            <button
              className="rv-btn rv-modify"
              disabled={busy || !mayReview}
              onClick={() => submit(f.key, 'modify')}
            >
              Modified
            </button>
            <button
              className="rv-btn rv-reject"
              disabled={busy || !mayReview}
              onClick={() => setRejecting(f.key)}
            >
              Reject
            </button>
            {st !== 'Unreviewed' && (
              <button
                className="rv-btn rv-undo"
                disabled={busy || !mayReview}
                onClick={() => submit(f.key, 'unreview')}
              >
                Undo
              </button>
            )}
            {!mayReview && <span className="cell-sub">{why('finding:review')}</span>}
          </div>
        )}
      </div>
    )
  }
}

/** Scroll one suggestion into view - unfolding its area's section first if the
 *  analyst folded it, since a hidden card cannot be scrolled to. */
function scrollToItem(key) {
  const el = document.getElementById(`rv-${key}`)
  if (!el) return
  const body = el.closest('.ui-section-body')
  if (body?.hidden) body.parentElement.querySelector('.ui-chevron')?.click()
  requestAnimationFrame(() => el.scrollIntoView({ behavior: 'smooth', block: 'center' }))
}

const LEVEL_TONE = { critical: 'danger', high: 'warn', medium: 'info' }
const LEVEL_RANK = ['critical', 'high', 'medium', 'low', 'informational']

/** Attack events grouped as the user approved (2026-10-27): one folding
 *  section per detection area, in areas.py's order, and inside it one block per
 *  rule, in the order of the list's own sort - so the rule with undecided
 *  suggestions comes first. Each suggestion keeps its whole card (the AI's
 *  explanation and the decision buttons): a section folds, a suggestion never
 *  hides behind a click. A rule outside every area goes under "Other rules". */
function ByArea({ findings, areas, item }) {
  const order = [...areas, { id: null, name: 'Other rules', about: 'Rules that belong to no detection area' }]
  return order.map((a) => {
    const fs = findings.filter((f) => (f.area ?? null) === a.id)
    if (!fs.length) return null
    const rules = []
    for (const f of fs) {
      const r = rules.find((x) => x.rid === f.rid)
      if (r) r.items.push(f)
      else rules.push({ rid: f.rid, items: [f] })
    }
    const top = LEVEL_RANK.find((l) => fs.some((f) => f.level === l))
    const decided = fs.filter((f) => f.review.status !== 'Unreviewed').length
    const explained = fs.filter((f) => f.ai_review?.what_happened).length
    const latest = fs.map((f) => (f.ts_last || f.ts_first || '').slice(0, 10)).sort().pop()
    return (
      <Section
        key={a.id || 'other'}
        icon={a.id || 'findings'}
        tone={LEVEL_TONE[top] || 'muted'}
        title={a.name}
        sub={a.about}
        stats={[
          { label: 'Suggestions', value: fmtNum(fs.length), tone: LEVEL_TONE[top] || 'text' },
          { label: 'Decided', value: `${fmtNum(decided)} / ${fmtNum(fs.length)}` },
          { label: 'Latest', value: latest || '—' },
        ]}
        pill={<span className="ui-pill tone-info">AI explained {fmtNum(explained)} / {fmtNum(fs.length)}</span>}
      >
        <div className="rv-area-body">
          {rules.map((r) => (
            <div key={r.rid}>
              <div className="rv-rule-chip">
                <span className={`ui-badge tone-${LEVEL_TONE[LEVEL_RANK.find((l) => r.items.some((f) => f.level === l))] || 'muted'}`}>
                  {r.rid} · {r.items.length}
                </span>
              </div>
              {r.items.map(item)}
            </div>
          ))}
        </div>
      </Section>
    )
  })
}
