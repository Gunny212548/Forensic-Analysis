import { useCallback, useEffect, useMemo, useState } from 'react'
import { getAnalysis, getCase, runAnalysis } from '../api.js'
import { fmtNum, fmtTime, statusOf } from '../format.js'
import { Empty, SeverityPill } from '../components/common.jsx'
import Workspace from '../components/Workspace.jsx'
import EventsTable from '../components/EventsTable.jsx'
import ReviewPanel from '../components/ReviewPanel.jsx'
import AttackGraph from '../components/AttackGraph.jsx'
import {
  AnalysisMeta,
  ChainFlow,
  ChainStages,
  Recommendations,
  RiskTables,
  Timeline,
} from '../components/analysis.jsx'

export default function Result({ caseId }) {
  const [manifest, setManifest] = useState(null)
  const [analysis, setAnalysis] = useState(null)
  const [error, setError] = useState('')
  const [analyzing, setAnalyzing] = useState(false)
  const [analyzeError, setAnalyzeError] = useState('')
  const [tab, setTab] = useState(undefined)

  useEffect(() => {
    let alive = true
    ;(async () => {
      try {
        const m = await getCase(caseId)
        if (!alive) return
        setManifest(m)
        if (m.status === 'ready') {
          const a = await getAnalysis(caseId)
          if (alive) setAnalysis(a)
        }
      } catch (err) {
        if (alive) setError(err.message)
      }
    })()
    return () => {
      alive = false
    }
  }, [caseId])

  const analyze = useCallback(
    async (force) => {
      setAnalyzing(true)
      setAnalyzeError('')
      setTab('overview')
      try {
        setAnalysis(await runAnalysis(caseId, force))
      } catch (err) {
        // 429 is normal operation here: the model allows about one analysis a
        // minute and says how long to wait (CLAUDE.md gotcha #5). Show the
        // wait rather than a generic failure, and never auto-retry.
        const wait = err.retryAfter ? ` รออีกประมาณ ${err.retryAfter} วินาที` : ''
        setAnalyzeError(err.status === 429 ? `${err.message}${wait}` : err.message)
      } finally {
        setAnalyzing(false)
      }
    },
    [caseId],
  )

  const tabs = useMemo(() => {
    if (!manifest || manifest.status !== 'ready') return []
    const out = []

    out.push({
      key: 'overview',
      label: 'Overview',
      node: (
        <>
          <div className="meta-line" style={{ marginTop: 0 }}>
            <SeverityPill severity={manifest.severity} /> · findings{' '}
            {fmtNum(manifest.flagged_count)} / {fmtNum(manifest.total_rows)} rows
          </div>
          {analyzing && (
            <Empty style={{ paddingTop: 14 }}>กำลังวิเคราะห์ด้วย AI... (อาจใช้เวลาถึง 1 นาที)</Empty>
          )}
          {!analyzing && analyzeError && <Empty style={{ paddingTop: 14 }}>{analyzeError}</Empty>}
          {!analyzing && analysis && (
            <>
              <div className="ws-overview-summary" style={{ marginTop: 14 }}>
                {analysis.summary || ''}
              </div>
              {analysis.attack_chain?.length > 0 && (
                <div className="ws-overview-mini">
                  <ChainFlow chain={analysis.attack_chain} />
                </div>
              )}
              <AnalysisMeta meta={analysis._meta} />
            </>
          )}
          {!analyzing && !analysis && (
            <>
              <Empty style={{ paddingTop: 14 }}>ยังไม่ได้วิเคราะห์เคสนี้ด้วย AI</Empty>
              <button className="secondary" onClick={() => analyze(false)}>
                วิเคราะห์ด้วย AI
              </button>
            </>
          )}
        </>
      ),
    })

    out.push({
      key: 'events',
      label: 'Events',
      count: manifest.flagged_count,
      node: <EventsTable caseId={caseId} />,
    })

    out.push({ key: 'review', label: 'Review', node: <ReviewPanel caseId={caseId} /> })

    if (analysis) {
      out.push({
        key: 'chain',
        label: 'Attack Chain',
        count: (analysis.attack_chain || []).length,
        node: <ChainStages chain={analysis.attack_chain} />,
      })

      const edges = analysis.graph?.edges?.length || 0
      if (edges) {
        out.push({
          key: 'graph',
          label: 'Attack Graph',
          count: edges,
          node: <AttackGraph graph={analysis.graph} />,
        })
      }

      const risk = analysis.risk || {}
      const riskCount =
        (risk.sources || []).length +
        (risk.destinations || []).length +
        (risk.accounts || []).length
      if (riskCount) {
        out.push({
          key: 'risk',
          label: 'Risk Ranking',
          count: riskCount,
          node: <RiskTables risk={risk} />,
        })
      }

      if (analysis.timeline?.length) {
        out.push({
          key: 'timeline',
          label: 'Timeline',
          count: analysis.timeline.length,
          node: <Timeline items={analysis.timeline} />,
        })
      }

      if (analysis.recommendations?.length) {
        out.push({
          key: 'recs',
          label: 'Recommendations',
          count: analysis.recommendations.length,
          node: <Recommendations items={analysis.recommendations} />,
        })
      }
    }

    return out
  }, [manifest, analysis, analyzing, analyzeError, caseId, analyze])

  const [statusLabel] = statusOf(manifest?.status)

  return (
    <section className="page">
      <div className="top-bar">
        <div>
          <a href="#/dashboard" className="back-link">
            &larr; กลับไป Dashboard
          </a>
          <h1>{manifest ? manifest.original_filename : caseId}</h1>
          <div className="subtitle">
            {manifest && (
              <>
                <code>{manifest.case_id}</code> · อัปโหลดเมื่อ {fmtTime(manifest.uploaded_at)} ·
                สถานะ: {statusLabel}
                {manifest.company_name ? ` · บริษัท: ${manifest.company_name}` : ''}
                {manifest.note ? ` · ${manifest.note}` : ''}
              </>
            )}
          </div>
        </div>
        {manifest?.status === 'ready' && (
          <button className="secondary" disabled={analyzing} onClick={() => analyze(true)}>
            วิเคราะห์ใหม่
          </button>
        )}
      </div>

      <div className="panel">
        {error && <Empty>โหลดไม่สำเร็จ: {error}</Empty>}
        {!error && !manifest && <Empty>กำลังโหลด...</Empty>}
        {!error && manifest && manifest.status === 'failed' && (
          <Empty>เคสนี้ประมวลผลล้มเหลว: {manifest.error || 'ไม่ทราบสาเหตุ'}</Empty>
        )}
        {!error && manifest && !['ready', 'failed'].includes(manifest.status) && (
          <Empty>เคสนี้ยังไม่พร้อม รอการประมวลผลให้เสร็จก่อน</Empty>
        )}
        {!error && manifest?.status === 'ready' && tabs.length > 0 && (
          <Workspace tabs={tabs} activeKey={tab} onChange={setTab} />
        )}
      </div>
    </section>
  )
}
