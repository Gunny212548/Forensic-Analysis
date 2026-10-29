// Static SVG attack diagram - no library, no physics, no interaction.
//
// This replaced a vis-network CDN dependency: a force simulation added
// interactivity nobody needed and read worse in a printed report, which is
// where these diagrams end up. The layout keeps the pre-React page's logic -
// columns by role, labels anchored at the source - because it was tuned
// against real cases and reads left to right as the attack went. IAI-61 gave
// it the look the user chose (2026-10-29): the Figma's column heads and
// boxed technique labels, and an attack-path style of round nodes with an
// icon for what the node is (address, host, account), its name underneath
// and callouts for what the evidence says about it (external, on a feed).
// Every colour is a theme token (styles.css .ag-*), so it reads in both themes.
//
// The data is not interpretation: db.build_graph() derives every edge in SQL
// from findings joined back to raw_events, so each one traces to real row_ids
// (CLAUDE.md gotcha #10), and a node's kind and callouts are facts of the
// evidence (db.node_facts) - never a role such as "domain controller". The
// model is explicitly told not to draw it.

const R = 24 // node circle radius
const COL_W = 160 // a column's width: the circle, its name and callouts underneath
const COL_GAP = 470
const ROW_GAP = 124
const PAD_X = 16
const HEAD_H = 44
const LABEL_H = 20
const LABEL_MAX = 46 // characters of an edge label before it is cut (the whole one is its tooltip)
const NAME_MAX = 22
const CHAR_W = 6.6 // IBM Plex Mono at 11px
const PILL_CHAR_W = 6.2 // IBM Plex Sans at 10.5px, a little generous

const ROLE = ['source', 'pivot', 'sink']
const ROLE_HEAD = ['SOURCES', 'PIVOTS (SOURCE + SINK)', 'SINKS']
const LEVELS = ['critical', 'high', 'medium', 'low']
const levelOf = (e) => (LEVELS.includes(e.level) ? e.level : 'low')
const cut = (s, n) => (s.length > n ? `${s.slice(0, n - 1)}…` : s)

// 24 x 24 stroke icons, drawn in the circle (icons.jsx's style).
const ICONS = {
  address: (
    <>
      <path d="M12 21s-6-5.6-6-11a6 6 0 1 1 12 0c0 5.4-6 11-6 11z" />
      <circle cx="12" cy="10" r="2.2" />
    </>
  ),
  host: (
    <>
      <rect x="3" y="4" width="18" height="12" rx="1.5" />
      <path d="M8 20h8M12 16v4" />
    </>
  ),
  account: (
    <>
      <circle cx="12" cy="8" r="4" />
      <path d="M4 20c0-4 3.6-6 8-6s8 2 8 6" />
    </>
  ),
}

function layout(edges) {
  const outDeg = {}
  const inDeg = {}
  const names = new Set()
  for (const e of edges) {
    names.add(e.from)
    names.add(e.to)
    outDeg[e.from] = (outDeg[e.from] || 0) + 1
    inDeg[e.to] = (inDeg[e.to] || 0) + 1
  }

  // Columns by role: pure sources left, pure sinks right, anything that both
  // receives and sends in the middle. That matches how these graphs actually
  // look - attacker IPs -> an account or service -> a destination.
  const cols = [[], [], []]
  for (const n of names) {
    if (!inDeg[n]) cols[0].push(n)
    else if (!outDeg[n]) cols[2].push(n)
    else cols[1].push(n)
  }
  // With nothing in the middle, fall back to two columns so the diagram is
  // not stretched across an empty gap. Each column keeps its role for its head.
  const used = cols.map((c, role) => ({ role, names: c })).filter((c) => c.names.length)
  const tallest = Math.max(...used.map((c) => c.names.length))

  const pos = {}
  used.forEach((col, ci) =>
    col.names.forEach((n, ri) => {
      pos[n] = {
        cx: PAD_X + COL_W / 2 + ci * COL_GAP,
        cy: HEAD_H + R + ri * ROW_GAP + ((tallest - col.names.length) * ROW_GAP) / 2,
        role: col.role,
      }
    }),
  )

  return {
    pos,
    names: [...names],
    heads: used.map((col, ci) => ({ x: PAD_X + ci * COL_GAP, text: ROLE_HEAD[col.role] })),
    width: PAD_X * 2 + (used.length - 1) * COL_GAP + COL_W,
    height: HEAD_H + tallest * ROW_GAP,
  }
}

/** The callouts under a node: what the evidence says that matters to the path. */
function callouts(node) {
  const out = []
  if (node.listed_by) out.push({ cls: 'ag-pill-feed', text: 'On threat feed', title: `listed by ${node.listed_by}` })
  if (node.external) out.push({ cls: 'ag-pill-ext', text: 'External', title: 'not in an RFC 1918 private range' })
  return out
}

export default function AttackGraph({ graph }) {
  const edges = (graph && graph.edges) || []
  if (!edges.length) return null
  const facts = Object.fromEntries(((graph && graph.nodes) || []).map((n) => [n.id, n]))

  const { pos, names, heads, width, height } = layout(edges)

  // Labels sit just past the SOURCE node, not at the edge midpoint: these
  // graphs are typically many sources converging on one target, so every
  // midpoint lands in the same spot and the labels pile up on each other.
  // Anchored to the source, each row gets its own space, and multiple edges
  // leaving one source stack downward.
  const srcSeen = {}
  const lines = []
  const labels = []
  for (const [i, e] of edges.entries()) {
    const a = pos[e.from]
    const b = pos[e.to]
    if (!a || !b) continue
    const nth = (srcSeen[e.from] = (srcSeen[e.from] || 0) + 1) - 1
    const level = levelOf(e)
    const x1 = a.cx + R + 2
    const y1 = a.cy
    const x2 = b.cx - R - 4
    const y2 = b.cy
    const bend = Math.max(60, (x2 - x1) / 2)
    const mitre = e.mitre || []
    const full = `${mitre.length ? `${mitre.join(' ')} · ` : ''}${e.label || ''}`
    const text = cut(`${mitre[0] ? `${mitre[0]} · ` : ''}${e.label || ''}`, LABEL_MAX)
    const lx = x1 + 12
    const ly = y1 - LABEL_H / 2 + nth * (LABEL_H + 6)
    const key = `${e.from}->${e.to}-${i}`
    lines.push(
      <path
        key={key}
        className={`ag-edge ag-${level}`}
        d={`M ${x1} ${y1} C ${x1 + bend} ${y1}, ${x2 - bend} ${y2}, ${x2} ${y2}`}
        markerEnd={`url(#ag-arw-${level})`}
      />,
    )
    // Drawn after every line, so no line crosses a label.
    labels.push(
      <g key={key} className={`ag-label ag-${level}`}>
        <title>{full}</title>
        <rect x={lx} y={ly} width={text.length * CHAR_W + 14} height={LABEL_H} rx="3" />
        <text x={lx + 7} y={ly + LABEL_H / 2 + 4}>
          {text}
        </text>
      </g>,
    )
  }

  return (
    <div className="graph-wrap">
      <svg viewBox={`0 0 ${width} ${height}`} width={width} height={height} role="img" className="attack-graph">
        <defs>
          {LEVELS.map((lv) => (
            <marker
              key={lv}
              id={`ag-arw-${lv}`}
              className={`ag-arrow ag-${lv}`}
              viewBox="0 0 10 10"
              refX="9"
              refY="5"
              markerWidth="7"
              markerHeight="7"
              orient="auto-start-reverse"
            >
              <path d="M 0 0 L 10 5 L 0 10 z" />
            </marker>
          ))}
        </defs>
        {heads.map((h) => (
          <text key={h.text} className="ag-head" x={h.x} y={16}>
            {h.text}
          </text>
        ))}
        {lines}
        {names.map((n) => {
          const p = pos[n]
          if (!p) return null
          const f = facts[n] || {}
          const kind = ICONS[f.kind] ? f.kind : /^\d{1,3}(\.\d{1,3}){3}$/.test(n) ? 'address' : 'host'
          const pills = callouts(f)
          const widths = pills.map((c) => c.text.length * PILL_CHAR_W + 16)
          let px = p.cx - (widths.reduce((s, w) => s + w, 0) + 4 * (pills.length - 1)) / 2
          return (
            <g key={n} className={`ag-node ag-${ROLE[p.role]}`}>
              <title>{f.about ? `${n} - ${f.about}` : n}</title>
              <circle className="ag-disc" cx={p.cx} cy={p.cy} r={R} />
              <g className="ag-icon" transform={`translate(${p.cx - 12} ${p.cy - 12})`}>
                {ICONS[kind]}
              </g>
              {/* Cut for width on real characters - JSX escapes after this, so a name is
                  never cut inside an escape (the old page sliced the escaped string). */}
              <text className="ag-name" x={p.cx} y={p.cy + R + 17}>
                {cut(String(n), NAME_MAX)}
              </text>
              {pills.map((c, k) => {
                const x = px
                px += widths[k] + 4
                return (
                  <g key={c.text} className={`ag-pill ${c.cls}`}>
                    <title>{c.title}</title>
                    <rect x={x} y={p.cy + R + 25} width={widths[k]} height="18" rx="9" />
                    <text x={x + widths[k] / 2} y={p.cy + R + 38}>
                      {c.text}
                    </text>
                  </g>
                )
              })}
            </g>
          )
        })}
        {labels}
      </svg>
    </div>
  )
}
