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
const LABEL_H = 20 // a one-line label
const LINE_H = 14 // each further line of a label
const LABEL_GAP = 6 // between labels stacked under one node
// Characters per line of a rule label, two lines at most, then cut (the whole one is its
// tooltip). One line of 34 cut most labels short in the screenshots that go into reports
// (UX audit, 2026-11-04); two lines of 38 fit the gap between columns.
const LINE_MAX = 38
const NAME_MAX = 22
const TECH_W = 7 // IBM Plex Mono 600 at 11px
const TEXT_W = 6.1 // IBM Plex Sans at 11px, a little generous
const PILL_CHAR_W = 6.3 // IBM Plex Sans 600 at 10.5px, a little generous

const ROLE = ['source', 'pivot', 'sink']
const ROLE_HEAD = ['SOURCES', 'PIVOTS (SOURCE + SINK)', 'SINKS']
const LEVELS = ['critical', 'high', 'medium', 'low']
const levelOf = (e) => (LEVELS.includes(e.level) ? e.level : 'low')
const cut = (s, n) => (s.length > n ? `${s.slice(0, n - 1)}…` : s)
// A label as at most two lines of `n` characters, broken at a space when one is near.
function wrap(s, n) {
  if (s.length <= n) return [s]
  let at = s.lastIndexOf(' ', n)
  if (at < n / 2) at = n
  return [s.slice(0, at).trimEnd(), cut(s.slice(at).trimStart(), n)]
}

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

// An edge's label height: one line, or two when its label wraps.
const labelHeight = (e) => LABEL_H + (wrap(e.label || '', LINE_MAX).length - 1) * LINE_H

function layout(edges) {
  const outDeg = {}
  const inDeg = {}
  const stack = {} // per node: the height of the labels stacked under it, gaps included
  const names = new Set()
  for (const e of edges) {
    names.add(e.from)
    names.add(e.to)
    outDeg[e.from] = (outDeg[e.from] || 0) + 1
    inDeg[e.to] = (inDeg[e.to] || 0) + 1
    stack[e.from] = (stack[e.from] || 0) + labelHeight(e) + LABEL_GAP
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
  // A node's row is as tall as the labels it stacks: one per edge leaving it, downward from its
  // centre. A fixed row let a source with many edges spill its labels over the next node's
  // (found on real data, 2026-10-29).
  // Labels start half a line above the node's centre, so the stack's bottom is that far less.
  const rowH = (n) => Math.max(ROW_GAP, R + 8 + Math.max(0, (stack[n] || 0) - LABEL_GAP - LABEL_H / 2) + 26)
  const heights = used.map((col) => col.names.reduce((s, n) => s + rowH(n), 0))
  const tallest = Math.max(...heights)

  const pos = {}
  used.forEach((col, ci) => {
    let y = HEAD_H + (tallest - heights[ci]) / 2
    col.names.forEach((n) => {
      pos[n] = { cx: PAD_X + COL_W / 2 + ci * COL_GAP, cy: y + R + 8, role: col.role }
      y += rowH(n)
    })
  })

  return {
    pos,
    names: [...names],
    heads: used.map((col, ci) => ({ x: PAD_X + ci * COL_GAP, text: ROLE_HEAD[col.role] })),
    width: PAD_X * 2 + (used.length - 1) * COL_GAP + COL_W,
    height: HEAD_H + tallest,
  }
}

/** The callout under a node - what the evidence says that matters to the path, in one bubble
 *  pointing at it: red when a feed lists the address, amber when it is only external. */
function callout(node) {
  const parts = []
  const why = []
  if (node.external) {
    parts.push('External')
    why.push('not in an RFC 1918 private range')
  }
  if (node.listed_by) {
    parts.push('On threat feed')
    why.push(`listed by ${node.listed_by}`)
  }
  if (!parts.length) return null
  return { cls: node.listed_by ? 'ag-callout-feed' : 'ag-callout-ext', text: parts.join(' · '), title: why.join('; ') }
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
  const srcBelow = {} // per source node: how far down its next label starts
  const lines = []
  const labels = []
  let bottom = 0
  for (const [i, e] of edges.entries()) {
    const a = pos[e.from]
    const b = pos[e.to]
    if (!a || !b) continue
    const level = levelOf(e)
    const x1 = a.cx + R + 2
    const y1 = a.cy
    const x2 = b.cx - R - 4
    const y2 = b.cy
    const mitre = e.mitre || []
    const full = `${mitre.length ? `${mitre.join(' ')} · ` : ''}${e.label || ''}`
    const tech = mitre[0] || ''
    const rows = wrap(e.label || '', LINE_MAX)
    const techW = tech.length * TECH_W + (tech ? 8 : 0)
    const labelW = Math.max(techW + rows[0].length * TEXT_W, rows[1] ? rows[1].length * TEXT_W : 0) + 20
    const labelH = labelHeight(e)
    // Past the node's name and callout, which are wider than its circle: a label never covers them.
    const lx = a.cx + COL_W / 2 + 8
    const ly = y1 - LABEL_H / 2 + (srcBelow[e.from] || 0)
    srcBelow[e.from] = (srcBelow[e.from] || 0) + labelH + LABEL_GAP
    bottom = Math.max(bottom, ly + labelH)
    const key = `${e.from}->${e.to}-${i}`
    // Each edge runs through its own label: from the node into the label's left end, then out of
    // its right end to the target - so a label stacked below the node still reads as its edge's.
    const my = ly + labelH / 2
    const ox = lx + labelW
    // Half the run left: a fixed minimum hooked the curve back on itself when the target was near.
    const bend = Math.max(12, (x2 - ox) / 2)
    lines.push(
      <g key={key} className={`ag-${level}`}>
        <path className={`ag-edge ag-${level}`} d={`M ${x1} ${y1} C ${x1 + 20} ${y1}, ${lx - 20} ${my}, ${lx} ${my}`} />
        <path
          className={`ag-edge ag-${level}`}
          d={`M ${ox} ${my} C ${ox + bend} ${my}, ${x2 - bend} ${y2}, ${x2} ${y2}`}
          markerEnd={`url(#ag-arw-${level})`}
        />
      </g>,
    )
    // Drawn after every line, so no line crosses a label.
    labels.push(
      <g key={key} className={`ag-label ag-${level}`}>
        <title>{full}</title>
        {/* An opaque panel under the tint: some tints are translucent, and the line runs beneath. */}
        <rect className="ag-label-bg" x={lx} y={ly} width={labelW} height={labelH} rx={LABEL_H / 2} />
        <rect x={lx} y={ly} width={labelW} height={labelH} rx={LABEL_H / 2} />
        <text x={lx + 10} y={ly + LABEL_H / 2 + 4}>
          {tech && <tspan className="ag-tech">{tech}</tspan>}
          {tech && ' '}
          <tspan>{rows[0]}</tspan>
          {rows[1] && (
            <tspan x={lx + 10} dy={LINE_H}>
              {rows[1]}
            </tspan>
          )}
        </text>
      </g>,
    )
  }

  // Labels stacked under the lowest node can reach past the last row: the picture grows to hold them.
  const h = Math.max(height, Math.ceil(bottom) + 8)
  return (
    <div className="graph-wrap">
      <svg viewBox={`0 0 ${width} ${h}`} width={width} height={h} role="img" className="attack-graph">
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
          const c = callout(f)
          const cw = c ? c.text.length * PILL_CHAR_W + 20 : 0
          const cy = p.cy + R + 30 // the bubble's top, under the name
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
              {c && (
                <g className={`ag-callout ${c.cls}`}>
                  <title>{c.title}</title>
                  {/* A rounded bubble with a tail pointing up at the node, the Microsoft attack-path
                      picture's callout. */}
                  <path
                    d={`M ${p.cx - cw / 2 + 10} ${cy} H ${p.cx - 6} L ${p.cx} ${cy - 6} L ${p.cx + 6} ${cy}
                        H ${p.cx + cw / 2 - 10} A 10 10 0 0 1 ${p.cx + cw / 2} ${cy + 10}
                        A 10 10 0 0 1 ${p.cx + cw / 2 - 10} ${cy + 20} H ${p.cx - cw / 2 + 10}
                        A 10 10 0 0 1 ${p.cx - cw / 2} ${cy + 10} A 10 10 0 0 1 ${p.cx - cw / 2 + 10} ${cy} Z`}
                  />
                  <text x={p.cx} y={cy + 14}>
                    {c.text}
                  </text>
                </g>
              )}
            </g>
          )
        })}
        {labels}
      </svg>
    </div>
  )
}
