// Static SVG attack diagram - no library, no physics, no interaction.
//
// This replaced a vis-network CDN dependency: a force simulation added
// interactivity nobody needed and read worse in a printed report, which is
// where these diagrams end up. The layout below is deliberately the same
// arithmetic the pre-React page used - it was tuned against real cases and
// the graphs get screenshotted, so changing the geometry would change
// evidence for no reason.
//
// The data is not interpretation: db.build_graph() derives every edge in SQL
// from findings joined back to raw_events, so each one traces to real row_ids
// (CLAUDE.md gotcha #10). The model is explicitly told not to draw it.

const NODE_W = 168
const NODE_H = 34
const COL_GAP = 330
const ROW_GAP = 74
const PAD_X = 12
const PAD_Y = 24

const isIp = (n) => /^\d{1,3}(\.\d{1,3}){3}$/.test(n)

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
  // not stretched across an empty gap.
  const used = cols.filter((c) => c.length)
  const tallest = Math.max(...used.map((c) => c.length))

  const pos = {}
  used.forEach((col, ci) =>
    col.forEach((n, ri) => {
      pos[n] = {
        x: PAD_X + ci * COL_GAP,
        y: PAD_Y + ri * ROW_GAP + ((tallest - col.length) * ROW_GAP) / 2,
      }
    }),
  )

  return {
    pos,
    names: [...names],
    width: PAD_X * 2 + (used.length - 1) * COL_GAP + NODE_W + 90,
    height: PAD_Y * 2 + tallest * ROW_GAP,
  }
}

export default function AttackGraph({ graph }) {
  const edges = (graph && graph.edges) || []
  if (!edges.length) return null

  const { pos, names, width, height } = layout(edges)

  // Labels sit just past the SOURCE node, not at the edge midpoint: these
  // graphs are typically many sources converging on one target, so every
  // midpoint lands in the same spot and the labels pile up on each other.
  // Anchored to the source, each row gets its own space, and multiple edges
  // leaving one source stack downward.
  const srcSeen = {}
  const drawn = []
  for (const [i, e] of edges.entries()) {
    const a = pos[e.from]
    const b = pos[e.to]
    if (!a || !b) continue
    const nth = (srcSeen[e.from] = (srcSeen[e.from] || 0) + 1) - 1
    const x1 = a.x + NODE_W
    const y1 = a.y + NODE_H / 2
    const x2 = b.x
    const y2 = b.y + NODE_H / 2
    const lx = x1 + 14
    const ly = y1 - 5 + nth * 26
    const mitre = (e.mitre || []).join(' ')
    drawn.push(
      <g key={`${e.from}->${e.to}-${i}`}>
        <path
          d={`M ${x1} ${y1} C ${x1 + 60} ${y1}, ${x2 - 60} ${y2}, ${x2} ${y2}`}
          fill="none"
          stroke="#475569"
          strokeWidth="1.4"
          markerEnd="url(#arw)"
        />
        <text x={lx} y={ly} fontSize="10.5" fill="#cbd5e1">
          {e.label || ''}
        </text>
        {mitre && (
          <text x={lx} y={ly + 11} fontSize="9.5" fill="#38bdf8">
            {mitre}
          </text>
        )}
      </g>,
    )
  }

  return (
    <div className="graph-wrap">
      <svg viewBox={`0 0 ${width} ${height}`} width={width} height={height} role="img">
        <defs>
          <marker
            id="arw"
            viewBox="0 0 10 10"
            refX="9"
            refY="5"
            markerWidth="7"
            markerHeight="7"
            orient="auto-start-reverse"
          >
            <path d="M 0 0 L 10 5 L 0 10 z" fill="#475569" />
          </marker>
        </defs>
        {drawn}
        {names.map((n) => {
          const p = pos[n]
          if (!p) return null
          return (
            <g key={n}>
              <rect
                x={p.x}
                y={p.y}
                width={NODE_W}
                height={NODE_H}
                rx="7"
                fill={isIp(n) ? '#7f1d1d' : '#155e75'}
                stroke={isIp(n) ? '#f87171' : '#38bdf8'}
                strokeWidth="1.5"
              />
              <text
                x={p.x + NODE_W / 2}
                y={p.y + NODE_H / 2 + 4.5}
                textAnchor="middle"
                fontSize="12.5"
                fontWeight="600"
                fill="#f1f5f9"
              >
                {/* Truncated for width. The old page sliced the *escaped*
                    string, which could cut an entity name mid-entity; JSX
                    escapes after this, so the cut is on real characters. */}
                {String(n).slice(0, 26)}
              </text>
            </g>
          )
        })}
      </svg>
    </div>
  )
}
