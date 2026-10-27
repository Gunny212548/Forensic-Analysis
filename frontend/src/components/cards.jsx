import { useId, useState } from 'react'
import Icon from './icons.jsx'

/** The building blocks of the SOCRadar layout the user approved (2026-10-27,
 *  CLAUDE.md "The SOCRadar layout"). Layout only: every figure is handed in by
 *  the page, which knows where it came from. A `tone` is one of danger, warn,
 *  info, ok, accent or muted, and colours the icon tile, number and bar. */

/** A tinted square holding an icon. */
export function IconTile({ icon, tone = 'muted', size = 'md' }) {
  return (
    <span className={`ui-icon-tile ui-icon-${size} tone-${tone}`} aria-hidden="true">
      <Icon name={icon} />
    </span>
  )
}

export function Badge({ tone = 'muted', children, title }) {
  return <span className={`ui-badge tone-${tone}`} title={title}>{children}</span>
}

/** The summary at the top of a page: the main column (facts, a chart) and,
 *  on the right, the one number the page is about. */
export function SummaryCard({ children, side, label }) {
  return (
    <section className="ui-summary" aria-label={label}>
      <div className="ui-summary-main">{children}</div>
      {side && <div className="ui-summary-side">{side}</div>}
    </section>
  )
}

/** Small labelled facts in a row of tiles: [{label, value, title}]. */
export function FactTiles({ facts }) {
  return (
    <dl className="ui-facts">
      {facts.map((f) => (
        <div className="ui-fact" key={f.label} title={f.title}>
          <dt>{f.label}</dt>
          <dd>{f.value}</dd>
        </div>
      ))}
    </dl>
  )
}

/** The big number of a summary card; `children` are the rows under it. */
export function BigTotal({ icon, tone = 'muted', label, value, badge, children }) {
  return (
    <div className="ui-total">
      {icon && <IconTile icon={icon} tone={tone} size="lg" />}
      <div className="ui-total-label">{label}</div>
      <div className="ui-total-value">{value}</div>
      {badge}
      {children && <div className="ui-total-rows">{children}</div>}
    </div>
  )
}

/** One row under a BigTotal: a name and its value. */
export function TotalRow({ label, children, title }) {
  return (
    <div className="ui-total-row" title={title}>
      <span>{label}</span>
      <span className="mono">{children}</span>
    </div>
  )
}

/** A card that opens a list: icon, number, name, its share of the whole and a
 *  line under it. `extra` sits top right (a trend line). `dim` greys a card
 *  with nothing in it, so the ones that need work stand out. */
export function AreaCard({ href, icon, tone = 'muted', value, name, share, foot, extra, dim, title }) {
  return (
    <a className={`ui-area tone-${tone}${dim ? ' ui-dim' : ''}`} href={href} title={title}>
      <div className="ui-area-top">
        <IconTile icon={icon} tone={tone} />
        {extra}
      </div>
      <div className="ui-area-value">{value}</div>
      <div className="ui-area-name">{name}</div>
      {share != null && (
        <div className="ui-share" aria-hidden="true">
          <span style={{ width: `${Math.max(0, Math.min(100, share))}%` }} />
        </div>
      )}
      {foot && <div className="ui-area-foot">{foot}</div>}
    </a>
  )
}

/** A KPI on its own: icon tile, number, label. */
export function StatTile({ icon, tone = 'muted', value, label, title }) {
  return (
    <div className="ui-stat" title={title}>
      <IconTile icon={icon} tone={tone} />
      <div>
        <div className="ui-stat-value">{value}</div>
        <div className="ui-stat-label">{label}</div>
      </div>
    </div>
  )
}

/** A panel whose body folds away. The head always shows what is inside -
 *  its counts (`stats`: [{label, value, tone}]) and a status `pill` - so a
 *  folded section still says how much it holds. Open unless told otherwise;
 *  nothing folds by itself. */
export function Section({ icon, tone = 'muted', title, sub, stats = [], pill, defaultOpen = true, children }) {
  const [open, setOpen] = useState(defaultOpen)
  const bodyId = useId()
  return (
    <section className="ui-section">
      <div className="ui-section-head">
        {icon && <IconTile icon={icon} tone={tone} />}
        <div className="ui-section-title">
          <h2>{title}</h2>
          {sub && <div className="ui-section-sub">{sub}</div>}
        </div>
        {stats.map((s) => (
          <div className={`ui-mini tone-${s.tone || 'text'}`} key={s.label} title={s.title}>
            <div className="ui-mini-label">{s.label}</div>
            <div className="ui-mini-value">{s.value}</div>
          </div>
        ))}
        {pill}
        <button type="button" className="ui-chevron" aria-expanded={open} aria-controls={bodyId}
                aria-label={`${open ? 'Collapse' : 'Expand'} ${title}`} onClick={() => setOpen(!open)}>
          <Icon name={open ? 'chevron-up' : 'chevron-down'} />
        </button>
      </div>
      <div id={bodyId} className="ui-section-body" hidden={!open}>
        {children}
      </div>
    </section>
  )
}
