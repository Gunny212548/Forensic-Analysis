import { useEffect, useState } from 'react'

/** Sidebar-tab shell for the Result page, so a case reads as a workspace
 *  rather than one very long scroll.
 *
 *  Tabs are {key, label, count?, node}. The active tab is state here, but
 *  `activeKey` lets the parent drive it - running an analysis jumps back to
 *  Overview, which is where its result appears. */
export default function Workspace({ tabs, activeKey, onChange }) {
  const [internal, setInternal] = useState(tabs[0]?.key)
  const active = activeKey ?? internal

  // If the active tab disappears (an analysis is re-run and the tab set
  // changes), fall back to the first one instead of rendering nothing.
  useEffect(() => {
    if (!tabs.some((t) => t.key === active)) setInternal(tabs[0]?.key)
  }, [tabs, active])

  function select(key) {
    setInternal(key)
    onChange?.(key)
  }

  return (
    <div className="ws">
      <div className="ws-nav">
        {tabs.map((t) => (
          <button
            key={t.key}
            className={t.key === active ? 'active' : ''}
            onClick={() => select(t.key)}
          >
            {t.label}
            {t.count !== undefined && <span className="ws-count">{t.count}</span>}
          </button>
        ))}
      </div>
      <div className="ws-content">
        {tabs.map((t) => (
          // Rendered and hidden rather than unmounted: the Events tab holds
          // a page offset and the Review tab its loaded findings, and
          // flipping tabs should not throw either away and refetch.
          <div className="ws-section" key={t.key} hidden={t.key !== active}>
            {t.node}
          </div>
        ))}
      </div>
    </div>
  )
}
