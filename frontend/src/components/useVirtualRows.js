import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react'

// A box taller than this is drawn this tall and its scroll position read as a
// fraction of the list - browsers stop laying out elements somewhere past 30M px,
// and a 10 GB case can hold millions of events.
const MAX_H = 8_000_000

/** A list of `total` same-height rows in a scrolling box whose scrollbar stands
 *  for every one of them from the start (the user, 2026-11-02: scroll, not load
 *  more). Only the rows in view, and `overscan` either side, are drawn; the
 *  server pages that hold them are fetched as they come into view and kept.
 *
 *  `fetchPage(offset, limit)` returns the API's answer for one page; `pick(answer)`
 *  its rows. Page 0's answer is `meta` (its total, counts, bounds). A new `resetKey`
 *  (another case, filter or view) drops every page and starts again at the top;
 *  an answer for the view before is ignored.
 *
 *  The caller draws <tr style={{height: topPad}}/>, the rows start..end-1 (rowAt(i),
 *  undefined while its page is on its way), <tr style={{height: bottomPad}}/>, and
 *  gives the first drawn row `measure` so the row height is the real one. */
export function useVirtualRows(fetchPage, pick, resetKey, { page = 200, overscan = 30, rowHeight = 36 } = {}) {
  const box = useRef(null)
  const cache = useRef(new Map()) // page index -> rows
  const pending = useRef(new Set())
  const gen = useRef(0)
  const fetchRef = useRef(fetchPage)
  fetchRef.current = fetchPage
  const pickRef = useRef(pick)
  pickRef.current = pick
  const [meta, setMeta] = useState(null)
  const [error, setError] = useState('')
  const [, setFilled] = useState(0) // bumped when a page arrives, to draw it
  const [view, setView] = useState({ top: 0, height: 600 })
  const [rowH, setRowH] = useState(rowHeight)

  const want = useCallback(
    (p) => {
      if (cache.current.has(p) || pending.current.has(p)) return
      const g = gen.current
      pending.current.add(p)
      fetchRef.current(p * page, page)
        .then((answer) => {
          if (g !== gen.current) return
          cache.current.set(p, pickRef.current(answer) || [])
          if (p === 0) setMeta(answer)
          setFilled((n) => n + 1)
        })
        .catch((err) => g === gen.current && setError(err.message))
        .finally(() => g === gen.current && pending.current.delete(p))
    },
    [page],
  )

  useEffect(() => {
    gen.current += 1
    cache.current = new Map()
    pending.current = new Set()
    setMeta(null)
    setError('')
    if (box.current) box.current.scrollTop = 0
    setView((v) => ({ ...v, top: 0 }))
    want(0)
  }, [resetKey, want])

  // Where the box is scrolled to, at most once a frame.
  const frame = useRef(0)
  const onScroll = useCallback(() => {
    if (frame.current) return
    frame.current = requestAnimationFrame(() => {
      frame.current = 0
      const b = box.current
      if (b) setView({ top: b.scrollTop, height: b.clientHeight })
    })
  }, [])
  useLayoutEffect(() => {
    const b = box.current
    if (!b) return undefined
    setView({ top: b.scrollTop, height: b.clientHeight })
    const seen = new ResizeObserver(() => setView({ top: b.scrollTop, height: b.clientHeight }))
    seen.observe(b)
    return () => seen.disconnect()
  }, [meta])
  useEffect(() => () => cancelAnimationFrame(frame.current), [])

  const total = meta ? meta.total || 0 : 0
  const range = useMemo(() => {
    const natural = total * rowH
    const H = Math.min(natural, MAX_H)
    const inView = Math.ceil(view.height / rowH) + 1
    let first
    if (natural <= MAX_H) first = Math.floor(view.top / rowH)
    else first = Math.floor((view.top / Math.max(1, H - view.height)) * Math.max(0, total - inView + 1))
    first = Math.max(0, Math.min(first, Math.max(0, total - 1)))
    const start = Math.max(0, first - overscan)
    const end = Math.min(total, first + inView + overscan)
    const topPad = natural <= MAX_H ? start * rowH : Math.max(0, view.top - (first - start) * rowH)
    const bottomPad = Math.max(0, H - topPad - (end - start) * rowH)
    return { start, end, topPad, bottomPad }
  }, [total, rowH, view, overscan])

  // Ask for every page the drawn rows fall in.
  useEffect(() => {
    if (!meta || range.end <= range.start) return
    for (let p = Math.floor(range.start / page); p <= Math.floor((range.end - 1) / page); p++) want(p)
  }, [meta, range.start, range.end, page, want])

  const rowAt = (i) => cache.current.get(Math.floor(i / page))?.[i % page]

  const measure = useCallback(
    (el) => {
      if (!el) return
      const h = el.getBoundingClientRect().height
      if (h > 0 && Math.abs(h - rowH) > 0.5) setRowH(h)
    },
    [rowH],
  )

  return { box, onScroll, meta, error, total, ...range, rowAt, measure }
}
