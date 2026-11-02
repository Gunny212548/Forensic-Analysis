import { useEffect } from 'react'

/** Calls `loadMore` when the element `end` (the last thing in a scrolling box)
 *  comes within `margin` px of the bottom of `box` - and again at once while the
 *  box is not yet full, so a short first page keeps loading until it is or until
 *  `loadMore` has nothing left to fetch (it decides that, and must not run twice
 *  at a time). Used by the events table and a finding's source events: a box
 *  that scrolls needs no Next button (the user, 2026-11-02).
 *
 *  `loadMore` is a dependency: give it a new identity whenever what it would
 *  fetch changes, so the watcher is set again after each page is in. */
export function useLoadOnScroll(box, end, loadMore, margin = 600) {
  useEffect(() => {
    if (!box.current || !end.current) return undefined
    const seen = new IntersectionObserver((entries) => entries[0].isIntersecting && loadMore(), {
      root: box.current,
      rootMargin: `0px 0px ${margin}px 0px`,
    })
    seen.observe(end.current)
    return () => seen.disconnect()
  }, [box, end, loadMore, margin])
}
