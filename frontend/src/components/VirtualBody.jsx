/** The drawn slice of a virtual list (useVirtualRows): a spacer for the rows above,
 *  the rows in view - a "Loading..." line where a page is still on its way - and a
 *  spacer for the rows below. `row(e, i, ref)` draws one row; `ref` measures it. */
export default function VirtualBody({ v, cols, row }) {
  const out = []
  for (let i = v.start; i < v.end; i++) {
    const e = v.rowAt(i)
    out.push(
      e ? (
        row(e, i, i === v.start ? v.measure : undefined)
      ) : (
        <tr key={i} className="vwait">
          <td colSpan={cols}>Loading...</td>
        </tr>
      ),
    )
  }
  return (
    <tbody>
      {v.topPad > 0 && (
        <tr className="vpad" style={{ height: v.topPad }}>
          <td colSpan={cols} />
        </tr>
      )}
      {out}
      {v.bottomPad > 0 && (
        <tr className="vpad" style={{ height: v.bottomPad }}>
          <td colSpan={cols} />
        </tr>
      )}
    </tbody>
  )
}
