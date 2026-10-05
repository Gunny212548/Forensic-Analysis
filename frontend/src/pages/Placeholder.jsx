/** Stand-in for a menu page whose story has not been built yet, so the
 *  sidebar can show the full planned menu (FR-0.1) without dead links. */
export default function Placeholder({ title }) {
  return (
    <div className="panel">
      <h1>{title}</h1>
      <div className="empty">หน้านี้ยังไม่พร้อมใช้งาน</div>
    </div>
  )
}
