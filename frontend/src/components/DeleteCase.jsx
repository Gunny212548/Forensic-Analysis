import { useState } from 'react'
import { deleteCase } from '../api.js'
import { useAccess } from '../permissions.js'

/** Delete the case and its evidence for good (specs/case_delete.md): admin and
 *  manager. Inline confirmation - the case id typed back - never a browser
 *  dialog. After it, the customer's page. */
export default function DeleteCase({ manifest }) {
  const { can, why } = useAccess()
  const [open, setOpen] = useState(false)
  const [typed, setTyped] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  if (!manifest) return null
  const allowed = can('case:delete')

  const confirm = async () => {
    setBusy(true)
    setError('')
    try {
      await deleteCase(manifest.case_id)
      window.location.hash = manifest.company_id ? `#/customers/${manifest.company_id}` : '#/cases'
    } catch (err) {
      setError(err.message)
      setBusy(false)
    }
  }

  if (!open) {
    return (
      <button className="secondary danger-outline" disabled={!allowed} title={why('case:delete')}
              onClick={() => setOpen(true)}>
        Delete case
      </button>
    )
  }
  return (
    <div className="delete-case">
      <div>
        Deletes this case for good: the evidence file, its events and findings, the AI analysis, the
        review log and the chain of custody. Who deleted it and when is recorded for the customer.
      </div>
      <label>
        Type <code>{manifest.case_id}</code> to confirm
        <input value={typed} onChange={(e) => setTyped(e.target.value)} autoFocus spellCheck={false} />
      </label>
      <div className="delete-actions">
        <button className="danger" disabled={busy || typed.trim() !== manifest.case_id} onClick={confirm}>
          {busy ? 'Deleting...' : 'Delete for good'}
        </button>
        <button className="secondary" disabled={busy} onClick={() => { setOpen(false); setTyped(''); setError('') }}>
          Cancel
        </button>
      </div>
      {error && <div className="lc-error">{error}</div>}
    </div>
  )
}
