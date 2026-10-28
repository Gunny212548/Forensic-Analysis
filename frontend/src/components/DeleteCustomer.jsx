import { useEffect, useState } from 'react'
import { deleteCustomer, getCustomerDeletion } from '../api.js'
import { fmtNum } from '../format.js'

/** The confirmation of deleting a customer (specs/customer_delete.md), as a row
 *  under the customer's row on the Customers page: what goes - read from the
 *  server, not guessed from the table - the cases that block it now, and the
 *  customer's name typed back. Never a browser dialog. `colSpan` is the table's
 *  width; `onDone(deleted)` closes it. */
export default function DeleteCustomer({ companyId, colSpan, onDone }) {
  const [info, setInfo] = useState(null)
  const [typed, setTyped] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    getCustomerDeletion(companyId).then(setInfo, (err) => setError(err.message))
  }, [companyId])

  const confirm = async () => {
    setBusy(true)
    setError('')
    try {
      await deleteCustomer(companyId)
      onDone(true)
    } catch (err) {
      setError(err.message)
      setBusy(false)
    }
  }

  const n = (v, one, many) => `${fmtNum(v)} ${v === 1 ? one : many}`
  return (
    <tr className="cust-delete-row">
      <td colSpan={colSpan}>
        <div className="delete-case">
          {!info ? (
            <div className="muted">{error || 'Reading what would be deleted...'}</div>
          ) : (
            <>
              <div>
                Deletes <strong>{info.name}</strong> for good
                {info.cases ? (
                  <>
                    : {n(info.cases, 'case', 'cases')} (evidence files, events, findings, AI analyses, review
                    logs and chains of custody), {n(info.projects, 'project', 'projects')},{' '}
                    {n(info.suggestions, 'suggestion', 'suggestions')},{' '}
                    {n(info.decisions, 'analyst decision', 'analyst decisions')} and {n(info.fd_ids, 'FD id', 'FD ids')}.
                  </>
                ) : (
                  <>. It holds no case{info.projects ? `, and ${n(info.projects, 'project', 'projects')} goes with it` : ''}.</>
                )}{' '}
                Who deleted it and when{info.cases ? ", and each case's evidence digest," : ''} stay in the deletion record.
              </div>
              {info.busy.length > 0 && (
                <div className="lc-error">
                  Cannot be deleted now - wait until these are done:{' '}
                  {info.busy.map((b) => `${b.file || b.case_id} (${b.reason})`).join('; ')}
                </div>
              )}
              <label>
                <span>Type <code>{info.name}</code> to confirm</span>
                <input value={typed} onChange={(e) => setTyped(e.target.value)} autoFocus spellCheck={false} />
              </label>
              <div className="delete-actions">
                <button className="danger" disabled={busy || info.busy.length > 0 || typed.trim() !== info.name.trim()}
                        onClick={confirm}>
                  {busy ? 'Deleting...' : 'Delete customer for good'}
                </button>
                <button className="secondary" disabled={busy} onClick={() => onDone(false)}>
                  Cancel
                </button>
              </div>
              {error && <div className="lc-error">{error}</div>}
            </>
          )}
        </div>
      </td>
    </tr>
  )
}
