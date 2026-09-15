// Every call the UI makes. Thin on purpose: the server already collapses,
// ranks and scores everything (see app/services/db.py), so the client's job
// is to render what it is handed, never to recompute it.

async function jsonOrThrow(resp, fallback) {
  let body = null
  try {
    body = await resp.json()
  } catch {
    // fall through - an empty or non-JSON body is still a failure to report
  }
  if (!resp.ok) {
    const err = new Error((body && body.detail) || fallback || `HTTP ${resp.status}`)
    err.status = resp.status
    err.retryAfter = resp.headers.get('Retry-After')
    throw err
  }
  return body
}

export async function listCases() {
  return jsonOrThrow(await fetch('/api/cases'), 'โหลดรายการเคสไม่สำเร็จ')
}

export async function listCompanies() {
  return jsonOrThrow(await fetch('/api/companies'), 'โหลดรายชื่อบริษัทไม่สำเร็จ')
}

export async function getCase(caseId) {
  return jsonOrThrow(await fetch(`/api/cases/${encodeURIComponent(caseId)}`), 'ไม่พบเคสนี้')
}

export async function getEvents(caseId, { limit, offset }) {
  const q = new URLSearchParams({ limit, offset })
  return jsonOrThrow(
    await fetch(`/api/cases/${encodeURIComponent(caseId)}/events?${q}`),
    'โหลด events ไม่สำเร็จ',
  )
}

export async function getFindings(caseId) {
  return jsonOrThrow(
    await fetch(`/api/cases/${encodeURIComponent(caseId)}/findings`),
    'โหลด findings ไม่สำเร็จ',
  )
}

/** Returns null when the case has never been analysed - not an error. */
export async function getAnalysis(caseId) {
  const resp = await fetch(`/api/cases/${encodeURIComponent(caseId)}/analysis`)
  if (resp.status === 404) return null
  if (!resp.ok) return null
  return resp.json()
}

export async function runAnalysis(caseId, force) {
  const resp = await fetch(
    `/api/cases/${encodeURIComponent(caseId)}/analyze${force ? '?force=true' : ''}`,
    { method: 'POST' },
  )
  // The model allows roughly one analysis a minute (CLAUDE.md gotcha #5), so
  // a 429 here is normal operation and carries Retry-After. Surface the wait
  // instead of a generic failure, and never retry in a loop.
  return jsonOrThrow(resp, 'วิเคราะห์ไม่สำเร็จ')
}

export async function postReview(caseId, body) {
  const resp = await fetch(`/api/cases/${encodeURIComponent(caseId)}/review`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  return jsonOrThrow(resp, 'บันทึกผลการตรวจสอบไม่สำเร็จ')
}

export async function uploadFile({ file, note, companyId, companyName }) {
  const fd = new FormData()
  fd.append('file', file)
  fd.append('note', note || '')
  if (companyName) fd.append('company_name', companyName)
  else if (companyId) fd.append('company_id', companyId)
  return jsonOrThrow(await fetch('/api/upload', { method: 'POST', body: fd }), 'อัปโหลดล้มเหลว')
}
