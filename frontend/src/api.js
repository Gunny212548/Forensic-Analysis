// Every call the UI makes. Thin on purpose: the server already collapses,
// ranks and scores everything (see app/services/db.py), so the client's job
// is to render what it is handed, never to recompute it.

/** Any 401 means the session is gone (expired, logged out in another tab,
 *  account removed). App.jsx listens for this and shows the login page. */
export const AUTH_REQUIRED = 'auth-required'

function checkSession(resp) {
  if (resp.status === 401) window.dispatchEvent(new Event(AUTH_REQUIRED))
}

async function jsonOrThrow(resp, fallback) {
  checkSession(resp)
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

export async function getLoginConfig() {
  return jsonOrThrow(await fetch('/api/auth/config'), 'โหลดหน้าเข้าสู่ระบบไม่สำเร็จ')
}

/** Returns null when nobody is signed in - the normal state on first load,
 *  so it is not reported as an error. */
export async function getMe() {
  const resp = await fetch('/api/auth/me')
  if (resp.status === 401) return null
  return jsonOrThrow(resp, 'ตรวจสอบการเข้าสู่ระบบไม่สำเร็จ')
}

// Not through jsonOrThrow: a 401 here is a wrong password, not a lost session.
export async function login(email, password) {
  const resp = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  })
  const body = await resp.json().catch(() => null)
  if (!resp.ok) throw new Error((body && body.detail) || 'Sign-in failed')
  return body
}

export async function logout() {
  await fetch('/api/auth/logout', { method: 'POST' })
}

/** Everything the Overview page shows, aggregated server-side over all cases
 *  (app/services/overview.py). */
export async function getOverview() {
  return jsonOrThrow(await fetch('/api/overview'), 'Could not load the overview')
}

export async function listCases() {
  return jsonOrThrow(await fetch('/api/cases'), 'โหลดรายการเคสไม่สำเร็จ')
}

export async function listCompanies() {
  return jsonOrThrow(await fetch('/api/companies'), 'โหลดรายชื่อบริษัทไม่สำเร็จ')
}

/** FR-6.1: case load per customer (app/services/overview.py customers()). */
export async function getCustomerSummary() {
  return jsonOrThrow(await fetch('/api/companies/summary'), 'Could not load customers')
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

/** The rule set never changes while the app runs, so it is fetched once. */
let rulesPromise = null
export function getRules() {
  if (!rulesPromise) {
    rulesPromise = fetch('/api/rules')
      .then((resp) => jsonOrThrow(resp, 'Could not load the detection rules'))
      .catch((err) => {
        rulesPromise = null // let a later open retry
        throw err
      })
  }
  return rulesPromise
}

export async function getCustody(caseId) {
  return jsonOrThrow(
    await fetch(`/api/cases/${encodeURIComponent(caseId)}/custody`),
    'Could not load the chain of custody',
  )
}

/** Re-hashes the preserved file server-side and records the check. */
export async function verifyEvidence(caseId) {
  return jsonOrThrow(
    await fetch(`/api/cases/${encodeURIComponent(caseId)}/verify`, { method: 'POST' }),
    'Could not verify the evidence',
  )
}

/** Returns null when the case has never been analysed - not an error.
 *
 *  This is also the poll point for a queued map-reduce job, and both of its
 *  in-progress answers are 2xx: 200 when an OLDER finished analysis is being
 *  returned meanwhile, 202 when nothing is cached yet and the body is only a
 *  progress stub. The HTTP code is therefore not what the caller reads -
 *  `analysis_status` ("ready" / "running" / "failed") is, and it is present on
 *  every body. See Result.jsx's readAnalysis(). */
export async function getAnalysis(caseId) {
  const resp = await fetch(`/api/cases/${encodeURIComponent(caseId)}/analysis`)
  checkSession(resp)
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
  //
  // A case too large for one call answers 202 with a progress stub instead of
  // the narrative - a 2xx, so it lands here as an ordinary body and the caller
  // must read `analysis_status` before rendering it as a report.
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

/** FR-2.2 pre-flight. With no size: the limits, for display. With a size:
 *  throws the server's reason (413 too large / 507 no disk) before a byte of
 *  the file is sent - the upload itself can only refuse after the fact. */
export async function checkUpload(size) {
  const q = size ? `?size=${encodeURIComponent(size)}` : ''
  return jsonOrThrow(await fetch(`/api/upload/check${q}`), 'Upload check failed')
}

/** XMLHttpRequest, not fetch: fetch has no upload progress, and FR-2.5 wants
 *  a percentage for the upload itself. `onProgress(fraction)` follows the
 *  bytes sent; processing progress is on the case manifest afterwards. */
export function uploadFile({ file, note, companyId, companyName, onProgress }) {
  const fd = new FormData()
  // Text fields before the file, so the server has them before the big part.
  fd.append('note', note || '')
  if (companyName) fd.append('company_name', companyName)
  else if (companyId) fd.append('company_id', companyId)
  fd.append('file', file)
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest()
    xhr.open('POST', '/api/upload')
    xhr.responseType = 'json'
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable && onProgress) onProgress(e.loaded / e.total)
    }
    xhr.onload = () => {
      const body = xhr.response
      if (xhr.status === 401) window.dispatchEvent(new Event(AUTH_REQUIRED))
      if (xhr.status >= 200 && xhr.status < 300) return resolve(body)
      const err = new Error((body && body.detail) || `Upload failed (HTTP ${xhr.status})`)
      err.status = xhr.status
      reject(err)
    }
    xhr.onerror = () => reject(new Error('Upload failed - the connection was interrupted'))
    xhr.send(fd)
  })
}
