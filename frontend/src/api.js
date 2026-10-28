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
  return jsonOrThrow(await fetch('/api/auth/config'), 'Could not load the sign-in page')
}

/** Returns null when nobody is signed in - the normal state on first load,
 *  so it is not reported as an error. */
export async function getMe() {
  const resp = await fetch('/api/auth/me')
  if (resp.status === 401) return null
  return jsonOrThrow(resp, 'Could not check the sign-in')
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
/** All customers, or one customer's store when `companyId` is given - and one
 *  project of it with `projectId` (specs/projects.md P2). */
export async function getOverview(companyId, projectId) {
  const p = new URLSearchParams()
  if (companyId) p.set('company_id', companyId)
  if (companyId && projectId) p.set('project_id', projectId)
  const q = p.toString() ? `?${p}` : ''
  return jsonOrThrow(await fetch(`/api/overview${q}`), 'Could not load the overview')
}

export async function listCases(companyId) {
  const q = companyId ? `?company_id=${encodeURIComponent(companyId)}` : ''
  return jsonOrThrow(await fetch(`/api/cases${q}`), 'Could not load the case list')
}

export async function listCompanies() {
  return jsonOrThrow(await fetch('/api/companies'), 'Could not load the customer list')
}

/** One customer's projects with their status and what their cases hold
 *  (projects.py), Open first, then the newest. */
export async function listProjects(companyId) {
  return jsonOrThrow(
    await fetch(`/api/companies/${encodeURIComponent(companyId)}/projects`),
    'Could not load the project list',
  )
}

/** Close or reopen a project (`action` 'close' | 'reopen'; manager, admin). */
export async function changeProject(companyId, projectId, action) {
  return jsonOrThrow(
    await fetch(`/api/companies/${encodeURIComponent(companyId)}/projects/${encodeURIComponent(projectId)}/${action}`,
                { method: 'POST' }),
    `Could not ${action} the project`,
  )
}

/** FR-6.1: case load per customer (app/services/overview.py customers()). */
export async function getCustomerSummary() {
  return jsonOrThrow(await fetch('/api/companies/summary'), 'Could not load customers')
}

export async function getCase(caseId) {
  return jsonOrThrow(await fetch(`/api/cases/${encodeURIComponent(caseId)}`), 'Case not found')
}

/** A behaviour profile (profiles.py): layer C facts. kind is "source" (an
 *  address) or "account". */
export async function getProfile(caseId, kind, value) {
  return jsonOrThrow(
    await fetch(
      `/api/cases/${encodeURIComponent(caseId)}/profiles/${kind}/${encodeURIComponent(value)}`,
    ),
    'Could not load the profile',
  )
}

export async function getEvents(caseId, { limit, offset, flagged = true, order = 'row' }) {
  const q = new URLSearchParams({ limit, offset, only_flagged: flagged, order })
  return jsonOrThrow(
    await fetch(`/api/cases/${encodeURIComponent(caseId)}/events?${q}`),
    'Could not load events',
  )
}

/** The case's six steps and where it stands on each (case_flow.py). */
export async function getFlow(caseId) {
  return jsonOrThrow(await fetch(`/api/cases/${encodeURIComponent(caseId)}/flow`), 'Could not load the case steps')
}

/** Attack graph and risk ranking from the findings in SQL - no AI needed. */
export async function getGraph(caseId) {
  return jsonOrThrow(await fetch(`/api/cases/${encodeURIComponent(caseId)}/graph`), 'Could not load the attack graph')
}

export async function getFindings(caseId) {
  return jsonOrThrow(
    await fetch(`/api/cases/${encodeURIComponent(caseId)}/findings`),
    'Could not load findings',
  )
}

/** The events behind one finding, each with the file it came from (FR-4.1). */
export async function getFindingEvents(caseId, key, { limit = 25, offset = 0 } = {}) {
  const q = new URLSearchParams({ key, limit, offset })
  return jsonOrThrow(
    await fetch(`/api/cases/${encodeURIComponent(caseId)}/findings/events?${q}`),
    'Could not load the events behind this finding',
  )
}

/** Every finding in the status workflow, across cases (FR-4.4). `open_count`
 *  is what the Findings menu badge shows. */
export async function listFindings({ companyId, projectId, decision, severity, area, q, limit = 50, offset = 0 } = {}) {
  const p = new URLSearchParams({ limit, offset })
  if (companyId) p.set('company_id', companyId)
  if (companyId && projectId) p.set('project_id', projectId)
  if (decision) p.set('decision', decision)
  if (severity) p.set('severity', severity)
  if (area) p.set('area', area)
  if (q) p.set('q', q)
  return jsonOrThrow(await fetch(`/api/findings?${p}`), 'Could not load findings')
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

/** The case's VERIS record, or null when it has no high/critical finding
 *  (the server answers 409 then - nothing to classify, not an error). */
export async function getVeris(caseId) {
  const resp = await fetch(`/api/cases/${encodeURIComponent(caseId)}/veris`)
  if (resp.status === 409) return null
  return jsonOrThrow(resp, 'Could not load the VERIS classification')
}

export async function getCustody(caseId) {
  return jsonOrThrow(
    await fetch(`/api/cases/${encodeURIComponent(caseId)}/custody`),
    'Could not load the chain of custody',
  )
}

/** Re-hashes the preserved file server-side and records the check. */
/** The Ingest step's own facts (story 3): question, provenance per evidence
 *  item, time settings applied, duplicates, reproducibility record, warnings. */
export async function getIngest(caseId) {
  return jsonOrThrow(await fetch(`/api/cases/${encodeURIComponent(caseId)}/ingest`), 'Could not load the ingest record')
}

async function putJson(url, body, fallback) {
  const resp = await fetch(url, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  return jsonOrThrow(resp, fallback)
}

/** The question of the investigation the case belongs to (its project's, or
 *  its own without one). Only the fields sent change. */
export async function putQuestion(caseId, body) {
  return putJson(`/api/cases/${encodeURIComponent(caseId)}/question`, body, 'Could not save the question')
}

/** Send the suggestions that have no AI advice yet to the model again (triage.py, C-D4). */
export async function aiReviewAgain(caseId) {
  const resp = await fetch(`/api/cases/${encodeURIComponent(caseId)}/ai-review`, { method: 'POST' })
  return jsonOrThrow(resp, 'Could not start the AI review again')
}

export async function reprocessCase(caseId, reason) {
  const resp = await fetch(`/api/cases/${encodeURIComponent(caseId)}/reprocess`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ reason }),
  })
  return jsonOrThrow(resp, 'Could not re-process the case')
}

/** Delete the case and its evidence for good (admin, manager). */
export async function deleteCase(caseId) {
  return jsonOrThrow(
    await fetch(`/api/cases/${encodeURIComponent(caseId)}`, { method: 'DELETE' }),
    'Could not delete the case',
  )
}

/** What deleting the customer would remove, and the cases that block it now. */
export async function getCustomerDeletion(companyId) {
  return jsonOrThrow(
    await fetch(`/api/companies/${encodeURIComponent(companyId)}/deletion`),
    'Could not read what the deletion would remove',
  )
}

/** Delete the customer with every case it holds, for good (admin, manager). */
export async function deleteCustomer(companyId) {
  return jsonOrThrow(
    await fetch(`/api/companies/${encodeURIComponent(companyId)}`, { method: 'DELETE' }),
    'Could not delete the customer',
  )
}

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
 *  every body. See CaseFlow.jsx's readAnalysis(). */
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
  return jsonOrThrow(resp, 'Analysis failed')
}

export async function postReview(caseId, body) {
  const resp = await fetch(`/api/cases/${encodeURIComponent(caseId)}/review`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  return jsonOrThrow(resp, 'Could not save the review decision')
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
export function uploadFile({ file, note, companyId, companyName, projectId, projectName, onProgress }) {
  const fd = new FormData()
  // Text fields before the file, so the server has them before the big part.
  fd.append('note', note || '')
  if (companyName) fd.append('company_name', companyName)
  else if (companyId) fd.append('company_id', companyId)
  if (projectName) fd.append('project_name', projectName)
  else if (projectId) fd.append('project_id', projectId)
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

// --- Accounts (IAI-14): the Users page, admin only ---------------------------

async function sendJson(url, method, body, fallback) {
  const resp = await fetch(url, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  return jsonOrThrow(resp, fallback)
}

export async function listUsers() {
  return jsonOrThrow(await fetch('/api/users'), 'Could not load the accounts')
}

export async function createUser(body) {
  return sendJson('/api/users', 'POST', body, 'Could not create the account')
}

export async function updateUser(email, body) {
  return sendJson(`/api/users/${encodeURIComponent(email)}`, 'PATCH', body, 'Could not change the account')
}

export async function resetUserPassword(email, password) {
  return sendJson(`/api/users/${encodeURIComponent(email)}/password`, 'POST', { password }, 'Could not reset the password')
}

export async function removeUser(email) {
  return sendJson(`/api/users/${encodeURIComponent(email)}`, 'DELETE', undefined, 'Could not remove the account')
}

export async function getAccountAudit() {
  return jsonOrThrow(await fetch('/api/users/audit'), 'Could not load the account history')
}
