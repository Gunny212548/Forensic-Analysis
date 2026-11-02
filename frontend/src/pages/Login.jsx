import { useEffect, useState } from 'react'
import { getLoginConfig, login } from '../api.js'

/** FR-1, laid out as figma-export/login.svg: email + password, a way to reach
 *  IT, and the internal-use notice. Accounts are made by an administrator
 *  (tools/create_user.py), so there is deliberately no sign-up or
 *  self-service reset here - the IT link is the path for anyone locked out. */
// Why a Google sign-in came back refused. The server sends only one of these
// codes (services/google_login.py REASONS) and the page words it - nothing
// from Google or from the address bar is shown as typed.
const GOOGLE_REFUSED = {
  cancelled: 'Google sign-in was cancelled',
  expired: 'The Google sign-in expired or was started in another tab - try again',
  domain: "That Google account is not in a domain allowed to use this tool",
  unverified: 'Google has not verified that email address',
  disabled: 'This account is disabled - ask an administrator',
  google_mismatch: 'This email address now belongs to a different Google account - ask an administrator',
  bad_token: 'Google sign-in could not be verified - try again',
  unreachable: 'Google could not be reached - try again, or sign in with your password',
  failed: 'Google sign-in failed - try again, or sign in with your password',
  off: 'Sign in with Google is not set up on this server',
}

/** Sign in with Google (specs/google_login.md): a plain link - the server runs
 *  the whole OpenID Connect exchange, so nothing is loaded from Google here. */
function GoogleButton() {
  return (
    <a className="login-google" href="/api/auth/google/start">
      <svg width="18" height="18" viewBox="0 0 48 48" aria-hidden="true">
        <path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z" />
        <path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z" />
        <path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z" />
        <path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z" />
      </svg>
      Sign in with Google
    </a>
  )
}

export default function Login({ onLogin }) {
  const [error, setError] = useState(() => {
    const code = new URLSearchParams(window.location.search).get('signin')
    return code ? GOOGLE_REFUSED[code] || GOOGLE_REFUSED.failed : ''
  })
  const [busy, setBusy] = useState(false)
  const [itUrl, setItUrl] = useState('')
  const [google, setGoogle] = useState(false)

  useEffect(() => {
    // Said once; a reload of the page should not say it again.
    if (window.location.search) window.history.replaceState(null, '', '/' + window.location.hash)
    getLoginConfig()
      .then((c) => {
        setItUrl(c.it_contact_url || '')
        setGoogle(!!c.google)
      })
      .catch(() => {})
  }, [])

  // Read from the form, not from React state: Chrome autofill fills the
  // fields without firing input events, so state-driven values stayed empty
  // and the button sat disabled beside two filled-in fields.
  async function submit(e) {
    e.preventDefault()
    const form = e.currentTarget
    const email = form.elements.email.value.trim()
    const password = form.elements.password.value
    if (!email || !password) {
      setError('Enter your account ID and password')
      return
    }
    setBusy(true)
    setError('')
    try {
      onLogin(await login(email, password))
    } catch (err) {
      setError(err.message)
      form.elements.password.value = ''
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="login-page">
      <div className="login-col">
        <div className="login-brand">SENTRY-IR</div>
        <div className="login-brand-sub">Internal Finding Response Console</div>
        <h1>Sign in to your account</h1>
        <div className="subtitle">Enter your credentials to access the console</div>

        <form onSubmit={submit}>
          <label htmlFor="login-email">Account ID</label>
          <input
            id="login-email"
            name="email"
            type="email"
            autoComplete="username"
            autoFocus
            placeholder="name@company.com"
          />
          <label htmlFor="login-password">Password</label>
          <input
            id="login-password"
            name="password"
            type="password"
            autoComplete="current-password"
          />
          <button type="submit" disabled={busy}>
            {busy ? 'Signing in...' : 'Sign in'}
          </button>
          {google && (
            <>
              <div className="login-or">or</div>
              <GoogleButton />
            </>
          )}
          <div className="status-line err" role="alert">{error}</div>
        </form>

        <div className="login-help">
          Trouble signing in?
          {itUrl ? <a href={itUrl}>Contact IT Support</a> : ' Contact IT Support.'}
        </div>
      </div>

      <div className="login-notice">Internal tool — unauthorized access is prohibited</div>
    </div>
  )
}
