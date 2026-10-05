import { useEffect, useState } from 'react'
import { getLoginConfig, login } from '../api.js'

/** FR-1, laid out as figma-export/login.svg: email + password, a way to reach
 *  IT, and the internal-use notice. Accounts are made by an administrator
 *  (tools/create_user.py), so there is deliberately no sign-up or
 *  self-service reset here - the IT link is the path for anyone locked out. */
export default function Login({ onLogin }) {
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [itUrl, setItUrl] = useState('')

  useEffect(() => {
    getLoginConfig()
      .then((c) => setItUrl(c.it_contact_url || ''))
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
