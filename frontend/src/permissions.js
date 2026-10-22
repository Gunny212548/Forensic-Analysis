import { createContext, useContext } from 'react'

/** The signed-in account and what its role may do (IAI-14,
 *  app/services/authz.py). The server decides every action; the page only
 *  reflects it - a control the role may not use is shown disabled with the
 *  role it needs, never hidden (no hidden state, the keep-UX-simple rule). */
export const UserContext = createContext(null)

export const ROLE_NAMES = { admin: 'Admin', manager: 'Manager', analyst: 'Analyst' }

export function useAccess() {
  const user = useContext(UserContext)
  const perms = new Set(user?.permissions || [])
  const can = (action) => perms.has(action)
  /** Why a control is disabled for this role, or '' when it is not. */
  const why = (action) => {
    if (can(action)) return ''
    const roles = (user?.needs?.[action] || []).map((r) => ROLE_NAMES[r] || r)
    return `Needs the ${roles.join(' or ') || 'another'} role - you are ${ROLE_NAMES[user?.role] || 'without a role'}`
  }
  return { user, can, why }
}
