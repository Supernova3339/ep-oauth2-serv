import React, { createContext, useContext, useEffect, useState } from 'react'

interface User {
  id: string
  email: string
  name?: string
  admin?: boolean
  isAdmin?: boolean
}

interface AuthContextValue {
  user: User | null
  csrfToken: string
  loading: boolean
  easypanelUrl: string
  setUser: (user: User | null) => void
  refreshCsrf: () => Promise<string>
}

const AuthContext = createContext<AuthContextValue>({
  user: null,
  csrfToken: '',
  loading: true,
  easypanelUrl: '',
  setUser: () => {},
  refreshCsrf: async () => '',
})

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [csrfToken, setCsrfToken] = useState('')
  const [loading, setLoading] = useState(true)
  const [easypanelUrl, setEasypanelUrl] = useState('')

  const refreshCsrf = async (): Promise<string> => {
    try {
      const res = await fetch('/api/csrf')
      if (res.ok) {
        const data = await res.json()
        setCsrfToken(data.token)
        return data.token as string
      }
    } catch {
      // ignore
    }
    return ''
  }

  useEffect(() => {
    Promise.all([
      fetch('/api/me').then(r => r.ok ? r.json() : null).catch(() => null),
      fetch('/api/csrf').then(r => r.ok ? r.json() : null).catch(() => null),
    ]).then(([meData, csrfData]) => {
      if (meData?.user) setUser(meData.user)
      if (meData?.easypanelUrl) setEasypanelUrl(meData.easypanelUrl)
      if (csrfData?.token) setCsrfToken(csrfData.token)
    }).finally(() => setLoading(false))
  }, [])

  return (
    <AuthContext.Provider value={{ user, csrfToken, loading, easypanelUrl, setUser, refreshCsrf }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  return useContext(AuthContext)
}
