'use client'

import { clearToken, getToken } from '@/lib/auth'
import { useRouter } from 'next/navigation'

export function Topbar() {
  const router = useRouter()
  return (
    <div className="topbar">
      <div>
        <h1 style={{ margin: 0, fontSize: 24 }}>Operations Panel</h1>
        <small style={{ color: 'var(--muted)' }}>Zentrale Verwaltung & Monitoring</small>
      </div>
      <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
        <span style={{ color: 'var(--muted)' }}>{getToken() ? 'Angemeldet' : 'Gast'}</span>
        <button
          className="btn"
          onClick={() => {
            clearToken()
            router.push('/login')
          }}
        >
          Logout
        </button>
      </div>
    </div>
  )
}
