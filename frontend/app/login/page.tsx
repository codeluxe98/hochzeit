'use client'

import { api } from '@/lib/api'
import { setToken } from '@/lib/auth'
import { useRouter } from 'next/navigation'
import { useState } from 'react'

export default function LoginPage() {
  const router = useRouter()
  const [identifier, setIdentifier] = useState('superadmin')
  const [password, setPassword] = useState('ChangeMe!1234')
  const [error, setError] = useState('')

  return (
    <main style={{ minHeight: '100vh', display: 'grid', placeItems: 'center', padding: 16 }}>
      <div className="panel" style={{ width: '100%', maxWidth: 420 }}>
        <h1>HomeOps Login</h1>
        <p style={{ color: 'var(--muted)' }}>Passkey/WebAuthn & 2FA Struktur backendseitig vorbereitet.</p>
        <div className="grid" style={{ gap: 10 }}>
          <input className="input" value={identifier} onChange={(e) => setIdentifier(e.target.value)} placeholder="E-Mail oder Benutzername" />
          <input className="input" type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Passwort" />
          {error && <div style={{ color: 'var(--bad)' }}>{error}</div>}
          <button
            className="btn btn-primary"
            onClick={async () => {
              try {
                const res = await api<{ access_token: string }>('/auth/login', {
                  method: 'POST',
                  body: JSON.stringify({ identifier, password }),
                })
                setToken(res.access_token)
                router.push('/dashboard')
              } catch (e) {
                setError('Login fehlgeschlagen')
              }
            }}
          >
            Einloggen
          </button>
        </div>
      </div>
    </main>
  )
}
