'use client'

import { listUsers } from '@/services/users'
import { User } from '@/types'
import { useEffect, useState } from 'react'

export default function UsersPage() {
  const [users, setUsers] = useState<User[]>([])
  useEffect(() => { listUsers().then(setUsers).catch(console.error) }, [])

  return (
    <div className="panel">
      <h3>Benutzerverwaltung</h3>
      <table className="table"><thead><tr><th>Username</th><th>E-Mail</th><th>Rolle</th><th>Aktiv</th></tr></thead><tbody>
        {users.map((u) => <tr key={u.id}><td>{u.username}</td><td>{u.email}</td><td>{u.role}</td><td>{u.is_active ? 'Ja' : 'Nein'}</td></tr>)}
      </tbody></table>
    </div>
  )
}
