'use client'

import { listAuditLogs } from '@/services/audit'
import { AuditLog } from '@/types'
import { useEffect, useState } from 'react'

export default function AuditPage() {
  const [logs, setLogs] = useState<AuditLog[]>([])
  useEffect(() => { listAuditLogs().then(setLogs).catch(console.error) }, [])

  return (
    <div className="panel">
      <h3>Audit-Logs</h3>
      <table className="table"><thead><tr><th>Zeit</th><th>Aktion</th><th>Ziel</th><th>Status</th></tr></thead><tbody>
        {logs.map((l) => <tr key={l.id}><td>{new Date(l.created_at).toLocaleString()}</td><td>{l.action}</td><td>{l.target_type}:{l.target_id}</td><td>{l.status}</td></tr>)}
      </tbody></table>
    </div>
  )
}
