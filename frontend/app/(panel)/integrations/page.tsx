'use client'

import { listIntegrations } from '@/services/integrations'
import { useEffect, useState } from 'react'

export default function IntegrationsPage() {
  const [integrations, setIntegrations] = useState<any[]>([])
  useEffect(() => { listIntegrations().then(setIntegrations).catch(console.error) }, [])

  return (
    <div className="panel">
      <h3>Integrationen (Adapter-Basis)</h3>
      <table className="table"><thead><tr><th>Key</th><th>Name</th><th>Aktiv</th></tr></thead><tbody>
        {integrations.map((i) => <tr key={i.id}><td>{i.key}</td><td>{i.name}</td><td>{i.enabled ? 'Ja' : 'Nein'}</td></tr>)}
      </tbody></table>
    </div>
  )
}
