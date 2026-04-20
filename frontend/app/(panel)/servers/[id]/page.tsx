'use client'

import { getMetrics, getServer } from '@/services/servers'
import { useParams } from 'next/navigation'
import { useEffect, useState } from 'react'

export default function ServerDetailPage() {
  const params = useParams<{ id: string }>()
  const [server, setServer] = useState<any>(null)
  const [metrics, setMetrics] = useState<any[]>([])

  useEffect(() => {
    const id = Number(params.id)
    getServer(id).then(setServer)
    getMetrics(id).then(setMetrics)
  }, [params.id])

  return (
    <div className="grid grid-2">
      <section className="panel">
        <h3>{server?.name}</h3>
        <p>Host: {server?.host}</p>
        <p>Typ: {server?.host_type}</p>
        <p>Standort: {server?.location}</p>
        <p>Status: <span className={`badge ${server?.status === 'online' ? 'badge-ok' : 'badge-bad'}`}>{server?.status}</span></p>
      </section>
      <section className="panel">
        <h3>Metriken (Mock/Seed)</h3>
        {metrics.map((m, idx) => (
          <div key={idx} style={{ borderBottom: '1px solid var(--border)', padding: '8px 0' }}>
            CPU {m.cpu_percent}% | RAM {m.ram_percent}% | Storage {m.storage_percent}% | Net In {m.network_in_kbps} kbps
          </div>
        ))}
      </section>
    </div>
  )
}
