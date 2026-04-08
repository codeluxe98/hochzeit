'use client'

import Link from 'next/link'
import { createServer, listServers } from '@/services/servers'
import { Server } from '@/types'
import { useEffect, useState } from 'react'

const initialForm = { name: '', host: '', host_type: 'rpi', location: 'home', notes: '' }

export default function ServersPage() {
  const [servers, setServers] = useState<Server[]>([])
  const [form, setForm] = useState(initialForm)

  const load = () => listServers().then(setServers).catch(console.error)
  useEffect(() => {
    void load()
  }, [])

  return (
    <div className="grid">
      <div className="panel">
        <h3>Server anlegen</h3>
        <div className="form-row">
          <input className="input" placeholder="Name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
          <input className="input" placeholder="Host/IP" value={form.host} onChange={(e) => setForm({ ...form, host: e.target.value })} />
          <select value={form.host_type} onChange={(e) => setForm({ ...form, host_type: e.target.value })}>
            <option value="rpi">rpi</option><option value="hetzner">hetzner</option><option value="vm">vm</option><option value="docker-host">docker-host</option>
          </select>
          <select value={form.location} onChange={(e) => setForm({ ...form, location: e.target.value })}>
            <option value="home">home</option><option value="hetzner">hetzner</option><option value="remote">remote</option>
          </select>
        </div>
        <button className="btn btn-primary" onClick={async () => { await createServer(form); setForm(initialForm); await load() }}>Speichern</button>
      </div>

      <div className="panel">
        <h3>Serverliste</h3>
        <table className="table"><thead><tr><th>Name</th><th>Host</th><th>Typ</th><th>Status</th><th></th></tr></thead><tbody>
          {servers.map((s) => <tr key={s.id}><td>{s.name}</td><td>{s.host}</td><td>{s.host_type}</td><td><span className={`badge ${s.status === 'online' ? 'badge-ok' : 'badge-bad'}`}>{s.status}</span></td><td><Link href={`/servers/${s.id}`}>Details</Link></td></tr>)}
        </tbody></table>
      </div>
    </div>
  )
}
