'use client'

import { getOverview } from '@/services/dashboard'
import { Overview } from '@/types'
import { useEffect, useState } from 'react'

export default function DashboardPage() {
  const [data, setData] = useState<Overview | null>(null)

  useEffect(() => {
    getOverview().then(setData).catch(console.error)
  }, [])

  return (
    <div className="grid" style={{ gap: 16 }}>
      <section className="grid grid-4">
        <article className="panel"><h3>Server gesamt</h3><strong>{data?.total_servers ?? '-'}</strong></article>
        <article className="panel"><h3>Online</h3><strong>{data?.online_servers ?? '-'}</strong></article>
        <article className="panel"><h3>Ø CPU</h3><strong>{data?.avg_cpu ?? '-'}%</strong></article>
        <article className="panel"><h3>Ø RAM</h3><strong>{data?.avg_ram ?? '-'}%</strong></article>
      </section>
      <section className="grid grid-2">
        <div className="panel"><h3>Letzte Aktionen</h3><p>{data?.recent_actions ?? 0}</p></div>
        <div className="panel"><h3>Warnungen</h3><p>{data?.warnings ?? 0}</p></div>
      </section>
    </div>
  )
}
