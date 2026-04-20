'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'

const items = [
  { href: '/dashboard', label: 'Dashboard' },
  { href: '/servers', label: 'Server' },
  { href: '/users', label: 'Benutzer' },
  { href: '/audit', label: 'Audit-Log' },
  { href: '/integrations', label: 'Integrationen' },
]

export function Sidebar() {
  const pathname = usePathname()

  return (
    <aside className="sidebar">
      <h2 style={{ marginTop: 0 }}>HomeOps</h2>
      <p style={{ color: 'var(--muted)', marginTop: 4 }}>Control Center</p>
      <nav style={{ display: 'grid', gap: 8, marginTop: 18 }}>
        {items.map((item) => (
          <Link
            key={item.href}
            href={item.href}
            className="panel"
            style={{
              padding: '10px 12px',
              background: pathname.startsWith(item.href) ? '#223056' : 'var(--panel)',
            }}
          >
            {item.label}
          </Link>
        ))}
      </nav>
    </aside>
  )
}
