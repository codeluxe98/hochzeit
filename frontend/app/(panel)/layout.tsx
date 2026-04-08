'use client'

import { AuthGuard } from '@/components/auth-guard'
import { Sidebar } from '@/components/sidebar'
import { Topbar } from '@/components/topbar'

export default function PanelLayout({ children }: { children: React.ReactNode }) {
  return (
    <AuthGuard>
      <div className="layout">
        <Sidebar />
        <main className="main">
          <Topbar />
          {children}
        </main>
      </div>
    </AuthGuard>
  )
}
