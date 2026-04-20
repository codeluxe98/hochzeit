'use client'

import { getToken } from '@/lib/auth'
import { usePathname, useRouter } from 'next/navigation'
import { useEffect } from 'react'

export function AuthGuard({ children }: { children: React.ReactNode }) {
  const router = useRouter()
  const pathname = usePathname()

  useEffect(() => {
    const token = getToken()
    if (!token && pathname !== '/login') {
      router.push('/login')
    }
  }, [pathname, router])

  return <>{children}</>
}
