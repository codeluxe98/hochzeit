import { api } from '@/lib/api'
import { Server } from '@/types'

export const listServers = () => api<Server[]>('/servers/')
export const createServer = (payload: Partial<Server>) =>
  api<Server>('/servers/', { method: 'POST', body: JSON.stringify(payload) })
export const getServer = (id: number) => api<Server>(`/servers/${id}`)
export const getMetrics = (id: number) => api<any[]>(`/servers/${id}/metrics`)
