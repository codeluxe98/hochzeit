import { api } from '@/lib/api'
import { AuditLog } from '@/types'

export const listAuditLogs = () => api<AuditLog[]>('/audit-logs/')
