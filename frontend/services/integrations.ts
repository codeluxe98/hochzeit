import { api } from '@/lib/api'

export const listIntegrations = () => api<any[]>('/integrations/')
