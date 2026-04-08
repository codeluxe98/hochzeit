import { api } from '@/lib/api'
import { Overview } from '@/types'

export const getOverview = () => api<Overview>('/dashboard/overview')
