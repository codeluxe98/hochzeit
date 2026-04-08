import { api } from '@/lib/api'
import { User } from '@/types'

export const listUsers = () => api<User[]>('/users/')
