export type Overview = {
  total_servers: number
  online_servers: number
  offline_servers: number
  avg_cpu: number
  avg_ram: number
  recent_actions: number
  warnings: number
}

export type Server = {
  id: number
  name: string
  host: string
  host_type: string
  location: string
  status: string
  notes: string
}

export type AuditLog = {
  id: number
  user_id: number | null
  action: string
  target_type: string
  target_id: string
  status: string
  details: string
  created_at: string
}

export type User = {
  id: number
  email: string
  username: string
  full_name: string
  role: string
  is_active: boolean
}
