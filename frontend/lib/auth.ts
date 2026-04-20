const KEY = 'homeops_token'

export const getToken = (): string | null => (typeof window !== 'undefined' ? localStorage.getItem(KEY) : null)
export const setToken = (token: string): void => localStorage.setItem(KEY, token)
export const clearToken = (): void => localStorage.removeItem(KEY)
