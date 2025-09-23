import { create } from 'zustand'
import { persist } from 'zustand/middleware'

interface User {
  id: string
  username: string
  email: string
  roles: string[]
  permissions: string[]
}

interface AuthState {
  isAuthenticated: boolean
  user: User | null
  token: string | null
  login: (credentials: { username: string; password: string }) => Promise<boolean>
  logout: () => void
  setToken: (token: string, user: User) => void
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      isAuthenticated: true, // Default to true for demo
      user: {
        id: '1',
        username: 'admin',
        email: 'admin@enterprise.ai',
        roles: ['admin'],
        permissions: ['read', 'write', 'admin']
      },
      token: 'demo-token',

      login: async (credentials) => {
        try {
          const response = await fetch('/api/auth/login', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(credentials),
          })

          if (response.ok) {
            const data = await response.json()
            set({
              isAuthenticated: true,
              user: data.user,
              token: data.token,
            })
            return true
          }
          return false
        } catch (error) {
          console.error('Login error:', error)
          return false
        }
      },

      logout: () => {
        set({
          isAuthenticated: false,
          user: null,
          token: null,
        })
      },

      setToken: (token, user) => {
        set({
          isAuthenticated: true,
          user,
          token,
        })
      },
    }),
    {
      name: 'auth-storage',
      partialize: (state) => ({
        isAuthenticated: state.isAuthenticated,
        user: state.user,
        token: state.token,
      }),
    }
  )
)