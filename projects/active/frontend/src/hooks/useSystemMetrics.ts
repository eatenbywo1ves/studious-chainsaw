import { useState, useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'

interface SystemMetrics {
  activeServices: number
  totalRequests: number
  securityEvents: number
  systemLoad: number
  uptime: number
  responseTime: number
}

export const useSystemMetrics = () => {
  const [realtimeData, setRealtimeData] = useState<SystemMetrics>({
    activeServices: 3,
    totalRequests: 12485,
    securityEvents: 247,
    systemLoad: 22,
    uptime: 8453,
    responseTime: 0.8
  })

  // Fetch initial data from API Gateway
  const { data: gatewayStats, isLoading } = useQuery({
    queryKey: ['gateway-stats'],
    queryFn: async () => {
      const response = await fetch('/api/stats')
      if (!response.ok) throw new Error('Failed to fetch stats')
      return response.json()
    },
    refetchInterval: 5000, // Refetch every 5 seconds
  })

  // Simulate real-time updates
  useEffect(() => {
    const interval = setInterval(() => {
      setRealtimeData(prev => ({
        ...prev,
        totalRequests: prev.totalRequests + Math.floor(Math.random() * 10),
        systemLoad: Math.max(15, Math.min(85, prev.systemLoad + (Math.random() - 0.5) * 5)),
        responseTime: Math.max(0.1, Math.min(10, prev.responseTime + (Math.random() - 0.5) * 0.5)),
        securityEvents: prev.securityEvents + (Math.random() > 0.9 ? 1 : 0),
      }))
    }, 3000)

    return () => clearInterval(interval)
  }, [])

  // Merge API data with realtime simulation
  const metrics = {
    ...realtimeData,
    ...(gatewayStats && {
      totalRequests: gatewayStats.requests_total || realtimeData.totalRequests,
      uptime: gatewayStats.uptime_seconds || realtimeData.uptime,
    })
  }

  return { metrics, isLoading }
}