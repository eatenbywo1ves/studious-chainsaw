import React, { useState, useEffect } from 'react'
import { LineChart, Line, XAxis, YAxis, CartesianGrid, ResponsiveContainer, Tooltip } from 'recharts'
import { motion } from 'framer-motion'

interface DataPoint {
  time: string
  responseTime: number
  requests: number
  cpuUsage: number
}

const RealtimeChart: React.FC = () => {
  const [data, setData] = useState<DataPoint[]>([])

  useEffect(() => {
    const generateDataPoint = (): DataPoint => ({
      time: new Date().toLocaleTimeString('en-US', { 
        hour12: false, 
        hour: '2-digit', 
        minute: '2-digit', 
        second: '2-digit' 
      }),
      responseTime: Math.random() * 50 + 10,
      requests: Math.floor(Math.random() * 100) + 50,
      cpuUsage: Math.random() * 30 + 20,
    })

    // Initialize with some data
    const initialData = Array.from({ length: 20 }, () => generateDataPoint())
    setData(initialData)

    // Update every 3 seconds
    const interval = setInterval(() => {
      setData(prev => {
        const newData = [...prev.slice(1), generateDataPoint()]
        return newData
      })
    }, 3000)

    return () => clearInterval(interval)
  }, [])

  interface TooltipPayload {
    color: string
    name: string
    value: number
  }

  interface CustomTooltipProps {
    active?: boolean
    payload?: TooltipPayload[]
    label?: string
  }

  const CustomTooltip = ({ active, payload, label }: CustomTooltipProps) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-white dark:bg-gray-800 p-3 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700">
          <p className="text-sm font-medium text-gray-900 dark:text-white mb-2">{label}</p>
          {payload.map((entry, index: number) => (
            <p key={index} className="text-xs" style={{ color: entry.color }}>
              {entry.name}: {entry.value.toFixed(1)}{entry.name === 'CPU Usage' ? '%' : entry.name === 'Response Time' ? 'ms' : ''}
            </p>
          ))}
        </div>
      )
    }
    return null
  }

  return (
    <motion.div 
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.5 }}
      className="h-64"
    >
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={data} margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
          <CartesianGrid strokeDasharray="3 3" className="opacity-30" />
          <XAxis 
            dataKey="time" 
            tick={{ fontSize: 12 }}
            className="text-gray-600 dark:text-gray-400"
          />
          <YAxis 
            tick={{ fontSize: 12 }}
            className="text-gray-600 dark:text-gray-400"
          />
          <Tooltip content={<CustomTooltip />} />
          <Line 
            type="monotone" 
            dataKey="responseTime" 
            stroke="#3b82f6" 
            strokeWidth={2}
            dot={false}
            name="Response Time"
            animationDuration={1000}
          />
          <Line 
            type="monotone" 
            dataKey="cpuUsage" 
            stroke="#10b981" 
            strokeWidth={2}
            dot={false}
            name="CPU Usage"
            animationDuration={1000}
          />
        </LineChart>
      </ResponsiveContainer>
    </motion.div>
  )
}

export default RealtimeChart