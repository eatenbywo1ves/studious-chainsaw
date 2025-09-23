import React from 'react'
import { motion } from 'framer-motion'
import { 
  ServerIcon, 
  EyeIcon, 
  CpuChipIcon,
  CheckCircleIcon,
  ExclamationTriangleIcon 
} from '@heroicons/react/24/outline'

interface Service {
  name: string
  type: string
  status: 'healthy' | 'warning' | 'error'
  port: number
  uptime: string
  icon: React.ComponentType<{ className?: string }>
}

const services: Service[] = [
  {
    name: 'API Gateway',
    type: 'Infrastructure',
    status: 'healthy',
    port: 9000,
    uptime: '2h 24m',
    icon: ServerIcon
  },
  {
    name: 'Observatory Agent',
    type: 'Monitoring',
    status: 'healthy',
    port: 8080,
    uptime: '2h 24m',
    icon: EyeIcon
  },
  {
    name: 'Agent-3',
    type: 'Analytics',
    status: 'healthy',
    port: 3001,
    uptime: '45m',
    icon: CpuChipIcon
  }
]

const ServicesList: React.FC = () => {
  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'healthy': return CheckCircleIcon
      case 'warning': return ExclamationTriangleIcon
      default: return ExclamationTriangleIcon
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'healthy': return 'text-green-500'
      case 'warning': return 'text-yellow-500'
      default: return 'text-red-500'
    }
  }

  return (
    <div className="space-y-3">
      {services.map((service, index) => {
        const ServiceIcon = service.icon
        const StatusIcon = getStatusIcon(service.status)
        
        return (
          <motion.div
            key={service.name}
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: index * 0.1 }}
            className="flex items-center justify-between p-4 rounded-lg border border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors group"
          >
            <div className="flex items-center space-x-3">
              <div className="p-2 rounded-lg bg-primary-100 dark:bg-primary-900/50 group-hover:scale-110 transition-transform">
                <ServiceIcon className="w-5 h-5 text-primary-600 dark:text-primary-400" />
              </div>
              <div>
                <p className="font-medium text-gray-900 dark:text-white">
                  {service.name}
                </p>
                <p className="text-sm text-gray-500 dark:text-gray-400">
                  {service.type} • Port {service.port}
                </p>
              </div>
            </div>
            
            <div className="flex items-center space-x-4">
              <div className="text-right">
                <p className="text-sm text-gray-600 dark:text-gray-300">
                  Uptime: {service.uptime}
                </p>
              </div>
              <StatusIcon className={`w-5 h-5 ${getStatusColor(service.status)}`} />
            </div>
          </motion.div>
        )
      })}
    </div>
  )
}

export default ServicesList