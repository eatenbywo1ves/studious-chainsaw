import React from 'react'
import { motion } from 'framer-motion'
import { CheckCircleIcon, ExclamationTriangleIcon, XCircleIcon } from '@heroicons/react/24/solid'

// No props needed for this component

const services = [
  { name: 'API Gateway', status: 'healthy', uptime: '99.9%', responseTime: '< 1ms' },
  { name: 'Observatory Agent', status: 'healthy', uptime: '99.8%', responseTime: '15ms' },
  { name: 'Agent-3', status: 'healthy', uptime: '99.7%', responseTime: '42ms' },
  { name: 'Financial Analytics', status: 'healthy', uptime: '99.9%', responseTime: '8ms' },
  { name: 'Security Framework', status: 'healthy', uptime: '100%', responseTime: '3ms' },
  { name: 'Multi-tenant Engine', status: 'warning', uptime: '98.5%', responseTime: '125ms' },
]

const getStatusColor = (status: string) => {
  switch (status) {
    case 'healthy': return 'text-green-600 dark:text-green-400'
    case 'warning': return 'text-yellow-600 dark:text-yellow-400'
    case 'error': return 'text-red-600 dark:text-red-400'
    default: return 'text-gray-600 dark:text-gray-400'
  }
}

const getStatusIcon = (status: string) => {
  switch (status) {
    case 'healthy': return CheckCircleIcon
    case 'warning': return ExclamationTriangleIcon
    case 'error': return XCircleIcon
    default: return CheckCircleIcon
  }
}

const SystemStatus: React.FC = () => {
  return (
    <div className="card p-6">
      <div className="flex items-center justify-between mb-6">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
          System Status
        </h3>
        <div className="flex items-center space-x-2">
          <div className="w-3 h-3 bg-green-500 rounded-full animate-pulse"></div>
          <span className="text-sm text-green-600 dark:text-green-400 font-medium">
            Operational
          </span>
        </div>
      </div>

      <div className="space-y-4">
        {services.map((service, index) => {
          const StatusIcon = getStatusIcon(service.status)
          
          return (
            <motion.div
              key={service.name}
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: index * 0.1 }}
              className="flex items-center justify-between p-4 rounded-lg border border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors"
            >
              <div className="flex items-center space-x-3">
                <StatusIcon className={`w-5 h-5 ${getStatusColor(service.status)}`} />
                <div>
                  <p className="font-medium text-gray-900 dark:text-white">
                    {service.name}
                  </p>
                  <p className="text-sm text-gray-500 dark:text-gray-400">
                    Response: {service.responseTime}
                  </p>
                </div>
              </div>
              <div className="text-right">
                <p className={`text-sm font-medium ${getStatusColor(service.status)}`}>
                  {service.status.charAt(0).toUpperCase() + service.status.slice(1)}
                </p>
                <p className="text-xs text-gray-500 dark:text-gray-400">
                  Uptime: {service.uptime}
                </p>
              </div>
            </motion.div>
          )
        })}
      </div>
    </div>
  )
}

export default SystemStatus