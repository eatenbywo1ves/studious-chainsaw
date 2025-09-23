import React, { useState } from 'react'
import { motion } from 'framer-motion'
import { 
  MagnifyingGlassIcon,
  PlusIcon,
  ServerIcon,
  EyeIcon,
  CpuChipIcon,
  ShieldCheckIcon,
  ChartBarIcon
} from '@heroicons/react/24/outline'
import { CheckCircleIcon, ExclamationTriangleIcon, XCircleIcon } from '@heroicons/react/24/solid'

interface Service {
  id: string
  name: string
  type: string
  status: 'healthy' | 'warning' | 'error'
  port: number
  uptime: string
  version: string
  requests: number
  errorRate: number
  responseTime: number
  capabilities: string[]
}

const mockServices: Service[] = [
  {
    id: '1',
    name: 'API Gateway',
    type: 'Infrastructure',
    status: 'healthy',
    port: 9000,
    uptime: '2h 24m',
    version: '1.0.0',
    requests: 12485,
    errorRate: 0.02,
    responseTime: 0.8,
    capabilities: ['routing', 'auth', 'rate-limiting', 'circuit-breaker']
  },
  {
    id: '2',
    name: 'Observatory Agent',
    type: 'Monitoring',
    status: 'healthy',
    port: 8080,
    uptime: '2h 24m',
    version: '2.0.0',
    requests: 8934,
    errorRate: 0.01,
    responseTime: 15.2,
    capabilities: ['monitoring', 'metrics', 'alerting', 'dashboard']
  },
  {
    id: '3',
    name: 'Agent-3',
    type: 'Analytics',
    status: 'healthy',
    port: 3001,
    uptime: '45m',
    version: '1.2.1',
    requests: 2847,
    errorRate: 0.03,
    responseTime: 42.1,
    capabilities: ['data-analysis', 'performance-monitoring']
  },
  {
    id: '4',
    name: 'Financial Stochastic',
    type: 'MCP Server',
    status: 'healthy',
    port: 3002,
    uptime: '1h 12m',
    version: '1.0.0',
    requests: 1523,
    errorRate: 0.00,
    responseTime: 8.5,
    capabilities: ['gbm', 'heston', 'cir', 'merton-jump']
  },
  {
    id: '5',
    name: 'Security Framework',
    type: 'Security',
    status: 'healthy',
    port: 8443,
    uptime: '3h 45m',
    version: '1.1.0',
    requests: 5672,
    errorRate: 0.01,
    responseTime: 3.2,
    capabilities: ['oauth2', 'saml', 'mfa', 'rbac']
  },
  {
    id: '6',
    name: 'Multi-tenant Engine',
    type: 'Infrastructure',
    status: 'warning',
    port: 8001,
    uptime: '1h 58m',
    version: '1.0.1',
    requests: 3421,
    errorRate: 0.08,
    responseTime: 125.7,
    capabilities: ['tenant-isolation', 'quota-management']
  }
]

const Services: React.FC = () => {
  const [searchTerm, setSearchTerm] = useState('')
  const [filterType, setFilterType] = useState('all')
  const [filterStatus, setFilterStatus] = useState('all')

  const filteredServices = mockServices.filter(service => {
    const matchesSearch = service.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         service.type.toLowerCase().includes(searchTerm.toLowerCase())
    const matchesType = filterType === 'all' || service.type.toLowerCase() === filterType.toLowerCase()
    const matchesStatus = filterStatus === 'all' || service.status === filterStatus
    
    return matchesSearch && matchesType && matchesStatus
  })

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'healthy': return CheckCircleIcon
      case 'warning': return ExclamationTriangleIcon
      case 'error': return XCircleIcon
      default: return CheckCircleIcon
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'healthy': return 'text-green-500'
      case 'warning': return 'text-yellow-500'
      case 'error': return 'text-red-500'
      default: return 'text-gray-500'
    }
  }

  const getTypeIcon = (type: string) => {
    switch (type.toLowerCase()) {
      case 'infrastructure': return ServerIcon
      case 'monitoring': return EyeIcon
      case 'analytics': return CpuChipIcon
      case 'security': return ShieldCheckIcon
      case 'mcp server': return ChartBarIcon
      default: return ServerIcon
    }
  }

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      className="space-y-6"
    >
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
          Services Management
        </h1>
        <motion.button
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.95 }}
          className="btn-primary flex items-center space-x-2"
        >
          <PlusIcon className="w-4 h-4" />
          <span>Deploy Service</span>
        </motion.button>
      </div>

      {/* Filters */}
      <div className="card p-6">
        <div className="flex flex-col sm:flex-row gap-4">
          <div className="flex-1">
            <div className="relative">
              <MagnifyingGlassIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
              <input
                type="text"
                placeholder="Search services..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="input-field pl-10"
              />
            </div>
          </div>
          
          <div className="flex space-x-3">
            <select
              value={filterType}
              onChange={(e) => setFilterType(e.target.value)}
              className="input-field w-40"
            >
              <option value="all">All Types</option>
              <option value="infrastructure">Infrastructure</option>
              <option value="monitoring">Monitoring</option>
              <option value="analytics">Analytics</option>
              <option value="security">Security</option>
              <option value="mcp server">MCP Server</option>
            </select>
            
            <select
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
              className="input-field w-32"
            >
              <option value="all">All Status</option>
              <option value="healthy">Healthy</option>
              <option value="warning">Warning</option>
              <option value="error">Error</option>
            </select>
          </div>
        </div>
      </div>

      {/* Services Grid */}
      <motion.div
        layout
        className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6"
      >
        {filteredServices.map((service, index) => {
          const ServiceIcon = getTypeIcon(service.type)
          const StatusIcon = getStatusIcon(service.status)
          
          return (
            <motion.div
              key={service.id}
              layout
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: index * 0.1 }}
              whileHover={{ y: -4, shadow: "0 10px 25px -5px rgba(0, 0, 0, 0.1)" }}
              className="card p-6 group cursor-pointer"
            >
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center space-x-3">
                  <div className="p-2 rounded-lg bg-gray-100 dark:bg-gray-700 group-hover:scale-110 transition-transform">
                    <ServiceIcon className="w-6 h-6 text-gray-600 dark:text-gray-400" />
                  </div>
                  <div>
                    <h3 className="font-semibold text-gray-900 dark:text-white">
                      {service.name}
                    </h3>
                    <p className="text-sm text-gray-500 dark:text-gray-400">
                      {service.type}
                    </p>
                  </div>
                </div>
                <StatusIcon className={`w-5 h-5 ${getStatusColor(service.status)}`} />
              </div>

              <div className="space-y-3">
                <div className="flex justify-between text-sm">
                  <span className="text-gray-600 dark:text-gray-400">Port:</span>
                  <span className="font-medium text-gray-900 dark:text-white">{service.port}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-gray-600 dark:text-gray-400">Uptime:</span>
                  <span className="font-medium text-gray-900 dark:text-white">{service.uptime}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-gray-600 dark:text-gray-400">Version:</span>
                  <span className="font-medium text-gray-900 dark:text-white">{service.version}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-gray-600 dark:text-gray-400">Requests:</span>
                  <span className="font-medium text-gray-900 dark:text-white">
                    {service.requests.toLocaleString()}
                  </span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-gray-600 dark:text-gray-400">Error Rate:</span>
                  <span className={`font-medium ${
                    service.errorRate < 0.05 ? 'text-green-600 dark:text-green-400' : 
                    service.errorRate < 0.1 ? 'text-yellow-600 dark:text-yellow-400' : 
                    'text-red-600 dark:text-red-400'
                  }`}>
                    {(service.errorRate * 100).toFixed(2)}%
                  </span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-gray-600 dark:text-gray-400">Avg Response:</span>
                  <span className="font-medium text-gray-900 dark:text-white">
                    {service.responseTime.toFixed(1)}ms
                  </span>
                </div>
              </div>

              <div className="mt-4 pt-4 border-t border-gray-200 dark:border-gray-700">
                <p className="text-xs text-gray-500 dark:text-gray-400 mb-2">Capabilities:</p>
                <div className="flex flex-wrap gap-1">
                  {service.capabilities.map((capability) => (
                    <span
                      key={capability}
                      className="inline-flex items-center px-2 py-1 rounded-md text-xs font-medium bg-primary-100 text-primary-700 dark:bg-primary-900/50 dark:text-primary-300"
                    >
                      {capability}
                    </span>
                  ))}
                </div>
              </div>

              <div className="mt-4 flex space-x-2">
                <motion.button
                  whileHover={{ scale: 1.02 }}
                  whileTap={{ scale: 0.98 }}
                  className="flex-1 btn-secondary text-xs py-2"
                >
                  View Details
                </motion.button>
                <motion.button
                  whileHover={{ scale: 1.02 }}
                  whileTap={{ scale: 0.98 }}
                  className="flex-1 btn-primary text-xs py-2"
                >
                  Manage
                </motion.button>
              </div>
            </motion.div>
          )
        })}
      </motion.div>

      {filteredServices.length === 0 && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="card p-12 text-center"
        >
          <ServerIcon className="w-12 h-12 text-gray-400 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
            No services found
          </h3>
          <p className="text-gray-500 dark:text-gray-400">
            Try adjusting your search or filter criteria
          </p>
        </motion.div>
      )}
    </motion.div>
  )
}

export default Services