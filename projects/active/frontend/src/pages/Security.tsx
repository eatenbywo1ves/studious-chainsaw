import React from 'react'
import { motion } from 'framer-motion'
import { 
  ShieldCheckIcon, 
  KeyIcon, 
  UserGroupIcon,
  ExclamationTriangleIcon,
  LockClosedIcon,
  FingerPrintIcon
} from '@heroicons/react/24/outline'

const Security: React.FC = () => {
  const securityMetrics = [
    { name: 'Active Sessions', value: 247, status: 'normal', icon: UserGroupIcon },
    { name: 'Failed Logins', value: 12, status: 'warning', icon: ExclamationTriangleIcon },
    { name: 'API Keys', value: 89, status: 'normal', icon: KeyIcon },
    { name: 'MFA Enabled', value: '98%', status: 'good', icon: FingerPrintIcon },
  ]

  const recentEvents = [
    { time: '10:45 AM', event: 'New API key generated for tenant-acme', severity: 'info' },
    { time: '10:42 AM', event: 'Failed login attempt blocked', severity: 'warning' },
    { time: '10:38 AM', event: 'OAuth2 token refreshed', severity: 'info' },
    { time: '10:35 AM', event: 'SAML assertion validated', severity: 'success' },
    { time: '10:30 AM', event: 'Rate limit exceeded for IP 192.168.1.100', severity: 'warning' },
  ]

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'good': return 'text-green-600 dark:text-green-400'
      case 'warning': return 'text-yellow-600 dark:text-yellow-400'
      case 'error': return 'text-red-600 dark:text-red-400'
      default: return 'text-blue-600 dark:text-blue-400'
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'success': return 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200'
      case 'warning': return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200'
      case 'error': return 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200'
      default: return 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200'
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
          Security Center
        </h1>
        <div className="flex items-center space-x-2">
          <ShieldCheckIcon className="w-6 h-6 text-green-500" />
          <span className="text-sm text-green-600 dark:text-green-400 font-medium">
            All Systems Secure
          </span>
        </div>
      </div>

      {/* Security Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {securityMetrics.map((metric, index) => {
          const IconComponent = metric.icon
          return (
            <motion.div
              key={metric.name}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.1 }}
              whileHover={{ y: -2 }}
              className="card p-6"
            >
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600 dark:text-gray-400">
                    {metric.name}
                  </p>
                  <p className={`text-2xl font-bold mt-1 ${getStatusColor(metric.status)}`}>
                    {metric.value}
                  </p>
                </div>
                <div className="p-3 rounded-full bg-gray-100 dark:bg-gray-700">
                  <IconComponent className="w-6 h-6 text-gray-600 dark:text-gray-400" />
                </div>
              </div>
            </motion.div>
          )
        })}
      </div>

      {/* Security Framework Status */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
        className="card p-6"
      >
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-6">
          Security Framework Status
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {[
            { name: 'OAuth2/OIDC', status: 'Active', details: 'PKCE enabled, 247 active tokens' },
            { name: 'SAML 2.0', status: 'Active', details: 'Multi-IdP configured, SSO enabled' },
            { name: 'Multi-Factor Auth', status: 'Active', details: 'TOTP + SMS, 98% adoption' },
            { name: 'RBAC Engine', status: 'Active', details: '12 roles, 45 permissions' },
            { name: 'Zero Trust', status: 'Active', details: 'Dynamic policies, real-time eval' },
            { name: 'Audit Logging', status: 'Active', details: '15.2K events logged today' },
          ].map((framework, index) => (
            <motion.div
              key={framework.name}
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: 0.4 + index * 0.1 }}
              className="p-4 rounded-lg border border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors"
            >
              <div className="flex items-center space-x-3 mb-2">
                <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                <p className="font-medium text-gray-900 dark:text-white">
                  {framework.name}
                </p>
              </div>
              <p className="text-xs text-green-600 dark:text-green-400 font-medium mb-1">
                {framework.status}
              </p>
              <p className="text-xs text-gray-500 dark:text-gray-400">
                {framework.details}
              </p>
            </motion.div>
          ))}
        </div>
      </motion.div>

      {/* Recent Security Events */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.5 }}
        className="card p-6"
      >
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-6">
          Recent Security Events
        </h3>
        <div className="space-y-3">
          {recentEvents.map((event, index) => (
            <motion.div
              key={index}
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.6 + index * 0.1 }}
              className="flex items-center justify-between p-4 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors"
            >
              <div className="flex items-center space-x-3">
                <span className={`status-indicator ${getSeverityColor(event.severity)}`}>
                  {event.severity}
                </span>
                <span className="text-sm text-gray-900 dark:text-white">
                  {event.event}
                </span>
              </div>
              <span className="text-xs text-gray-500 dark:text-gray-400">
                {event.time}
              </span>
            </motion.div>
          ))}
        </div>
      </motion.div>

      {/* Threat Intelligence */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.7 }}
          className="card p-6"
        >
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-6">
            Threat Detection
          </h3>
          <div className="space-y-4">
            <div className="flex items-center justify-between p-3 rounded-lg bg-green-50 dark:bg-green-900/20">
              <div className="flex items-center space-x-3">
                <LockClosedIcon className="w-5 h-5 text-green-600" />
                <span className="text-sm font-medium text-green-800 dark:text-green-200">
                  No active threats detected
                </span>
              </div>
              <span className="text-xs text-green-600 dark:text-green-400">
                Last scan: 2 min ago
              </span>
            </div>
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div>
                <p className="text-gray-600 dark:text-gray-400">Blocked IPs</p>
                <p className="font-semibold text-gray-900 dark:text-white">127</p>
              </div>
              <div>
                <p className="text-gray-600 dark:text-gray-400">Quarantined</p>
                <p className="font-semibold text-gray-900 dark:text-white">0</p>
              </div>
            </div>
          </div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.8 }}
          className="card p-6"
        >
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-6">
            Compliance Status
          </h3>
          <div className="space-y-3">
            {[
              { framework: 'SOC 2 Type II', status: 'Compliant', score: 98 },
              { framework: 'GDPR', status: 'Compliant', score: 96 },
              { framework: 'HIPAA', status: 'Compliant', score: 94 },
              { framework: 'ISO 27001', status: 'In Progress', score: 87 },
            ].map((compliance) => (
              <div key={compliance.framework} className="flex items-center justify-between">
                <span className="text-sm text-gray-600 dark:text-gray-400">
                  {compliance.framework}
                </span>
                <div className="flex items-center space-x-3">
                  <div className="w-24 bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                    <div 
                      className={`h-2 rounded-full ${
                        compliance.score >= 95 ? 'bg-green-500' : 
                        compliance.score >= 85 ? 'bg-yellow-500' : 'bg-red-500'
                      }`}
                      style={{ width: `${compliance.score}%` }}
                    />
                  </div>
                  <span className="text-sm font-medium text-gray-900 dark:text-white w-12">
                    {compliance.score}%
                  </span>
                </div>
              </div>
            ))}
          </div>
        </motion.div>
      </div>
    </motion.div>
  )
}



export default Security