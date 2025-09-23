import React from 'react'
import { motion } from 'framer-motion'
import { 
  ServerIcon, 
  ChartBarIcon, 
  ShieldCheckIcon, 
  CpuChipIcon,
  ClockIcon,
  UserGroupIcon
} from '@heroicons/react/24/outline'
import MetricCard from '../components/MetricCard'
import SystemStatus from '../components/SystemStatus'
import RealtimeChart from '../components/RealtimeChart'
import ServicesList from '../components/ServicesList'
import { useSystemMetrics } from '../hooks/useSystemMetrics'

const Dashboard: React.FC = () => {
  const { metrics, isLoading } = useSystemMetrics()

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: {
        staggerChildren: 0.1
      }
    }
  }

  const itemVariants = {
    hidden: { opacity: 0, y: 20 },
    visible: { opacity: 1, y: 0 }
  }

  return (
    <motion.div
      variants={containerVariants}
      initial="hidden"
      animate="visible"
      className="space-y-6"
    >
      <div className="flex items-center justify-between">
        <motion.h1 
          variants={itemVariants}
          className="text-3xl font-bold text-gray-900 dark:text-white"
        >
          Platform Dashboard
        </motion.h1>
        <motion.div 
          variants={itemVariants}
          className="flex items-center space-x-2 text-sm text-gray-600 dark:text-gray-400"
        >
          <ClockIcon className="w-4 h-4" />
          <span>Last updated: {new Date().toLocaleTimeString()}</span>
        </motion.div>
      </div>

      {/* Key Metrics Grid */}
      <motion.div 
        variants={itemVariants}
        className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6"
      >
        <MetricCard
          title="Active Services"
          value={metrics?.activeServices || 3}
          icon={ServerIcon}
          color="blue"
          trend="+2.3%"
          loading={isLoading}
        />
        <MetricCard
          title="API Requests"
          value={metrics?.totalRequests || 12485}
          icon={ChartBarIcon}
          color="green"
          trend="+15.4%"
          loading={isLoading}
        />
        <MetricCard
          title="Security Events"
          value={metrics?.securityEvents || 247}
          icon={ShieldCheckIcon}
          color="purple"
          trend="-5.2%"
          loading={isLoading}
        />
        <MetricCard
          title="System Load"
          value={`${metrics?.systemLoad || 22}%`}
          icon={CpuChipIcon}
          color="orange"
          trend="+1.8%"
          loading={isLoading}
        />
      </motion.div>

      {/* System Status */}
      <motion.div variants={itemVariants}>
        <SystemStatus />
      </motion.div>

      {/* Charts and Services Grid */}
      <motion.div 
        variants={itemVariants}
        className="grid grid-cols-1 lg:grid-cols-2 gap-6"
      >
        <div className="card p-6">
          <div className="flex items-center justify-between mb-6">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
              Performance Metrics
            </h3>
            <div className="flex items-center space-x-2">
              <div className="w-3 h-3 bg-green-500 rounded-full animate-pulse"></div>
              <span className="text-sm text-gray-500 dark:text-gray-400">Live</span>
            </div>
          </div>
          <RealtimeChart />
        </div>

        <div className="card p-6">
          <div className="flex items-center justify-between mb-6">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
              Active Services
            </h3>
            <UserGroupIcon className="w-5 h-5 text-gray-400" />
          </div>
          <ServicesList />
        </div>
      </motion.div>

      {/* Recent Activity */}
      <motion.div variants={itemVariants} className="card p-6">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-6">
          Recent Activity
        </h3>
        <div className="space-y-4">
          {[
            { time: '2 min ago', event: 'Agent-3 completed data analysis', type: 'success' },
            { time: '5 min ago', event: 'API Gateway handled 1,247 requests', type: 'info' },
            { time: '8 min ago', event: 'Observatory sync completed', type: 'success' },
            { time: '12 min ago', event: 'Security scan passed', type: 'success' },
            { time: '15 min ago', event: 'New service registered: ml-inference', type: 'info' },
          ].map((activity, index) => (
            <motion.div
              key={index}
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: index * 0.1 }}
              className="flex items-center justify-between py-3 px-4 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors"
            >
              <div className="flex items-center space-x-3">
                <div className={`w-2 h-2 rounded-full ${
                  activity.type === 'success' ? 'bg-green-500' : 
                  activity.type === 'warning' ? 'bg-yellow-500' : 'bg-blue-500'
                }`} />
                <span className="text-sm text-gray-900 dark:text-white">
                  {activity.event}
                </span>
              </div>
              <span className="text-xs text-gray-500 dark:text-gray-400">
                {activity.time}
              </span>
            </motion.div>
          ))}
        </div>
      </motion.div>
    </motion.div>
  )
}

export default Dashboard