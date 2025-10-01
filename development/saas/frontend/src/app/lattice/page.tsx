'use client'

import { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Progress } from '@/components/ui/progress'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import {
  Cpu, Activity, Database, Settings, Play, Pause, Square, RefreshCw,
  AlertCircle, CheckCircle, Clock, TrendingUp, Zap, Layers,
  Plus, Edit, Trash2, Eye, Download, Upload, Grid3X3
} from 'lucide-react'

interface LatticeConfig {
  id: string
  name: string
  status: 'running' | 'stopped' | 'error' | 'pending'
  type: 'compute' | 'storage' | 'hybrid'
  nodes: number
  utilization: number
  performance: number
  created: string
  lastModified: string
  region: string
  size: string
}

export default function LatticePage() {
  const router = useRouter()
  const [isLoading, setIsLoading] = useState(false)
  const [selectedLattice, setSelectedLattice] = useState<string | null>(null)
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [newLatticeConfig, setNewLatticeConfig] = useState({
    name: '',
    type: 'compute',
    region: 'us-east-1',
    size: 'small',
    nodes: 4
  })

  // Mock lattice data
  const [lattices, setLattices] = useState<LatticeConfig[]>([
    {
      id: 'lattice-001',
      name: 'Primary Compute Grid',
      status: 'running',
      type: 'compute',
      nodes: 16,
      utilization: 78,
      performance: 92,
      created: '2024-01-15',
      lastModified: '2024-01-20',
      region: 'us-east-1',
      size: 'large'
    },
    {
      id: 'lattice-002',
      name: 'Storage Cluster Alpha',
      status: 'running',
      type: 'storage',
      nodes: 8,
      utilization: 45,
      performance: 88,
      created: '2024-01-18',
      lastModified: '2024-01-19',
      region: 'us-west-2',
      size: 'medium'
    },
    {
      id: 'lattice-003',
      name: 'Dev Environment',
      status: 'stopped',
      type: 'hybrid',
      nodes: 4,
      utilization: 0,
      performance: 0,
      created: '2024-01-22',
      lastModified: '2024-01-22',
      region: 'eu-west-1',
      size: 'small'
    },
    {
      id: 'lattice-004',
      name: 'ML Training Grid',
      status: 'pending',
      type: 'compute',
      nodes: 32,
      utilization: 0,
      performance: 0,
      created: '2024-01-25',
      lastModified: '2024-01-25',
      region: 'us-east-1',
      size: 'extra-large'
    }
  ])

  const handleCreateLattice = async () => {
    setIsLoading(true)
    // Simulate API call
    await new Promise(resolve => setTimeout(resolve, 2000))

    const newLattice: LatticeConfig = {
      id: `lattice-${String(lattices.length + 1).padStart(3, '0')}`,
      name: newLatticeConfig.name,
      status: 'pending',
      type: newLatticeConfig.type as 'compute' | 'storage' | 'hybrid',
      nodes: newLatticeConfig.nodes,
      utilization: 0,
      performance: 0,
      created: new Date().toISOString().split('T')[0],
      lastModified: new Date().toISOString().split('T')[0],
      region: newLatticeConfig.region,
      size: newLatticeConfig.size
    }

    setLattices([...lattices, newLattice])
    setShowCreateModal(false)
    setNewLatticeConfig({
      name: '',
      type: 'compute',
      region: 'us-east-1',
      size: 'small',
      nodes: 4
    })
    setIsLoading(false)
  }

  const handleLatticeAction = async (latticeId: string, action: 'start' | 'stop' | 'restart') => {
    setIsLoading(true)
    // Simulate API call
    await new Promise(resolve => setTimeout(resolve, 1000))

    setLattices(lattices.map(lattice => {
      if (lattice.id === latticeId) {
        switch (action) {
          case 'start':
            return { ...lattice, status: 'running' as const }
          case 'stop':
            return { ...lattice, status: 'stopped' as const, utilization: 0, performance: 0 }
          case 'restart':
            return { ...lattice, status: 'pending' as const }
          default:
            return lattice
        }
      }
      return lattice
    }))
    setIsLoading(false)
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'running':
        return <CheckCircle className="h-4 w-4 text-green-500" />
      case 'stopped':
        return <Square className="h-4 w-4 text-gray-500" />
      case 'error':
        return <AlertCircle className="h-4 w-4 text-red-500" />
      case 'pending':
        return <Clock className="h-4 w-4 text-yellow-500" />
      default:
        return <AlertCircle className="h-4 w-4 text-gray-500" />
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'running':
        return 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300'
      case 'stopped':
        return 'bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-300'
      case 'error':
        return 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300'
      case 'pending':
        return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300'
      default:
        return 'bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-300'
    }
  }

  useEffect(() => {
    // Check if user is authenticated
    const token = localStorage.getItem('token')
    if (!token) {
      router.push('/login')
    }
  }, [router])

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100 dark:from-slate-900 dark:to-slate-800">
      {/* Header */}
      <header className="border-b bg-white/50 dark:bg-slate-900/50 backdrop-blur-sm">
        <div className="flex h-16 items-center justify-between px-6">
          <div className="flex items-center space-x-4">
            <Button
              variant="ghost"
              onClick={() => router.push('/dashboard')}
              className="text-sm"
            >
              ← Dashboard
            </Button>
            <Grid3X3 className="h-8 w-8 text-primary" />
            <h1 className="text-xl font-semibold">Lattice Management</h1>
          </div>
          <Button onClick={() => setShowCreateModal(true)}>
            <Plus className="h-4 w-4 mr-2" />
            Create Lattice
          </Button>
        </div>
      </header>

      <div className="container mx-auto p-6">
        {/* Overview Cards */}
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4 mb-6">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Total Lattices</CardTitle>
              <Layers className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{lattices.length}</div>
              <p className="text-xs text-muted-foreground">
                {lattices.filter(l => l.status === 'running').length} running
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Total Nodes</CardTitle>
              <Cpu className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">
                {lattices.reduce((sum, l) => sum + l.nodes, 0)}
              </div>
              <p className="text-xs text-muted-foreground">
                Across all lattices
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Avg Utilization</CardTitle>
              <Activity className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">
                {Math.round(lattices.filter(l => l.status === 'running').reduce((sum, l) => sum + l.utilization, 0) / lattices.filter(l => l.status === 'running').length || 0)}%
              </div>
              <p className="text-xs text-muted-foreground">
                Running lattices only
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Avg Performance</CardTitle>
              <TrendingUp className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">
                {Math.round(lattices.filter(l => l.status === 'running').reduce((sum, l) => sum + l.performance, 0) / lattices.filter(l => l.status === 'running').length || 0)}%
              </div>
              <p className="text-xs text-muted-foreground">
                Efficiency rating
              </p>
            </CardContent>
          </Card>
        </div>

        {/* Main Content */}
        <Tabs defaultValue="overview" className="space-y-4">
          <TabsList className="grid w-full grid-cols-3">
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="monitoring">Monitoring</TabsTrigger>
            <TabsTrigger value="configuration">Configuration</TabsTrigger>
          </TabsList>

          <TabsContent value="overview" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle>Lattice Grid</CardTitle>
                <CardDescription>
                  Manage your computational lattices and monitor their status
                </CardDescription>
              </CardHeader>
              <CardContent>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Name</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Type</TableHead>
                      <TableHead>Nodes</TableHead>
                      <TableHead>Utilization</TableHead>
                      <TableHead>Performance</TableHead>
                      <TableHead>Region</TableHead>
                      <TableHead>Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {lattices.map((lattice) => (
                      <TableRow key={lattice.id}>
                        <TableCell className="font-medium">{lattice.name}</TableCell>
                        <TableCell>
                          <Badge className={getStatusColor(lattice.status)}>
                            <div className="flex items-center gap-1">
                              {getStatusIcon(lattice.status)}
                              {lattice.status}
                            </div>
                          </Badge>
                        </TableCell>
                        <TableCell className="capitalize">{lattice.type}</TableCell>
                        <TableCell>{lattice.nodes}</TableCell>
                        <TableCell>
                          <div className="flex items-center space-x-2">
                            <Progress value={lattice.utilization} className="w-16 h-2" />
                            <span className="text-sm">{lattice.utilization}%</span>
                          </div>
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center space-x-2">
                            <Progress value={lattice.performance} className="w-16 h-2" />
                            <span className="text-sm">{lattice.performance}%</span>
                          </div>
                        </TableCell>
                        <TableCell>{lattice.region}</TableCell>
                        <TableCell>
                          <div className="flex items-center space-x-1">
                            {lattice.status === 'stopped' && (
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => handleLatticeAction(lattice.id, 'start')}
                                disabled={isLoading}
                              >
                                <Play className="h-4 w-4" />
                              </Button>
                            )}
                            {lattice.status === 'running' && (
                              <>
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  onClick={() => handleLatticeAction(lattice.id, 'stop')}
                                  disabled={isLoading}
                                >
                                  <Pause className="h-4 w-4" />
                                </Button>
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  onClick={() => handleLatticeAction(lattice.id, 'restart')}
                                  disabled={isLoading}
                                >
                                  <RefreshCw className="h-4 w-4" />
                                </Button>
                              </>
                            )}
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => setSelectedLattice(lattice.id)}
                            >
                              <Eye className="h-4 w-4" />
                            </Button>
                            <Button variant="ghost" size="sm">
                              <Edit className="h-4 w-4" />
                            </Button>
                            <Button variant="ghost" size="sm">
                              <Trash2 className="h-4 w-4" />
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="monitoring" className="space-y-4">
            <div className="grid gap-4 md:grid-cols-2">
              <Card>
                <CardHeader>
                  <CardTitle>Resource Utilization</CardTitle>
                  <CardDescription>
                    Real-time monitoring of lattice resources
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  {lattices.filter(l => l.status === 'running').map((lattice) => (
                    <div key={lattice.id} className="space-y-2">
                      <div className="flex justify-between text-sm">
                        <span>{lattice.name}</span>
                        <span>{lattice.utilization}%</span>
                      </div>
                      <Progress value={lattice.utilization} className="h-2" />
                    </div>
                  ))}
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Performance Metrics</CardTitle>
                  <CardDescription>
                    Efficiency and throughput monitoring
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  {lattices.filter(l => l.status === 'running').map((lattice) => (
                    <div key={lattice.id} className="space-y-2">
                      <div className="flex justify-between text-sm">
                        <span>{lattice.name}</span>
                        <span>{lattice.performance}%</span>
                      </div>
                      <Progress value={lattice.performance} className="h-2" />
                    </div>
                  ))}
                </CardContent>
              </Card>
            </div>

            {selectedLattice && (
              <Card>
                <CardHeader>
                  <CardTitle>Detailed Monitoring</CardTitle>
                  <CardDescription>
                    Deep dive into {lattices.find(l => l.id === selectedLattice)?.name} performance
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="grid gap-4 md:grid-cols-3">
                    <div className="text-center">
                      <div className="text-2xl font-bold text-green-600">
                        {lattices.find(l => l.id === selectedLattice)?.nodes}
                      </div>
                      <p className="text-sm text-muted-foreground">Active Nodes</p>
                    </div>
                    <div className="text-center">
                      <div className="text-2xl font-bold text-blue-600">
                        {lattices.find(l => l.id === selectedLattice)?.utilization}%
                      </div>
                      <p className="text-sm text-muted-foreground">Current Load</p>
                    </div>
                    <div className="text-center">
                      <div className="text-2xl font-bold text-purple-600">
                        {lattices.find(l => l.id === selectedLattice)?.performance}%
                      </div>
                      <p className="text-sm text-muted-foreground">Efficiency</p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            )}
          </TabsContent>

          <TabsContent value="configuration" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle>Lattice Configuration</CardTitle>
                <CardDescription>
                  Configure global settings and parameters
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="grid gap-4 md:grid-cols-2">
                  <div className="space-y-2">
                    <Label htmlFor="default-region">Default Region</Label>
                    <Select defaultValue="us-east-1">
                      <SelectTrigger>
                        <SelectValue placeholder="Select region" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="us-east-1">US East (N. Virginia)</SelectItem>
                        <SelectItem value="us-west-2">US West (Oregon)</SelectItem>
                        <SelectItem value="eu-west-1">Europe (Ireland)</SelectItem>
                        <SelectItem value="ap-southeast-1">Asia Pacific (Singapore)</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="auto-scaling">Auto Scaling</Label>
                    <Select defaultValue="enabled">
                      <SelectTrigger>
                        <SelectValue placeholder="Select scaling mode" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="enabled">Enabled</SelectItem>
                        <SelectItem value="disabled">Disabled</SelectItem>
                        <SelectItem value="custom">Custom Rules</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="monitoring-interval">Monitoring Interval</Label>
                    <Select defaultValue="30">
                      <SelectTrigger>
                        <SelectValue placeholder="Select interval" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="10">10 seconds</SelectItem>
                        <SelectItem value="30">30 seconds</SelectItem>
                        <SelectItem value="60">1 minute</SelectItem>
                        <SelectItem value="300">5 minutes</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="retention-period">Data Retention</Label>
                    <Select defaultValue="30">
                      <SelectTrigger>
                        <SelectValue placeholder="Select retention period" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="7">7 days</SelectItem>
                        <SelectItem value="30">30 days</SelectItem>
                        <SelectItem value="90">90 days</SelectItem>
                        <SelectItem value="365">1 year</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>

                <div className="space-y-4">
                  <h3 className="text-lg font-medium">Advanced Settings</h3>

                  <div className="space-y-2">
                    <Label htmlFor="max-nodes">Maximum Nodes per Lattice</Label>
                    <Input
                      id="max-nodes"
                      type="number"
                      defaultValue="100"
                      className="w-32"
                    />
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="timeout">Operation Timeout (seconds)</Label>
                    <Input
                      id="timeout"
                      type="number"
                      defaultValue="300"
                      className="w-32"
                    />
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="alert-threshold">Alert Threshold (%)</Label>
                    <Input
                      id="alert-threshold"
                      type="number"
                      defaultValue="85"
                      className="w-32"
                    />
                  </div>
                </div>

                <div className="flex space-x-2">
                  <Button>Save Configuration</Button>
                  <Button variant="outline">Reset to Defaults</Button>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>

        {/* Create Lattice Modal */}
        {showCreateModal && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
            <Card className="w-full max-w-md">
              <CardHeader>
                <CardTitle>Create New Lattice</CardTitle>
                <CardDescription>
                  Configure your new computational lattice
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="lattice-name">Name</Label>
                  <Input
                    id="lattice-name"
                    placeholder="Enter lattice name"
                    value={newLatticeConfig.name}
                    onChange={(e) => setNewLatticeConfig({
                      ...newLatticeConfig,
                      name: e.target.value
                    })}
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="lattice-type">Type</Label>
                  <Select
                    value={newLatticeConfig.type}
                    onValueChange={(value) => setNewLatticeConfig({
                      ...newLatticeConfig,
                      type: value
                    })}
                  >
                    <SelectTrigger>
                      <SelectValue placeholder="Select type" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="compute">Compute</SelectItem>
                      <SelectItem value="storage">Storage</SelectItem>
                      <SelectItem value="hybrid">Hybrid</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="lattice-region">Region</Label>
                  <Select
                    value={newLatticeConfig.region}
                    onValueChange={(value) => setNewLatticeConfig({
                      ...newLatticeConfig,
                      region: value
                    })}
                  >
                    <SelectTrigger>
                      <SelectValue placeholder="Select region" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="us-east-1">US East (N. Virginia)</SelectItem>
                      <SelectItem value="us-west-2">US West (Oregon)</SelectItem>
                      <SelectItem value="eu-west-1">Europe (Ireland)</SelectItem>
                      <SelectItem value="ap-southeast-1">Asia Pacific (Singapore)</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="lattice-size">Size</Label>
                  <Select
                    value={newLatticeConfig.size}
                    onValueChange={(value) => setNewLatticeConfig({
                      ...newLatticeConfig,
                      size: value,
                      nodes: value === 'small' ? 4 : value === 'medium' ? 8 : value === 'large' ? 16 : 32
                    })}
                  >
                    <SelectTrigger>
                      <SelectValue placeholder="Select size" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="small">Small (4 nodes)</SelectItem>
                      <SelectItem value="medium">Medium (8 nodes)</SelectItem>
                      <SelectItem value="large">Large (16 nodes)</SelectItem>
                      <SelectItem value="extra-large">Extra Large (32 nodes)</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="lattice-nodes">Custom Node Count</Label>
                  <Input
                    id="lattice-nodes"
                    type="number"
                    min="1"
                    max="100"
                    value={newLatticeConfig.nodes}
                    onChange={(e) => setNewLatticeConfig({
                      ...newLatticeConfig,
                      nodes: parseInt(e.target.value) || 4
                    })}
                  />
                </div>
              </CardContent>
              <div className="flex justify-end space-x-2 p-6">
                <Button
                  variant="outline"
                  onClick={() => setShowCreateModal(false)}
                  disabled={isLoading}
                >
                  Cancel
                </Button>
                <Button
                  onClick={handleCreateLattice}
                  disabled={isLoading || !newLatticeConfig.name}
                >
                  {isLoading ? 'Creating...' : 'Create Lattice'}
                </Button>
              </div>
            </Card>
          </div>
        )}
      </div>
    </div>
  )
}