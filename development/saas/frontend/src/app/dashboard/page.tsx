'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Progress } from '@/components/ui/progress';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import {
  BarChart, Bar, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer,
  PieChart, Pie, Cell, AreaChart, Area
} from 'recharts';
import {
  Cpu, Activity, Database, Users, DollarSign, TrendingUp, Clock,
  Server, AlertCircle, CheckCircle, XCircle, LogOut, Settings, Bell
} from 'lucide-react';

export default function DashboardPage() {
  const router = useRouter();
  const [isLoading, setIsLoading] = useState(false);
  const [userInfo, setUserInfo] = useState({
    name: 'John Doe',
    company: 'Acme Corp',
    plan: 'Professional',
    email: 'john@acme.com'
  });

  // Mock data for charts
  const apiUsageData = [
    { month: 'Jan', calls: 2400, limit: 10000 },
    { month: 'Feb', calls: 1398, limit: 10000 },
    { month: 'Mar', calls: 9800, limit: 10000 },
    { month: 'Apr', calls: 3908, limit: 10000 },
    { month: 'May', calls: 4800, limit: 10000 },
    { month: 'Jun', calls: 6832, limit: 10000 }
  ];

  const performanceData = [
    { time: '00:00', latency: 120, throughput: 850 },
    { time: '04:00', latency: 98, throughput: 920 },
    { time: '08:00', latency: 145, throughput: 780 },
    { time: '12:00', latency: 189, throughput: 650 },
    { time: '16:00', latency: 134, throughput: 820 },
    { time: '20:00', latency: 102, throughput: 890 }
  ];

  const planUsageData = [
    { name: 'Free Users', value: 1247, color: '#8884d8' },
    { name: 'Starter Users', value: 423, color: '#82ca9d' },
    { name: 'Professional Users', value: 156, color: '#ffc658' },
    { name: 'Enterprise Users', value: 67, color: '#ff7300' }
  ];

  const revenueData = [
    { month: 'Jan', revenue: 12450, growth: 8.2 },
    { month: 'Feb', revenue: 13230, growth: 6.3 },
    { month: 'Mar', revenue: 15670, growth: 18.4 },
    { month: 'Apr', revenue: 16890, growth: 7.8 },
    { month: 'May', revenue: 18450, growth: 9.2 },
    { month: 'Jun', revenue: 19780, growth: 7.2 }
  ];

  const currentUsage = {
    apiCalls: 6832,
    limit: 10000,
    percentage: 68.32
  };

  const systemStatus = {
    api: 'operational',
    database: 'operational',
    cache: 'degraded',
    cdn: 'operational'
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    router.push('/login');
  };

  useEffect(() => {
    // Check if user is authenticated
    const token = localStorage.getItem('token');
    if (!token) {
      router.push('/login');
    }
  }, [router]);

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100 dark:from-slate-900 dark:to-slate-800">
      {/* Header */}
      <header className="border-b bg-white/50 dark:bg-slate-900/50 backdrop-blur-sm">
        <div className="flex h-16 items-center justify-between px-6">
          <div className="flex items-center space-x-4">
            <Cpu className="h-8 w-8 text-primary" />
            <h1 className="text-xl font-semibold">Catalytic Computing</h1>
          </div>
          <div className="flex items-center space-x-4">
            <Button variant="ghost" size="sm">
              <Bell className="h-4 w-4" />
            </Button>
            <Button variant="ghost" size="sm">
              <Settings className="h-4 w-4" />
            </Button>
            <Button variant="ghost" size="sm" onClick={handleLogout}>
              <LogOut className="h-4 w-4" />
              Logout
            </Button>
          </div>
        </div>
      </header>

      <div className="flex">
        {/* Sidebar */}
        <aside className="w-64 border-r bg-white/50 dark:bg-slate-900/50 backdrop-blur-sm p-6">
          <div className="space-y-6">
            <div>
              <h3 className="text-sm font-medium text-muted-foreground mb-2">Account</h3>
              <div className="space-y-1">
                <p className="text-sm font-medium">{userInfo.name}</p>
                <p className="text-sm text-muted-foreground">{userInfo.company}</p>
                <Badge variant="secondary">{userInfo.plan}</Badge>
              </div>
            </div>

            <div>
              <h3 className="text-sm font-medium text-muted-foreground mb-2">Quick Stats</h3>
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm">API Calls</span>
                  <span className="text-sm font-medium">{currentUsage.apiCalls.toLocaleString()}</span>
                </div>
                <Progress value={currentUsage.percentage} className="h-2" />
                <p className="text-xs text-muted-foreground">
                  {currentUsage.apiCalls.toLocaleString()} / {currentUsage.limit.toLocaleString()} calls
                </p>
              </div>
            </div>

            <div>
              <h3 className="text-sm font-medium text-muted-foreground mb-2">System Status</h3>
              <div className="space-y-2">
                {Object.entries(systemStatus).map(([service, status]) => (
                  <div key={service} className="flex items-center justify-between">
                    <span className="text-sm capitalize">{service}</span>
                    {status === 'operational' ? (
                      <CheckCircle className="h-4 w-4 text-green-500" />
                    ) : status === 'degraded' ? (
                      <AlertCircle className="h-4 w-4 text-yellow-500" />
                    ) : (
                      <XCircle className="h-4 w-4 text-red-500" />
                    )}
                  </div>
                ))}
              </div>
            </div>
          </div>
        </aside>

        {/* Main Content */}
        <main className="flex-1 p-6">
          <div className="mb-6">
            <h2 className="text-2xl font-bold tracking-tight">Dashboard</h2>
            <p className="text-muted-foreground">
              Monitor your API usage, performance metrics, and system health.
            </p>
          </div>

          {/* Key Metrics Cards */}
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4 mb-6">
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Total API Calls</CardTitle>
                <Activity className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{currentUsage.apiCalls.toLocaleString()}</div>
                <p className="text-xs text-muted-foreground">
                  +12% from last month
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Avg Response Time</CardTitle>
                <Clock className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">134ms</div>
                <p className="text-xs text-muted-foreground">
                  -8ms from last month
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Success Rate</CardTitle>
                <TrendingUp className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">99.8%</div>
                <p className="text-xs text-muted-foreground">
                  +0.2% from last month
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Data Processed</CardTitle>
                <Database className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">2.4TB</div>
                <p className="text-xs text-muted-foreground">
                  +23% from last month
                </p>
              </CardContent>
            </Card>
          </div>

          {/* Charts and Analytics */}
          <Tabs defaultValue="usage" className="space-y-4">
            <TabsList className="grid w-full grid-cols-4">
              <TabsTrigger value="usage">API Usage</TabsTrigger>
              <TabsTrigger value="performance">Performance</TabsTrigger>
              <TabsTrigger value="users">Users</TabsTrigger>
              <TabsTrigger value="revenue">Revenue</TabsTrigger>
            </TabsList>

            <TabsContent value="usage" className="space-y-4">
              <div className="grid gap-4 md:grid-cols-1">
                <Card>
                  <CardHeader>
                    <CardTitle>API Calls Over Time</CardTitle>
                    <CardDescription>
                      Monthly API usage vs. plan limits
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <ResponsiveContainer width="100%" height={350}>
                      <BarChart data={apiUsageData}>
                        <CartesianGrid strokeDasharray="3 3" />
                        <XAxis dataKey="month" />
                        <YAxis />
                        <Tooltip />
                        <Legend />
                        <Bar dataKey="calls" fill="#8884d8" name="API Calls" />
                        <Bar dataKey="limit" fill="#e0e0e0" name="Plan Limit" />
                      </BarChart>
                    </ResponsiveContainer>
                  </CardContent>
                </Card>
              </div>
            </TabsContent>

            <TabsContent value="performance" className="space-y-4">
              <div className="grid gap-4 md:grid-cols-1">
                <Card>
                  <CardHeader>
                    <CardTitle>Performance Metrics</CardTitle>
                    <CardDescription>
                      Response latency and throughput over 24 hours
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <ResponsiveContainer width="100%" height={350}>
                      <LineChart data={performanceData}>
                        <CartesianGrid strokeDasharray="3 3" />
                        <XAxis dataKey="time" />
                        <YAxis yAxisId="left" />
                        <YAxis yAxisId="right" orientation="right" />
                        <Tooltip />
                        <Legend />
                        <Line
                          yAxisId="left"
                          type="monotone"
                          dataKey="latency"
                          stroke="#8884d8"
                          name="Latency (ms)"
                        />
                        <Line
                          yAxisId="right"
                          type="monotone"
                          dataKey="throughput"
                          stroke="#82ca9d"
                          name="Throughput (req/min)"
                        />
                      </LineChart>
                    </ResponsiveContainer>
                  </CardContent>
                </Card>
              </div>
            </TabsContent>

            <TabsContent value="users" className="space-y-4">
              <div className="grid gap-4 md:grid-cols-2">
                <Card>
                  <CardHeader>
                    <CardTitle>Users by Plan</CardTitle>
                    <CardDescription>
                      Distribution of users across subscription plans
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <ResponsiveContainer width="100%" height={300}>
                      <PieChart>
                        <Pie
                          data={planUsageData}
                          cx="50%"
                          cy="50%"
                          labelLine={false}
                          label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                          outerRadius={80}
                          fill="#8884d8"
                          dataKey="value"
                        >
                          {planUsageData.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={entry.color} />
                          ))}
                        </Pie>
                        <Tooltip />
                      </PieChart>
                    </ResponsiveContainer>
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader>
                    <CardTitle>User Metrics</CardTitle>
                    <CardDescription>
                      Key user engagement statistics
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-medium">Total Users</span>
                      <span className="text-2xl font-bold">1,893</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-medium">Active Users (30d)</span>
                      <span className="text-2xl font-bold">1,247</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-medium">New Users (7d)</span>
                      <span className="text-2xl font-bold">23</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-medium">Churn Rate</span>
                      <span className="text-2xl font-bold">2.1%</span>
                    </div>
                  </CardContent>
                </Card>
              </div>
            </TabsContent>

            <TabsContent value="revenue" className="space-y-4">
              <div className="grid gap-4 md:grid-cols-1">
                <Card>
                  <CardHeader>
                    <CardTitle>Revenue Growth</CardTitle>
                    <CardDescription>
                      Monthly recurring revenue and growth rate
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <ResponsiveContainer width="100%" height={350}>
                      <AreaChart data={revenueData}>
                        <CartesianGrid strokeDasharray="3 3" />
                        <XAxis dataKey="month" />
                        <YAxis yAxisId="left" />
                        <YAxis yAxisId="right" orientation="right" />
                        <Tooltip />
                        <Legend />
                        <Area
                          yAxisId="left"
                          type="monotone"
                          dataKey="revenue"
                          stroke="#8884d8"
                          fill="#8884d8"
                          fillOpacity={0.3}
                          name="Revenue ($)"
                        />
                        <Area
                          yAxisId="right"
                          type="monotone"
                          dataKey="growth"
                          stroke="#82ca9d"
                          fill="transparent"
                          name="Growth Rate (%)"
                        />
                      </AreaChart>
                    </ResponsiveContainer>
                  </CardContent>
                </Card>
              </div>
            </TabsContent>
          </Tabs>

          {/* Alerts and Notifications */}
          <div className="mt-6">
            <h3 className="text-lg font-semibold mb-4">Recent Alerts</h3>
            <div className="space-y-3">
              <Alert>
                <AlertCircle className="h-4 w-4" />
                <AlertDescription>
                  Cache service experiencing elevated response times. Monitoring closely.
                </AlertDescription>
              </Alert>
              <Alert variant="default">
                <CheckCircle className="h-4 w-4" />
                <AlertDescription>
                  System maintenance completed successfully. All services operational.
                </AlertDescription>
              </Alert>
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}
