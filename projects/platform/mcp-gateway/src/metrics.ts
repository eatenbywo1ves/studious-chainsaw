/**
 * Metrics Collector - Collects and exposes gateway metrics
 */

export interface Metrics {
  requests: {
    total: number;
    success: number;
    failed: number;
    byMethod: Record<string, number>;
    byPath: Record<string, number>;
    byStatus: Record<number, number>;
  };
  latency: {
    min: number;
    max: number;
    avg: number;
    p50: number;
    p95: number;
    p99: number;
  };
  cache: {
    hits: number;
    misses: number;
    hitRate: number;
  };
  services: {
    registered: number;
    healthy: number;
    unhealthy: number;
  };
  uptime: number;
  timestamp: string;
}

export class MetricsCollector {
  private startTime: number;
  private requests: Map<string, any[]> = new Map();
  private latencies: number[] = [];
  private cacheHits: number = 0;
  private cacheMisses: number = 0;

  constructor() {
    this.startTime = Date.now();
  }

  recordRequest(
    method: string,
    path: string,
    status: number,
    duration: number
  ): void {
    const key = `${method}:${path}`;
    if (!this.requests.has(key)) {
      this.requests.set(key, []);
    }

    this.requests.get(key)!.push({
      status,
      duration,
      timestamp: Date.now()
    });

    this.latencies.push(duration);

    // Keep only last 10000 latencies for percentile calculation
    if (this.latencies.length > 10000) {
      this.latencies.shift();
    }
  }

  recordCacheHit(): void {
    this.cacheHits++;
  }

  recordCacheMiss(): void {
    this.cacheMisses++;
  }

  getSnapshot(): Metrics {
    const allRequests = Array.from(this.requests.values()).flat();
    const totalRequests = allRequests.length;
    const successRequests = allRequests.filter(r => r.status < 400).length;
    const failedRequests = totalRequests - successRequests;

    // Calculate request counts by method and path
    const byMethod: Record<string, number> = {};
    const byPath: Record<string, number> = {};
    const byStatus: Record<number, number> = {};

    this.requests.forEach((requests, key) => {
      const [method, path] = key.split(':');
      byMethod[method] = (byMethod[method] || 0) + requests.length;
      byPath[path] = (byPath[path] || 0) + requests.length;

      requests.forEach(r => {
        byStatus[r.status] = (byStatus[r.status] || 0) + 1;
      });
    });

    // Calculate latency percentiles
    const sortedLatencies = [...this.latencies].sort((a, b) => a - b);
    const latencyMetrics = this.calculateLatencyMetrics(sortedLatencies);

    // Calculate cache hit rate
    const totalCacheRequests = this.cacheHits + this.cacheMisses;
    const hitRate = totalCacheRequests > 0
      ? this.cacheHits / totalCacheRequests
      : 0;

    return {
      requests: {
        total: totalRequests,
        success: successRequests,
        failed: failedRequests,
        byMethod,
        byPath,
        byStatus
      },
      latency: latencyMetrics,
      cache: {
        hits: this.cacheHits,
        misses: this.cacheMisses,
        hitRate
      },
      services: {
        registered: 0, // To be updated from registry
        healthy: 0,
        unhealthy: 0
      },
      uptime: Date.now() - this.startTime,
      timestamp: new Date().toISOString()
    };
  }

  private calculateLatencyMetrics(sortedLatencies: number[]): Metrics['latency'] {
    if (sortedLatencies.length === 0) {
      return {
        min: 0,
        max: 0,
        avg: 0,
        p50: 0,
        p95: 0,
        p99: 0
      };
    }

    const sum = sortedLatencies.reduce((a, b) => a + b, 0);
    const avg = sum / sortedLatencies.length;

    return {
      min: sortedLatencies[0],
      max: sortedLatencies[sortedLatencies.length - 1],
      avg,
      p50: this.percentile(sortedLatencies, 0.5),
      p95: this.percentile(sortedLatencies, 0.95),
      p99: this.percentile(sortedLatencies, 0.99)
    };
  }

  private percentile(sortedArray: number[], percentile: number): number {
    const index = Math.ceil(sortedArray.length * percentile) - 1;
    return sortedArray[Math.max(0, index)];
  }

  reset(): void {
    this.requests.clear();
    this.latencies = [];
    this.cacheHits = 0;
    this.cacheMisses = 0;
  }
}