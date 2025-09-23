// Enhanced logging system for MCP servers

class Logger {
  constructor(name, level = 'INFO') {
    this.name = name;
    this.level = this.parseLevel(level);
    this.colors = {
      DEBUG: '\x1b[36m', // Cyan
      INFO: '\x1b[32m',  // Green
      WARN: '\x1b[33m',  // Yellow
      ERROR: '\x1b[31m', // Red
      RESET: '\x1b[0m'   // Reset
    };
  }

  parseLevel(level) {
    const levels = { DEBUG: 0, INFO: 1, WARN: 2, ERROR: 3 };
    return levels[level.toUpperCase()] ?? 1;
  }

  formatMessage(level, message, data = null) {
    const timestamp = new Date().toISOString();
    const color = this.colors[level] || '';
    const reset = this.colors.RESET;
    
    let logLine = `${color}[${timestamp}] ${level.padEnd(5)} [${this.name}] ${message}${reset}`;
    
    if (data) {
      if (typeof data === 'object') {
        logLine += `\n${JSON.stringify(data, null, 2)}`;
      } else {
        logLine += ` ${data}`;
      }
    }
    
    return logLine;
  }

  debug(message, data) {
    if (this.level <= 0) {
      console.error(this.formatMessage('DEBUG', message, data));
    }
  }

  info(message, data) {
    if (this.level <= 1) {
      console.error(this.formatMessage('INFO', message, data));
    }
  }

  warn(message, data) {
    if (this.level <= 2) {
      console.error(this.formatMessage('WARN', message, data));
    }
  }

  error(message, data) {
    if (this.level <= 3) {
      console.error(this.formatMessage('ERROR', message, data));
    }
  }

  // Performance timing
  time(label) {
    console.time(`[${this.name}] ${label}`);
  }

  timeEnd(label) {
    console.timeEnd(`[${this.name}] ${label}`);
  }

  // Method call logging
  logMethodCall(method, args, startTime) {
    const duration = Date.now() - startTime;
    this.debug(`${method} completed in ${duration}ms`, {
      arguments: args,
      duration: `${duration}ms`
    });
  }

  // Request/Response logging for MCP
  logMCPRequest(request) {
    this.info('MCP Request received', {
      method: request.method,
      id: request.id,
      params: request.params
    });
  }

  logMCPResponse(response, requestId) {
    this.info('MCP Response sent', {
      requestId,
      success: !response.error,
      error: response.error?.message
    });
  }

  logMCPError(error, context = {}) {
    this.error('MCP Error occurred', {
      error: error.message,
      stack: error.stack,
      context
    });
  }
}

// Create logger instances
export function createLogger(name, level = process.env.LOG_LEVEL || 'INFO') {
  return new Logger(name, level);
}

// Default logger
export const logger = createLogger('MCP-Server');

// Performance decorator
export function logPerformance(target, propertyName, descriptor) {
  const originalMethod = descriptor.value;
  
  descriptor.value = function(...args) {
    const startTime = Date.now();
    const logger = this.logger || createLogger(this.constructor.name);
    
    try {
      const result = originalMethod.apply(this, args);
      
      if (result instanceof Promise) {
        return result.then(res => {
          logger.logMethodCall(propertyName, args, startTime);
          return res;
        }).catch(err => {
          logger.error(`${propertyName} failed after ${Date.now() - startTime}ms`, err);
          throw err;
        });
      } else {
        logger.logMethodCall(propertyName, args, startTime);
        return result;
      }
    } catch (error) {
      logger.error(`${propertyName} failed after ${Date.now() - startTime}ms`, error);
      throw error;
    }
  };
  
  return descriptor;
}

export { Logger };