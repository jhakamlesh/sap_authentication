const winston = require('winston');
const path = require('path');
const appInsights = require('applicationinsights');

// Initialize Application Insights if connection string is provided
if (process.env.APPLICATIONINSIGHTS_CONNECTION_STRING) {
  try {
    appInsights.setup(process.env.APPLICATIONINSIGHTS_CONNECTION_STRING)
      .setAutoDependencyCorrelation(true)
      .setAutoCollectRequests(true)
      .setAutoCollectPerformance(true, true)
      .setAutoCollectExceptions(true)
      .setAutoCollectDependencies(true)
      .setAutoCollectConsole(true, false)
      .setUseDiskRetryCaching(true)
      .setSendLiveMetrics(true)
      .setDistributedTracingMode(appInsights.DistributedTracingModes.AI_AND_W3C)
      .start();
  } catch (error) {
    console.error('Failed to initialize Application Insights:', error.message);
  }
}

// Custom format to safely enumerate error properties
const enumerateErrorFormat = winston.format((info) => {
  if (info instanceof Error) {
    return Object.assign({}, info, {
      message: info.message,
      stack: info.stack,
      name: info.name,
      code: info.code,
      ...info
    });
  }
  return info;
});

// Determine log level based on environment
const getLogLevel = () => {
  const env = process.env.NODE_ENV || 'development';
  return env === 'production' ? 'info' :
    env === 'test' ? 'error' : 'debug';
};

// Application Insights Transport
class ApplicationInsightsTransport extends winston.Transport {
  constructor(opts) {
    super(opts);
    this.name = 'applicationInsights';
    this.client = appInsights.defaultClient;
  }

  log(info, callback) {
    setImmediate(() => {
      this.emit('logged', info);
    });

    if (!this.client) {
      return callback();
    }

    const { level, message, timestamp, requestId, userId, sessionId, ...meta } = info;

    // Map winston levels to AI severity
    const severityMap = {
      error: 3, // Error
      warn: 2,  // Warning
      info: 1,  // Information
      debug: 0, // Verbose
    };

    const properties = {
      level,
      requestId,
      userId,
      sessionId,
      timestamp,
      ...meta
    };

    // Track different event types
    if (info.event) {
      // Custom events for auth and security
      this.client.trackEvent({
        name: info.event,
        properties: {
          ...properties,
          message
        }
      });
    } else if (level === 'error') {
      // Track errors/exceptions
      const error = info.stack ? new Error(message) : null;
      if (error) {
        error.stack = info.stack;
      }
      
      this.client.trackException({
        exception: error || new Error(message),
        properties,
        severityLevel: severityMap[level] || 3
      });
    } else {
      // Track as trace
      this.client.trackTrace({
        message,
        severity: severityMap[level] || 1,
        properties
      });
    }

    // Track custom metrics if present
    if (info.metric) {
      this.client.trackMetric({
        name: info.metric.name,
        value: info.metric.value,
        properties
      });
    }

    callback();
  }
}

// Configure transports based on environment
const getTransports = () => {
  const transports = [];
  const env = process.env.NODE_ENV || 'development';

  // Console transport with appropriate formatting
  if (env !== 'production') {
    transports.push(
      new winston.transports.Console({
        stderrLevels: ['error'],
        format: winston.format.combine(
          winston.format.colorize(),
          winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
          winston.format.printf(({ level, message, timestamp, ...meta }) => {
            let metaStr = '';
            const filteredMeta = { ...meta };
            delete filteredMeta.service;
            delete filteredMeta.environment;
            
            if (Object.keys(filteredMeta).length) {
              metaStr = '\n' + JSON.stringify(filteredMeta, null, 2);
            }
            return `${timestamp} [${level}]: ${message}${metaStr}`;
          })
        )
      })
    );
  } else {
    // Production: uncolorized console output
    transports.push(
      new winston.transports.Console({
        stderrLevels: ['error'],
        format: winston.format.combine(
          winston.format.timestamp(),
          winston.format.json()
        )
      })
    );
  }

  // File transports for production and staging
  if (env === 'production' || env === 'staging') {
    // Error log file
    transports.push(
      new winston.transports.File({
        filename: path.join(process.cwd(), 'logs', 'error.log'),
        level: 'error',
        maxsize: 10485760, // 10MB
        maxFiles: 5,
        format: winston.format.combine(
          winston.format.timestamp(),
          winston.format.json()
        )
      })
    );

    // Auth-specific log file
    transports.push(
      new winston.transports.File({
        filename: path.join(process.cwd(), 'logs', 'auth.log'),
        maxsize: 10485760, // 10MB
        maxFiles: 5,
        format: winston.format.combine(
          winston.format.timestamp(),
          winston.format.json()
        ),
        level: 'info'
      })
    );

    // Combined log file
    transports.push(
      new winston.transports.File({
        filename: path.join(process.cwd(), 'logs', 'combined.log'),
        maxsize: 10485760, // 10MB
        maxFiles: 5,
        format: winston.format.combine(
          winston.format.timestamp(),
          winston.format.json()
        )
      })
    );
  }

  // Add Application Insights transport if configured
  if (process.env.APPLICATIONINSIGHTS_CONNECTION_STRING && appInsights.defaultClient) {
    transports.push(new ApplicationInsightsTransport({ level: 'info' }));
  }

  return transports;
};

// Create the logger instance
const logger = winston.createLogger({
  level: getLogLevel(),
  format: winston.format.combine(
    enumerateErrorFormat(),
    winston.format.splat(),
    winston.format.errors({ stack: true })
  ),
  transports: getTransports(),
  exitOnError: false,
  defaultMeta: {
    service: process.env.SERVICE_NAME || 'auth-service',
    environment: process.env.NODE_ENV || 'development',
    version: process.env.APP_VERSION || '1.0.0'
  }
});

// Handle uncaught exceptions and rejections
if (process.env.NODE_ENV === 'production' || process.env.NODE_ENV === 'staging') {
  logger.exceptions.handle(
    new winston.transports.File({
      filename: path.join(process.cwd(), 'logs', 'exceptions.log'),
      maxsize: 10485760,
      maxFiles: 5
    })
  );

  logger.rejections.handle(
    new winston.transports.File({
      filename: path.join(process.cwd(), 'logs', 'rejections.log'),
      maxsize: 10485760,
      maxFiles: 5
    })
  );
}

// Add request ID to logs (useful for request tracing)
logger.addRequestId = (requestId) => {
  return logger.child({ requestId });
};

// Add user context to logs
logger.addUserContext = (userId, sessionId) => {
  return logger.child({ userId, sessionId });
};

// Enhanced auth event logger with Application Insights integration
logger.logAuthEvent = function(event, data = {}) {
  const logData = {
    event,
    eventType: 'AUTH',
    timestamp: new Date().toISOString(),
    ...data
  };

  this.info('AUTH_EVENT', logData);

  // Track custom event in Application Insights
  if (appInsights.defaultClient) {
    appInsights.defaultClient.trackEvent({
      name: `Auth_${event}`,
      properties: logData
    });
  }
};

// Enhanced security event logger
logger.logSecurityEvent = function(event, data = {}) {
  const logData = {
    event,
    eventType: 'SECURITY',
    severity: 'HIGH',
    timestamp: new Date().toISOString(),
    ...data
  };

  this.warn('SECURITY_EVENT', logData);

  // Track security event in Application Insights with high severity
  if (appInsights.defaultClient) {
    appInsights.defaultClient.trackEvent({
      name: `Security_${event}`,
      properties: logData
    });

    // Also track as exception for critical security events
    if (data.critical) {
      appInsights.defaultClient.trackException({
        exception: new Error(`Security Event: ${event}`),
        properties: logData,
        severityLevel: 3 // Error
      });
    }
  }
};

// Performance tracking
logger.logPerformance = function(operation, duration, metadata = {}) {
  const logData = {
    operation,
    duration,
    ...metadata
  };

  this.info('PERFORMANCE', logData);

  if (appInsights.defaultClient) {
    appInsights.defaultClient.trackMetric({
      name: `Performance_${operation}`,
      value: duration,
      properties: metadata
    });
  }
};

// Track custom metrics
logger.trackMetric = function(name, value, properties = {}) {
  if (appInsights.defaultClient) {
    appInsights.defaultClient.trackMetric({
      name,
      value,
      properties: {
        service: this.defaultMeta.service,
        environment: this.defaultMeta.environment,
        ...properties
      }
    });
  }
};

// Track dependencies (external API calls, DB queries)
logger.trackDependency = function(name, command, duration, success, properties = {}) {
  if (appInsights.defaultClient) {
    appInsights.defaultClient.trackDependency({
      name,
      data: command,
      duration,
      success,
      dependencyTypeName: properties.type || 'HTTP',
      properties
    });
  }
};

// Flush Application Insights before shutdown
logger.flush = async () => {
  if (appInsights.defaultClient) {
    return new Promise((resolve) => {
      appInsights.defaultClient.flush({
        callback: resolve
      });
    });
  }
};

module.exports = logger;