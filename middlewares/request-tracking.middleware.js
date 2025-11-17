const logger = require('../utils/logger');
const crypto = require('crypto');

/**
 * Request tracking middleware
 * Adds request ID and logs request/response
 */
function requestTracking(req, res, next) {
  // Generate or extract request ID
  const requestId = req.headers['x-request-id'] || 
                    req.headers['x-correlation-id'] || 
                    crypto.randomUUID();
  
  req.id = requestId;
  res.setHeader('X-Request-ID', requestId);

  // Create request-scoped logger
  req.logger = logger.addRequestId(requestId);

  // Log incoming request
  req.logger.info('Incoming request', {
    method: req.method,
    path: req.path,
    query: req.query,
    ip: req.ip,
    userAgent: req.get('user-agent')
  });

  // Track request start time
  req.startTime = Date.now();

  // Capture response
  const originalSend = res.send;
  res.send = function(data) {
    const duration = Date.now() - req.startTime;
    
    req.logger.info('Outgoing response', {
      method: req.method,
      path: req.path,
      statusCode: res.statusCode,
      duration: `${duration}ms`
    });

    // Track performance metric
    logger.logPerformance(`${req.method}_${req.path}`, duration, {
      requestId,
      statusCode: res.statusCode,
      userId: req.user?.id
    });

    res.send = originalSend;
    return originalSend.call(this, data);
  };

  next();
}

/**
 * Error tracking middleware
 */
function errorTracking(err, req, res, next) {
  const requestId = req.id || crypto.randomUUID();
  
  // Log error with full context
  logger.error('Request error', {
    requestId,
    error: err.message,
    stack: err.stack,
    method: req.method,
    path: req.path,
    userId: req.user?.id,
    ip: req.ip
  });

  // Determine status code
  const statusCode = err.statusCode || err.status || 500;
  
  res.status(statusCode).json({
    success: false,
    error: process.env.NODE_ENV === 'production' 
      ? 'Internal server error' 
      : err.message,
    code: err.code || 'INTERNAL_ERROR',
    requestId
  });
}

module.exports = {
  requestTracking,
  errorTracking
};