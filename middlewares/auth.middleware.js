const tokenService = require('../services/token.service');
const sessionService = require('../services/session.service');
const logger = require('../utils/logger');
const crypto = require('crypto');

/**
 * Extract token from request
 */
function extractToken(req) {
  // Check Authorization header
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.substring(7);
  }

  // Check query parameter (for Socket.io compatibility)
  if (req.query && req.query.token) {
    return req.query.token;
  }

  // Check cookies
  if (req.cookies && req.cookies.accessToken) {
    return req.cookies.accessToken;
  }

  return null;
}

/**
 * Main authentication middleware
 */
async function authenticateToken(req, res, next) {
  const startTime = Date.now();
  const requestId = req.id || crypto.randomUUID();
  req.id = requestId;

  // Create request-scoped logger
  req.logger = logger.addRequestId(requestId);

  const token = extractToken(req);

  if (!token) {
    logger.logSecurityEvent('MISSING_TOKEN', {
      requestId,
      ip: req.ip,
      path: req.path,
      userAgent: req.get('user-agent')
    });

    return res.status(401).json({
      success: false,
      error: 'Authentication required',
      code: 'NO_TOKEN'
    });
  }

  // Verify token signature and claims
  const verification = tokenService.verifyAccessToken(token);

  if (!verification.valid) {
    logger.logSecurityEvent('INVALID_TOKEN', {
      requestId,
      ip: req.ip,
      path: req.path,
      error: verification.error,
      expired: verification.expired
    });

    return res.status(401).json({
      success: false,
      error: verification.expired ? 'Token expired' : 'Invalid token',
      code: verification.expired ? 'TOKEN_EXPIRED' : 'INVALID_TOKEN'
    });
  }

  const { decoded } = verification;

  // Verify session is still active
  try {
    const session = await sessionService.findSessionByRefreshToken(decoded.sessionId);
    
    if (!session) {
      logger.logSecurityEvent('INVALID_SESSION', {
        requestId,
        userId: decoded.sub,
        sessionId: decoded.sessionId,
        ip: req.ip
      });

      return res.status(401).json({
        success: false,
        error: 'Session invalid or expired',
        code: 'INVALID_SESSION'
      });
    }

    // Update session activity
    await sessionService.updateSessionActivity(session._id);

    // Attach user info to request
    req.user = {
      id: decoded.sub,
      email: decoded.email,
      roles: decoded.roles,
      sessionId: decoded.sessionId
    };

    req.session = session;

    // Update logger with user context
    req.logger = logger.addUserContext(req.user.id, decoded.sessionId);

    const duration = Date.now() - startTime;
    logger.logPerformance('AUTH_MIDDLEWARE', duration, {
      requestId,
      userId: req.user.id,
      path: req.path
    });

    next();
  } catch (error) {
    req.logger.error('Authentication middleware error', {
      requestId,
      error: error.message,
      stack: error.stack
    });

    return res.status(500).json({
      success: false,
      error: 'Authentication failed',
      code: 'AUTH_ERROR'
    });
  }
}

/**
 * Optional authentication (doesn't fail if no token)
 */
async function optionalAuth(req, res, next) {
  const token = extractToken(req);

  if (!token) {
    return next();
  }

  try {
    const verification = tokenService.verifyAccessToken(token);
    if (verification.valid) {
      req.user = {
        id: verification.decoded.sub,
        email: verification.decoded.email,
        roles: verification.decoded.roles,
        sessionId: verification.decoded.sessionId
      };
    }
  } catch (error) {
    logger.debug('Optional auth failed', { error: error.message });
  }

  next();
}

/**
 * Role-based authorization middleware
 */
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: 'Authentication required',
        code: 'NO_AUTH'
      });
    }

    const hasRole = roles.some(role => req.user.roles.includes(role));

    if (!hasRole) {
      logger.logSecurityEvent('INSUFFICIENT_PERMISSIONS', {
        userId: req.user.id,
        requiredRoles: roles,
        userRoles: req.user.roles,
        path: req.path
      });

      return res.status(403).json({
        success: false,
        error: 'Insufficient permissions',
        code: 'FORBIDDEN'
      });
    }

    next();
  };
}

/**
 * Rate limiting middleware
 */
const rateLimitStore = new Map();

function rateLimit(maxRequests = 100, windowMs = 60000) {
  return (req, res, next) => {
    const key = req.user ? req.user.id : req.ip;
    const now = Date.now();
    
    if (!rateLimitStore.has(key)) {
      rateLimitStore.set(key, { count: 1, resetTime: now + windowMs });
      return next();
    }

    const record = rateLimitStore.get(key);

    if (now > record.resetTime) {
      record.count = 1;
      record.resetTime = now + windowMs;
      return next();
    }

    if (record.count >= maxRequests) {
      logger.logSecurityEvent('RATE_LIMIT_EXCEEDED', {
        key,
        ip: req.ip,
        path: req.path
      });

      return res.status(429).json({
        success: false,
        error: 'Too many requests',
        code: 'RATE_LIMIT_EXCEEDED',
        retryAfter: Math.ceil((record.resetTime - now) / 1000)
      });
    }

    record.count++;
    next();
  };
}

module.exports = {
  authenticateToken,
  optionalAuth,
  requireRole,
  rateLimit,
  extractToken
};