const Session = require('../models/Session');
const config = require('../config/auth.config');
const logger = require('../utils/logger');

class SessionService {
  /**
   * Create new session or reuse existing one from same device
   */
  async createSession(userId, refreshToken, deviceInfo, provider = 'local', providerTokens = null) {
    try {
      const expiresAt = new Date(Date.now() + this.parseExpiry(config.jwt.refreshTokenExpiry));

      // Option 1: Single session per user (invalidate all others)
      if (config.session.singleSessionPerUser) {
        await this.invalidateAllUserSessions(userId);
        
        const session = await Session.create({
          userId,
          refreshToken,
          refreshTokenHash: Session.hashToken(refreshToken),
          deviceInfo,
          provider,
          providerTokens,
          expiresAt,
          metadata: {
            loginMethod: provider,
            loginAt: new Date()
          }
        });

        logger.logAuthEvent('SESSION_CREATED_SINGLE', {
          userId,
          sessionId: session._id,
          provider,
          deviceInfo: deviceInfo.userAgent
        });

        return session;
      }

      // Option 2: Reuse session from same device
      if (config.session.reuseDeviceSession) {
        const existingSession = await Session.findOne({
          userId,
          isActive: true,
          'deviceInfo.userAgent': deviceInfo.userAgent,
          'deviceInfo.ip': deviceInfo.ip,
          expiresAt: { $gt: new Date() }
        });

        if (existingSession) {
          existingSession.refreshToken = refreshToken;
          existingSession.refreshTokenHash = Session.hashToken(refreshToken);
          existingSession.lastActivity = new Date();
          existingSession.expiresAt = expiresAt;
          existingSession.providerTokens = providerTokens;
          existingSession.metadata.loginAt = new Date();

          await existingSession.save();

          logger.logAuthEvent('SESSION_REUSED', {
            userId,
            sessionId: existingSession._id,
            provider,
            deviceInfo: deviceInfo.userAgent
          });

          return existingSession;
        }
      }

      // Option 3: Create new session (with limit enforcement)
      await this.enforceSessionLimit(userId);
      
      const session = await Session.create({
        userId,
        refreshToken,
        refreshTokenHash: Session.hashToken(refreshToken),
        deviceInfo,
        provider,
        providerTokens,
        expiresAt,
        metadata: {
          loginMethod: provider,
          loginAt: new Date()
        }
      });

      logger.logAuthEvent('SESSION_CREATED', {
        userId,
        sessionId: session._id,
        provider,
        deviceInfo: deviceInfo.userAgent
      });

      return session;
    } catch (error) {
      logger.error('Failed to create session', { error: error.message, userId });
      throw error;
    }
  }

  /**
   * Find session by refresh token
   */
  async findSessionByRefreshToken(refreshToken) {
    const tokenHash = Session.hashToken(refreshToken);
    
    const session = await Session.findOne({
      refreshTokenHash: tokenHash,
      isActive: true,
      expiresAt: { $gt: new Date() }
    }).populate('userId', 'email roles');

    if (!session) {
      logger.logSecurityEvent('INVALID_REFRESH_TOKEN_ATTEMPT', {
        tokenHash: tokenHash.substring(0, 10)
      });
      return null;
    }

    // Check inactivity timeout
    const inactiveTime = Date.now() - session.lastActivity.getTime();
    if (inactiveTime > config.session.inactivityTimeout) {
      await this.invalidateSession(session._id);
      logger.logSecurityEvent('SESSION_EXPIRED_INACTIVITY', {
        sessionId: session._id,
        userId: session.userId
      });
      return null;
    }

    return session;
  }

  /**
   * Update session activity
   */
  async updateSessionActivity(sessionId) {
    await Session.findByIdAndUpdate(sessionId, {
      lastActivity: new Date()
    });
  }

  /**
   * Invalidate session
   */
  async invalidateSession(sessionId) {
    const result = await Session.findByIdAndUpdate(sessionId, {
      isActive: false
    });

    if (result) {
      logger.logAuthEvent('SESSION_INVALIDATED', {
        sessionId,
        userId: result.userId
      });
    }

    return result;
  }

  /**
   * Invalidate all user sessions
   */
  async invalidateAllUserSessions(userId) {
    const result = await Session.updateMany(
      { userId, isActive: true },
      { isActive: false }
    );

    logger.logAuthEvent('ALL_SESSIONS_INVALIDATED', {
      userId,
      count: result.modifiedCount
    });

    return result;
  }

  /**
   * Enforce session limit per user
   */
  async enforceSessionLimit(userId) {
    const activeSessions = await Session.find({
      userId,
      isActive: true,
      expiresAt: { $gt: new Date() }
    }).sort({ lastActivity: -1 });

    if (activeSessions.length >= config.session.maxActiveSessions) {
      // Remove oldest sessions
      const sessionsToRemove = activeSessions.slice(config.session.maxActiveSessions - 1);
      const sessionIds = sessionsToRemove.map(s => s._id);
      
      await Session.updateMany(
        { _id: { $in: sessionIds } },
        { isActive: false }
      );

      logger.logAuthEvent('SESSION_LIMIT_ENFORCED', {
        userId,
        removedCount: sessionIds.length
      });
    }
  }

  /**
   * Clean up expired sessions
   */
  async cleanupExpiredSessions() {
    const result = await Session.deleteMany({
      expiresAt: { $lt: new Date() }
    });

    if (result.deletedCount > 0) {
      logger.info('Expired sessions cleaned up', { count: result.deletedCount });
    }
    
    return result;
  }

  /**
   * Get user active sessions
   */
  async getUserSessions(userId) {
    return await Session.find({
      userId,
      isActive: true,
      expiresAt: { $gt: new Date() }
    }).sort({ lastActivity: -1 });
  }

  /**
   * Parse expiry string to milliseconds
   */
  parseExpiry(expiry) {
    const units = {
      s: 1000,
      m: 60 * 1000,
      h: 60 * 60 * 1000,
      d: 24 * 60 * 60 * 1000
    };
    const match = expiry.match(/^(\d+)([smhd])$/);
    if (!match) throw new Error('Invalid expiry format');
    return parseInt(match[1]) * units[match[2]];
  }
}

module.exports = new SessionService();