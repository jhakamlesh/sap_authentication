
const express = require('express');
const router = express.Router();
const passport = require('../strategies/sap.strategy');
const tokenService = require('../services/token.service');
const sessionService = require('../services/session.service');
const logger = require('../utils/logger');
const { authenticateToken } = require('../middlewares/auth.middleware');
const crypto = require('crypto');

// ============================================================================
// SAP OAuth Routes
// ============================================================================

/**
 * Initiate SAP OAuth flow
 * GET /auth/sap
 */
router.get('/sap', (req, res, next) => {
  logger.info('Initiating SAP OAuth flow');
  
  passport.authenticate('sap', {
    session: false,
    // Optional: pass additional parameters
    state: crypto.randomBytes(16).toString('hex')
  })(req, res, next);
});

/**
 * SAP OAuth callback
 * GET /auth/sap/callback
 */
router.get('/sap/callback',
  passport.authenticate('sap', {
    session: false,
    failureRedirect: '/auth/sap/error'
  }),
  async (req, res) => {
    try {
      const { user, providerTokens } = req.user;

      logger.info('SAP OAuth callback processing', {
        userId: user._id,
        email: user.email
      });

      // Generate your own JWT tokens
      const sessionId = crypto.randomUUID();
      const tokens = tokenService.generateTokenPair({
        userId: user._id.toString(),
        email: user.email,
        roles: user.roles,
        sessionId
      });

      // Store session with SAP tokens
      const deviceInfo = {
        userAgent: req.get('user-agent'),
        ip: req.ip,
        platform: req.get('sec-ch-ua-platform') || 'unknown',
        browser: req.get('sec-ch-ua') || 'unknown'
      };

      await sessionService.createSession(
        user._id,
        tokens.refreshToken,
        deviceInfo,
        'sap',
        providerTokens
      );

      logger.logAuthEvent('SAP_LOGIN_SUCCESS', {
        userId: user._id,
        email: user.email,
        sapId: user.sapId
      });

      // Redirect to frontend with tokens
      const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:3000';
      const redirectUrl = `${frontendUrl}/auth/callback?token=${tokens.accessToken}&refresh=${tokens.refreshToken}`;
      
      res.redirect(redirectUrl);
    } catch (error) {
      logger.error('SAP callback error', {
        error: error.message,
        stack: error.stack
      });
      
      const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:3000';
      res.redirect(`${frontendUrl}/login?error=auth_failed`);
    }
  }
);

/**
 * SAP OAuth error handler
 * GET /auth/sap/error
 */
router.get('/sap/error', (req, res) => {
  logger.error('SAP OAuth authentication failed');
  
  const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:3000';
  res.redirect(`${frontendUrl}/login?error=sap_auth_failed`);
});

/**
 * Refresh SAP tokens (internal use)
 */
async function refreshSAPToken(session) {
  const axios = require('axios');
  
  try {
    const decryptedTokens = session.getDecryptedTokens();
    
    if (!decryptedTokens || !decryptedTokens.refreshToken) {
      throw new Error('No SAP refresh token available');
    }

    logger.info('Refreshing SAP token', {
      sessionId: session._id
    });

    const response = await axios.post(process.env.SAP_TOKEN_URL, {
      grant_type: 'refresh_token',
      refresh_token: decryptedTokens.refreshToken,
      client_id: process.env.SAP_CLIENT_ID,
      client_secret: process.env.SAP_CLIENT_SECRET
    }, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    });

    const { access_token, refresh_token, expires_in, token_type } = response.data;

    // Update session with new tokens
    session.providerTokens = {
      accessToken: access_token,
      refreshToken: refresh_token || decryptedTokens.refreshToken,
      expiresAt: new Date(Date.now() + (expires_in * 1000)),
      tokenType: token_type || 'Bearer'
    };

    await session.save();

    logger.logAuthEvent('SAP_TOKEN_REFRESHED', {
      sessionId: session._id,
      userId: session.userId
    });

    return {
      accessToken: access_token,
      expiresAt: session.providerTokens.expiresAt
    };
  } catch (error) {
    logger.error('Failed to refresh SAP token', {
      error: error.message,
      sessionId: session._id,
      status: error.response?.status,
      data: error.response?.data
    });
    throw error;
  }
}

/**
 * Get SAP access token (with auto-refresh)
 * Helper function for making SAP API calls
 */
async function getSAPAccessToken(session) {
  const decryptedTokens = session.getDecryptedTokens();
  
  if (!decryptedTokens) {
    throw new Error('No SAP tokens available');
  }

  // Check if token is expired or will expire in next 5 minutes
  const expiryBuffer = 5 * 60 * 1000; // 5 minutes
  const isExpired = new Date(decryptedTokens.expiresAt).getTime() - Date.now() < expiryBuffer;

  if (isExpired) {
    logger.info('SAP token expired, refreshing', {
      sessionId: session._id
    });
    const refreshed = await refreshSAPToken(session);
    return refreshed.accessToken;
  }

  return decryptedTokens.accessToken;
}

// Export helper functions
module.exports = router;
module.exports.refreshSAPToken = refreshSAPToken;
module.exports.getSAPAccessToken = getSAPAccessToken;
