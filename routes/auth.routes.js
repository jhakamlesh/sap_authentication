// ============================================================================
// routes/auth.routes.js - Fixed OAuth State Management
// ============================================================================

const express = require('express');
const router = express.Router();
const passport = require('passport');
const axios = require('axios');
const tokenService = require('../services/token.service');
const sessionService = require('../services/session.service');
const logger = require('../utils/logger');
const { authenticateToken } = require('../middlewares/auth.middleware');
const crypto = require('crypto');

// In-memory store for OAuth state (for development)
// In production, use Redis or database
const oauthStateStore = new Map();

// Clean up old states (older than 10 minutes)
setInterval(() => {
  const tenMinutesAgo = Date.now() - 10 * 60 * 1000;
  for (const [state, data] of oauthStateStore.entries()) {
    if (data.timestamp < tenMinutesAgo) {
      oauthStateStore.delete(state);
    }
  }
}, 60000); // Every minute

// ============================================================================
// SAP OAuth Routes (Redirect Flow)
// ============================================================================

/**
 * Initiate SAP OAuth flow
 * GET /auth/sap
 */
router.get('/sap', (req, res, next) => {
  logger.info('Initiating SAP OAuth flow', {
    ip: req.ip,
    userAgent: req.get('user-agent'),
    sapConfig: {
      authorizationURL: process.env.SAP_AUTHORIZATION_URL,
      callbackURL: process.env.SAP_CALLBACK_URL,
      clientID: process.env.SAP_CLIENT_ID ? 'SET' : 'NOT SET',
      clientSecret: process.env.SAP_CLIENT_SECRET ? 'SET' : 'NOT SET'
    }
  });

  // Generate state and store it
  const state = crypto.randomBytes(16).toString('hex');
  oauthStateStore.set(state, {
    timestamp: Date.now(),
    ip: req.ip,
    userAgent: req.get('user-agent')
  });

  logger.info('OAuth state generated', { state });

  passport.authenticate('sap', {
    session: false, // Disable session, we'll use our own state management
    state: state
  })(req, res, next);
});

/**
 * SAP OAuth callback with state verification
 * GET /auth/sap/callback
 */
router.get('/sap/callback', async (req, res) => {
  try {
    // Log the callback request details
    logger.info('SAP OAuth callback received', {
      query: req.query,
      hasCode: !!req.query.code,
      hasError: !!req.query.error,
      errorDescription: req.query.error_description,
      state: req.query.state
    });

    // Check for OAuth errors in query params
    if (req.query.error) {
      logger.error('SAP OAuth returned error', {
        error: req.query.error,
        errorDescription: req.query.error_description,
        errorUri: req.query.error_uri
      });

      return res.redirect('/auth/sap/error?details=' + encodeURIComponent(req.query.error_description || req.query.error));
    }

    // Verify state manually
    const receivedState = req.query.state;
    if (!receivedState) {
      logger.error('No state in callback');
      return res.redirect('/auth/sap/error?details=Missing state parameter');
    }

    const storedStateData = oauthStateStore.get(receivedState);
    if (!storedStateData) {
      logger.error('Invalid or expired state', { receivedState });
      return res.redirect('/auth/sap/error?details=Invalid or expired state. Please try again.');
    }

    // Delete used state
    oauthStateStore.delete(receivedState);

    logger.info('State verified successfully');

    // Exchange code for token manually
    const code = req.query.code;
    if (!code) {
      logger.error('No authorization code received');
      return res.redirect('/auth/sap/error?details=No authorization code received');
    }

    logger.info('Exchanging code for tokens', {
      tokenURL: process.env.SAP_TOKEN_URL,
      callbackURL: process.env.SAP_CALLBACK_URL
    });

    // Exchange authorization code for tokens
    const tokenResponse = await axios.post(
      process.env.SAP_TOKEN_URL,
      new URLSearchParams({
        grant_type: 'client_credentials',
        code: code,
        client_id: process.env.SAP_CLIENT_ID,
        client_secret: process.env.SAP_CLIENT_SECRET,
        redirect_uri: process.env.SAP_CALLBACK_URL
      }),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );

    const { access_token, refresh_token, expires_in, token_type } = tokenResponse.data;

    logger.info('Tokens received from SAP', {
      hasAccessToken: !!access_token,
      hasRefreshToken: !!refresh_token,
      expiresIn: expires_in
    });

    // Fetch user info from SAP
    logger.info('Fetching user info from SAP', {
      url: process.env.SAP_USER_INFO_URL
    });

    const userInfoResponse = await axios.get(process.env.SAP_USER_INFO_URL, {
      headers: {
        'Authorization': `Bearer ${access_token}`,
        'Accept': 'application/json'
      }
    });

    const userInfo = userInfoResponse.data;

    logger.info('User info retrieved from SAP', {
      userId: userInfo.sub || userInfo.id,
      email: userInfo.email,
      name: userInfo.name
    });

    // Find or create user in your database
    const User = require('../models/User');

    let user = await User.findOne({ sapId: userInfo.sub || userInfo.id });

    if (!user) {
      // Create new user
      user = await User.create({
        sapId: userInfo.sub || userInfo.id,
        email: userInfo.email,
        name: userInfo.name || `${userInfo.given_name || ''} ${userInfo.family_name || ''}`.trim() || 'SAP User',
        firstName: userInfo.given_name,
        lastName: userInfo.family_name,
        provider: 'sap',
        roles: ['user'],
        sapProfile: userInfo,
        emailVerified: userInfo.email_verified || false,
        createdAt: new Date()
      });

      logger.logAuthEvent('SAP_USER_CREATED', {
        userId: user._id,
        sapId: user.sapId,
        email: user.email
      });
    } else {
      // Update existing user
      user.name = userInfo.name || user.name;
      user.sapProfile = userInfo;
      user.lastLogin = new Date();
      await user.save();

      logger.logAuthEvent('SAP_USER_LOGIN', {
        userId: user._id,
        sapId: user.sapId,
        email: user.email
      });
    }

    // Generate your own JWT tokens
    const sessionId = crypto.randomUUID();
    const tokens = tokenService.generateTokenPair({
      userId: user._id.toString(),
      email: user.email,
      roles: user.roles,
      sessionId
    });

    // Store session with encrypted SAP tokens
    const deviceInfo = {
      userAgent: req.get('user-agent'),
      ip: req.ip,
      platform: req.get('sec-ch-ua-platform') || 'unknown',
      browser: req.get('sec-ch-ua') || 'unknown'
    };

    const providerTokens = {
      accessToken: access_token,
      refreshToken: refresh_token,
      expiresAt: new Date(Date.now() + (expires_in * 1000)),
      tokenType: token_type || 'Bearer'
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

    // Check if frontend URL is configured
    const frontendUrl = process.env.FRONTEND_URL;

    if (frontendUrl && frontendUrl !== 'http://localhost:3000') {
      // Production: Redirect to frontend
      const redirectUrl = `${frontendUrl}/auth/callback?token=${tokens.accessToken}&refresh=${tokens.refreshToken}`;
      return res.redirect(redirectUrl);
    }

    // Development/Testing: Display tokens in browser
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>SAP OAuth Success</title>
        <meta charset="UTF-8">
        <style>
          body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
            background: #f5f5f5;
          }
          .container {
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
          }
          h1 {
            color: #4CAF50;
            margin-top: 0;
          }
          .success-icon {
            font-size: 48px;
            margin-bottom: 20px;
          }
          .token-box {
            background: #f9f9f9;
            padding: 15px;
            border-radius: 4px;
            margin: 15px 0;
            border-left: 4px solid #4CAF50;
          }
          .token-label {
            font-weight: bold;
            color: #555;
            margin-bottom: 8px;
          }
          .token-value {
            font-family: 'Courier New', monospace;
            font-size: 12px;
            word-break: break-all;
            color: #333;
            background: white;
            padding: 10px;
            border-radius: 4px;
            border: 1px solid #ddd;
          }
          .user-info {
            background: #e3f2fd;
            padding: 15px;
            border-radius: 4px;
            margin: 20px 0;
          }
          .copy-btn {
            background: #2196F3;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            margin-top: 10px;
          }
          .copy-btn:hover {
            background: #1976D2;
          }
          .note {
            background: #fff3cd;
            padding: 15px;
            border-radius: 4px;
            margin-top: 20px;
            border-left: 4px solid #ffc107;
          }
          .test-section {
            margin-top: 30px;
            padding: 20px;
            background: #f0f0f0;
            border-radius: 4px;
          }
          code {
            background: #333;
            color: #0f0;
            padding: 2px 6px;
            border-radius: 3px;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="success-icon">✅</div>
          <h1>SAP OAuth Authentication Successful!</h1>
          
          <div class="user-info">
            <h3>User Information:</h3>
            <p><strong>Email:</strong> ${user.email}</p>
            <p><strong>Name:</strong> ${user.name}</p>
            <p><strong>User ID:</strong> ${user._id}</p>
            <p><strong>SAP ID:</strong> ${user.sapId}</p>
            <p><strong>Provider:</strong> SAP</p>
            <p><strong>Roles:</strong> ${user.roles.join(', ')}</p>
          </div>

          <div class="token-box">
            <div class="token-label">Access Token (15 min):</div>
            <div class="token-value" id="accessToken">${tokens.accessToken}</div>
            <button class="copy-btn" onclick="copyToken('accessToken')">📋 Copy Access Token</button>
          </div>

          <div class="token-box">
            <div class="token-label">Refresh Token (7 days):</div>
            <div class="token-value" id="refreshToken">${tokens.refreshToken}</div>
            <button class="copy-btn" onclick="copyToken('refreshToken')">📋 Copy Refresh Token</button>
          </div>

          <div class="test-section">
            <h3>🧪 Test Your Authentication:</h3>
            <p>Use this curl command:</p>
            <div class="token-value">
curl -H "Authorization: Bearer ${tokens.accessToken}" \\
     http://localhost:3000/api/profile
            </div>
            <button class="copy-btn" onclick="copyCurl()">📋 Copy curl Command</button>
          </div>

          <div class="note">
            <strong>📝 Note:</strong> Access token expires in 15 minutes. Use the refresh token to get a new one.
            <br><br>
            <strong>Test endpoints:</strong>
            <ul>
              <li><code>GET /api/profile</code> - Get user profile</li>
              <li><code>GET /api/test</code> - Test protected route</li>
              <li><code>GET /auth/sessions</code> - View active sessions</li>
            </ul>
          </div>
        </div>

        <script>
          function copyToken(elementId) {
            const tokenElement = document.getElementById(elementId);
            const token = tokenElement.textContent;
            navigator.clipboard.writeText(token).then(() => {
              const btn = event.target;
              const originalText = btn.textContent;
              btn.textContent = '✓ Copied!';
              btn.style.background = '#4CAF50';
              setTimeout(() => {
                btn.textContent = originalText;
                btn.style.background = '#2196F3';
              }, 2000);
            });
          }

          function copyCurl() {
            const curlCommand = \`curl -H "Authorization: Bearer ${tokens.accessToken}" http://localhost:3000/api/profile\`;
            navigator.clipboard.writeText(curlCommand).then(() => {
              const btn = event.target;
              const originalText = btn.textContent;
              btn.textContent = '✓ Copied!';
              btn.style.background = '#4CAF50';
              setTimeout(() => {
                btn.textContent = originalText;
                btn.style.background = '#2196F3';
              }, 2000);
            });
          }
        </script>
      </body>
      </html>
    `);

  } catch (error) {
    logger.error('SAP OAuth callback error', {
      error: error.message,
      stack: error.stack,
      response: error.response?.data
    });

    const errorMessage = error.response?.data?.error_description || error.message;
    res.redirect('/auth/sap/error?details=' + encodeURIComponent(errorMessage));
  }
});

/**
 * SAP OAuth error handler
 * GET /auth/sap/error
 */
router.get('/sap/error', (req, res) => {
  const errorDetails = req.query.details || 'Unknown error';

  logger.logSecurityEvent('SAP_OAUTH_ERROR', {
    ip: req.ip,
    query: req.query,
    errorDetails: errorDetails
  });

  res.status(401).send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>SAP Authentication Error</title>
      <meta charset="UTF-8">
      <style>
        body {
          font-family: Arial, sans-serif;
          max-width: 700px;
          margin: 50px auto;
          padding: 20px;
          background: #f5f5f5;
        }
        .error-container {
          background: white;
          padding: 30px;
          border-radius: 8px;
          box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 { color: #f44336; }
        .error-icon { font-size: 48px; margin-bottom: 20px; }
        .error-message {
          background: #ffebee;
          padding: 15px;
          border-radius: 4px;
          margin: 15px 0;
          border-left: 4px solid #f44336;
          word-wrap: break-word;
        }
        .tips {
          background: #fff3cd;
          padding: 15px;
          border-radius: 4px;
          margin: 20px 0;
        }
        code {
          background: #333;
          color: #0f0;
          padding: 2px 6px;
          border-radius: 3px;
          font-family: monospace;
        }
        a {
          display: inline-block;
          background: #2196F3;
          color: white;
          padding: 10px 20px;
          text-decoration: none;
          border-radius: 4px;
          margin-top: 20px;
        }
        a:hover { background: #1976D2; }
      </style>
    </head>
    <body>
      <div class="error-container">
        <div class="error-icon">❌</div>
        <h1>SAP Authentication Failed</h1>
        
        <div class="error-message">
          <strong>Error Details:</strong><br>
          ${errorDetails}
        </div>
        
        <div class="tips">
          <strong>Common Issues:</strong>
          <ul>
            <li><strong>State verification failed:</strong> Try clearing your browser cookies and try again</li>
            <li><strong>Invalid client:</strong> Check SAP_CLIENT_ID and SAP_CLIENT_SECRET in .env</li>
            <li><strong>Redirect URI mismatch:</strong> Callback URL must be <code>http://localhost:3000/auth/sap/callback</code></li>
            <li><strong>Invalid scope:</strong> Check if SAP supports the requested scopes</li>
          </ul>
        </div>

        <p>Check your server logs for detailed error messages.</p>
        
        <a href="/auth/sap">← Try Again</a>
      </div>
    </body>
    </html>
  `);
});

// ============================================================================
// Token Management Routes
// ============================================================================

/**
 * Refresh access token
 * POST /auth/refresh
 */
router.post('/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({
        success: false,
        error: 'Refresh token required',
        code: 'NO_REFRESH_TOKEN'
      });
    }

    const verification = tokenService.verifyRefreshToken(refreshToken);

    if (!verification.valid) {
      logger.logSecurityEvent('INVALID_REFRESH_TOKEN', {
        error: verification.error,
        ip: req.ip
      });

      return res.status(401).json({
        success: false,
        error: 'Invalid refresh token',
        code: 'INVALID_REFRESH_TOKEN'
      });
    }

    const session = await sessionService.findSessionByRefreshToken(refreshToken);

    if (!session) {
      return res.status(401).json({
        success: false,
        error: 'Session not found or expired',
        code: 'INVALID_SESSION'
      });
    }

    const newSessionId = crypto.randomUUID();
    const tokens = tokenService.generateTokenPair({
      userId: session.userId._id.toString(),
      email: session.userId.email,
      roles: session.userId.roles,
      sessionId: newSessionId
    });

    await sessionService.invalidateSession(session._id);

    const deviceInfo = {
      userAgent: req.get('user-agent'),
      ip: req.ip,
      platform: req.get('sec-ch-ua-platform') || 'unknown',
      browser: req.get('sec-ch-ua') || 'unknown'
    };

    await sessionService.createSession(
      session.userId._id,
      tokens.refreshToken,
      deviceInfo,
      session.provider,
      session.providerTokens
    );

    logger.logAuthEvent('TOKEN_REFRESHED', {
      userId: session.userId._id,
      oldSessionId: session._id,
      newSessionId
    });

    res.json({
      success: true,
      data: {
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        expiresIn: '15m',
        tokenType: 'Bearer'
      }
    });
  } catch (error) {
    logger.error('Token refresh failed', {
      error: error.message,
      stack: error.stack
    });

    res.status(500).json({
      success: false,
      error: 'Token refresh failed'
    });
  }
});

// ============================================================================
// Session Management Routes
// ============================================================================

router.post('/logout', authenticateToken, async (req, res) => {
  try {
    await sessionService.invalidateSession(req.session._id);

    logger.logAuthEvent('USER_LOGOUT', {
      userId: req.user.id,
      sessionId: req.session._id
    });

    res.json({
      success: true,
      message: 'Logged out successfully'
    });
  } catch (error) {
    logger.error('Logout failed', { error: error.message });
    res.status(500).json({
      success: false,
      error: 'Logout failed'
    });
  }
});

router.post('/logout-all', authenticateToken, async (req, res) => {
  try {
    await sessionService.invalidateAllUserSessions(req.user.id);

    logger.logAuthEvent('USER_LOGOUT_ALL', {
      userId: req.user.id
    });

    res.json({
      success: true,
      message: 'All sessions logged out'
    });
  } catch (error) {
    logger.error('Logout all failed', { error: error.message });
    res.status(500).json({
      success: false,
      error: 'Logout all failed'
    });
  }
});

router.get('/sessions', authenticateToken, async (req, res) => {
  try {
    const sessions = await sessionService.getUserSessions(req.user.id);

    res.json({
      success: true,
      data: sessions.map(s => ({
        id: s._id,
        deviceInfo: s.deviceInfo,
        lastActivity: s.lastActivity,
        createdAt: s.createdAt,
        provider: s.provider,
        isCurrent: s._id.toString() === req.session._id.toString()
      }))
    });
  } catch (error) {
    logger.error('Get sessions failed', { error: error.message });
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve sessions'
    });
  }
});

module.exports = router;