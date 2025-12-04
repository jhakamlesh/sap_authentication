// ============================================================================
// routes/auth.routes.js - Fixed User Info Retrieval
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

// In-memory store for OAuth state
const oauthStateStore = new Map();

// Clean up old states
setInterval(() => {
  const tenMinutesAgo = Date.now() - 10 * 60 * 1000;
  for (const [state, data] of oauthStateStore.entries()) {
    if (data.timestamp < tenMinutesAgo) {
      oauthStateStore.delete(state);
    }
  }
}, 60000);

// ============================================================================
// SAP OAuth Routes
// ============================================================================

router.get('/sap', (req, res, next) => {
  logger.info('Initiating SAP OAuth flow');

  const state = crypto.randomBytes(16).toString('hex');
  oauthStateStore.set(state, {
    timestamp: Date.now(),
    ip: req.ip,
    userAgent: req.get('user-agent')
  });

  // Build authorization URL with proper scopes
  const authorizationURL = process.env.SAP_AUTHORIZATION_URL;
  const clientId = process.env.SAP_CLIENT_ID;
  const redirectUri = process.env.SAP_CALLBACK_URL;
  const scopes = 'openid email profile'; // Critical: openid is required for user info

  const authUrl = `${authorizationURL}?` + new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: redirectUri,
    scope: scopes,
    state: state
  }).toString();

  logger.info('Redirecting to SAP', {
    authorizationURL,
    clientId,
    redirectUri,
    scopes,
    state
  });

  res.redirect(authUrl);
});

router.get('/sap/callback', async (req, res) => {
  try {
    logger.info('SAP OAuth callback received', {
      query: req.query,
      hasCode: !!req.query.code,
      hasError: !!req.query.error
    });

    if (req.query.error) {
      logger.error('SAP OAuth returned error', {
        error: req.query.error,
        errorDescription: req.query.error_description
      });
      return res.redirect('/auth/sap/error?details=' + encodeURIComponent(req.query.error_description || req.query.error));
    }

    const receivedState = req.query.state;
    if (!receivedState || !oauthStateStore.has(receivedState)) {
      logger.error('Invalid or expired state');
      return res.redirect('/auth/sap/error?details=Invalid or expired state. Please try again.');
    }

    oauthStateStore.delete(receivedState);
    logger.info('State verified successfully');

    const code = req.query.code;
    if (!code) {
      return res.redirect('/auth/sap/error?details=No authorization code received');
    }

    logger.info('Exchanging code for tokens');

    // Exchange code for tokens with Basic Auth
    const basicAuth = Buffer.from(`${process.env.SAP_CLIENT_ID}:${process.env.SAP_CLIENT_SECRET}`).toString('base64');

    const tokenResponse = await axios.post(
      process.env.SAP_TOKEN_URL,
      new URLSearchParams({
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: process.env.SAP_CALLBACK_URL
      }),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': `Basic ${basicAuth}`
        }
      }
    );

    const { access_token, refresh_token, expires_in, token_type, id_token } = tokenResponse.data;

    logger.info('Tokens received from SAP', {
      hasAccessToken: !!access_token,
      hasRefreshToken: !!refresh_token,
      hasIdToken: !!id_token,
      expiresIn: expires_in
    });

    // Decode ID token to get user info (SAP usually puts user info here)
    let userInfo = null;

    if (id_token) {
      try {
        // Decode JWT (without verification - we trust SAP's token)
        const base64Payload = id_token.split('.')[1];
        const payload = Buffer.from(base64Payload, 'base64').toString('utf-8');
        userInfo = JSON.parse(payload);

        logger.info('User info from ID token', {
          sub: userInfo.sub,
          email: userInfo.email,
          name: userInfo.name,
          allClaims: Object.keys(userInfo)
        });
      } catch (error) {
        logger.error('Failed to decode ID token', { error: error.message });
      }
    }

    // If no ID token or ID token doesn't have user info, try userinfo endpoint
    if (!userInfo || !userInfo.sub || userInfo.sub === process.env.SAP_CLIENT_ID) {
      logger.info('Fetching user info from userinfo endpoint', {
        url: process.env.SAP_USER_INFO_URL
      });

      try {
        const userInfoResponse = await axios.get(process.env.SAP_USER_INFO_URL, {
          headers: {
            'Authorization': `Bearer ${access_token}`,
            'Accept': 'application/json'
          }
        });

        userInfo = userInfoResponse.data;

        logger.info('User info retrieved from endpoint', {
          sub: userInfo.sub,
          email: userInfo.email,
          name: userInfo.name,
          allFields: Object.keys(userInfo)
        });
      } catch (error) {
        logger.error('Failed to fetch user info from endpoint', {
          error: error.message,
          status: error.response?.status,
          data: error.response?.data
        });

        // If userinfo endpoint fails but we have ID token, use it
        if (id_token) {
          const base64Payload = id_token.split('.')[1];
          const payload = Buffer.from(base64Payload, 'base64').toString('utf-8');
          userInfo = JSON.parse(payload);
          logger.info('Falling back to ID token user info');
        } else {
          throw new Error('Unable to retrieve user information from SAP');
        }
      }
    }

    // Extract user ID from various possible fields
    const sapUserId = userInfo.sub ||
      userInfo.user_id ||
      userInfo.id ||
      userInfo.username ||
      userInfo.email ||
      userInfo.user_uuid;

    if (!sapUserId || sapUserId === process.env.SAP_CLIENT_ID) {
      logger.error('No valid user ID found in token', {
        userInfo,
        clientId: process.env.SAP_CLIENT_ID
      });
      throw new Error('SAP returned client credentials token instead of user token. Check your SAP OAuth configuration and scopes.');
    }

    logger.info('Valid user ID found', { sapUserId });

    // Find or create user
    const User = require('../models/User');
    let user = await User.findOne({ sapId: sapUserId });

    if (!user) {
      user = await User.create({
        sapId: sapUserId,
        email: userInfo.email || userInfo.mail || `${sapUserId}@sap.user`,
        name: userInfo.name || userInfo.given_name || userInfo.firstname || userInfo.displayname || 'SAP User',
        firstName: userInfo.given_name || userInfo.firstname || userInfo.givenName,
        lastName: userInfo.family_name || userInfo.lastname || userInfo.familyName || userInfo.surname,
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

    // Generate your JWT tokens
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

    const frontendUrl = process.env.FRONTEND_URL;

    if (frontendUrl && frontendUrl !== 'http://localhost:3000') {
      const redirectUrl = `${frontendUrl}/auth/callback?token=${tokens.accessToken}&refresh=${tokens.refreshToken}`;
      return res.redirect(redirectUrl);
    }

    // Display success page
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
            <div class="token-label">Your Access Token (15 min):</div>
            <div class="token-value" id="accessToken">${tokens.accessToken}</div>
            <button class="copy-btn" onclick="copyToken('accessToken')">📋 Copy Access Token</button>
          </div>

          <div class="token-box">
            <div class="token-label">Your Refresh Token (7 days):</div>
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
            <strong>📝 Note:</strong> These are YOUR application's JWT tokens (not SAP tokens).
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
      response: error.response?.data,
      status: error.response?.status
    });

    const errorMessage = error.response?.data?.error_description || error.response?.data?.error || error.message;
    res.redirect('/auth/sap/error?details=' + encodeURIComponent(errorMessage));
  }
});

router.get('/sap/error', (req, res) => {
  const errorDetails = req.query.details || 'Unknown error';

  logger.logSecurityEvent('SAP_OAUTH_ERROR', {
    ip: req.ip,
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
          <strong>Error:</strong><br>
          ${errorDetails}
        </div>
        
        <div class="tips">
          <strong>Common fixes:</strong>
          <ul>
            <li>Make sure <code>openid</code> scope is included in SAP_SCOPES</li>
            <li>Verify the SAP OAuth app is configured for "Authorization Code" grant</li>
            <li>Check if your SAP admin enabled user info access</li>
          </ul>
        </div>

        <p>Check server logs for more details.</p>
        
        <a href="/auth/sap">← Try Again</a>
      </div>
    </body>
    </html>
  `);
});

// Session routes (same as before)
router.post('/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      return res.status(400).json({ success: false, error: 'Refresh token required' });
    }
    const verification = tokenService.verifyRefreshToken(refreshToken);
    if (!verification.valid) {
      return res.status(401).json({ success: false, error: 'Invalid refresh token' });
    }
    const session = await sessionService.findSessionByRefreshToken(refreshToken);
    if (!session) {
      return res.status(401).json({ success: false, error: 'Session not found' });
    }
    const newSessionId = crypto.randomUUID();
    const tokens = tokenService.generateTokenPair({
      userId: session.userId._id.toString(),
      email: session.userId.email,
      roles: session.userId.roles,
      sessionId: newSessionId
    });
    await sessionService.invalidateSession(session._id);
    const deviceInfo = { userAgent: req.get('user-agent'), ip: req.ip, platform: 'unknown', browser: 'unknown' };
    await sessionService.createSession(session.userId._id, tokens.refreshToken, deviceInfo, session.provider, session.providerTokens);
    res.json({ success: true, data: { accessToken: tokens.accessToken, refreshToken: tokens.refreshToken, expiresIn: '15m', tokenType: 'Bearer' } });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Token refresh failed' });
  }
});

router.post('/logout', authenticateToken, async (req, res) => {
  try {
    await sessionService.invalidateSession(req.session._id);
    res.json({ success: true, message: 'Logged out successfully' });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Logout failed' });
  }
});

router.post('/logout-all', authenticateToken, async (req, res) => {
  try {
    await sessionService.invalidateAllUserSessions(req.user.id);
    res.json({ success: true, message: 'All sessions logged out' });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Logout all failed' });
  }
});

router.get('/sessions', authenticateToken, async (req, res) => {
  try {
    const sessions = await sessionService.getUserSessions(req.user.id);
    res.json({ success: true, data: sessions.map(s => ({ id: s._id, deviceInfo: s.deviceInfo, lastActivity: s.lastActivity, createdAt: s.createdAt, provider: s.provider, isCurrent: s._id.toString() === req.session._id.toString() })) });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to retrieve sessions' });
  }
});

module.exports = router;