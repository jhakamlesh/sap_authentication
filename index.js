// ============================================================================
// SAP OAuth Integration - Complete Setup
// ============================================================================

// ============================================================================
// 1. Update .env with SAP Configuration
// ============================================================================
/*
Add to your .env file:

# SAP OAuth Configuration
SAP_BASE_URL=https://your-sap-instance.com
SAP_CLIENT_ID=your-client-id
SAP_CLIENT_SECRET=your-client-secret
SAP_AUTHORIZATION_URL=https://your-sap-instance.com/oauth/authorize
SAP_TOKEN_URL=https://your-sap-instance.com/oauth/token
SAP_USER_INFO_URL=https://your-sap-instance.com/oauth/userinfo
SAP_CALLBACK_URL=http://localhost:3000/auth/sap/callback
SAP_SCOPES=openid email profile

# Your backend URL (for redirect)
BACKEND_URL=http://localhost:3000
*/

// ============================================================================
// 2. Install Passport.js and OAuth Strategy
// ============================================================================
/*
npm install passport passport-oauth2 axios
*/

// ============================================================================
// 3. Create SAP OAuth Strategy
// ============================================================================
// strategies/sap.strategy.js

const passport = require('passport');
const OAuth2Strategy = require('passport-oauth2');
const axios = require('axios');
const logger = require('../utils/logger');

// SAP OAuth Strategy Configuration
passport.use('sap', new OAuth2Strategy({
    authorizationURL: process.env.SAP_AUTHORIZATION_URL,
    tokenURL: process.env.SAP_TOKEN_URL,
    clientID: process.env.SAP_CLIENT_ID,
    clientSecret: process.env.SAP_CLIENT_SECRET,
    callbackURL: process.env.SAP_CALLBACK_URL,
    scope: (process.env.SAP_SCOPES || 'openid email profile').split(' '),
    state: true, // Enable CSRF protection
    pkce: true,  // Enable PKCE for additional security
  },
  async (accessToken, refreshToken, params, profile, done) => {
    try {
      logger.info('SAP OAuth callback received', {
        hasAccessToken: !!accessToken,
        hasRefreshToken: !!refreshToken,
        expiresIn: params.expires_in
      });

      // Fetch user info from SAP
      let userInfo;
      try {
        const response = await axios.get(process.env.SAP_USER_INFO_URL, {
          headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Accept': 'application/json'
          }
        });
        userInfo = response.data;
        
        logger.info('SAP user info retrieved', {
          userId: userInfo.sub || userInfo.id,
          email: userInfo.email
        });
      } catch (error) {
        logger.error('Failed to fetch SAP user info', {
          error: error.message,
          status: error.response?.status
        });
        return done(error, null);
      }

      // Find or create user in your database
      const User = require('../models/User');
      
      let user = await User.findOne({ sapId: userInfo.sub || userInfo.id });
      
      if (!user) {
        // Create new user
        user = await User.create({
          sapId: userInfo.sub || userInfo.id,
          email: userInfo.email,
          name: userInfo.name || userInfo.given_name + ' ' + userInfo.family_name,
          firstName: userInfo.given_name,
          lastName: userInfo.family_name,
          provider: 'sap',
          roles: ['user'], // Default role
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

      // Calculate token expiry
      const expiresAt = new Date(Date.now() + (params.expires_in * 1000));

      // Return user and tokens
      return done(null, {
        user,
        providerTokens: {
          accessToken,
          refreshToken,
          expiresAt,
          tokenType: params.token_type || 'Bearer'
        }
      });
    } catch (error) {
      logger.error('SAP OAuth error', {
        error: error.message,
        stack: error.stack
      });
      return done(error, null);
    }
  }
));

// Serialize/deserialize user (required by passport, but we don't use sessions)
passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});

module.exports = passport;

// ============================================================================
// 4. Create User Model
// ============================================================================
// models/User.js

const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  // Local auth fields
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
    index: true
  },
  password: {
    type: String,
    required: function() {
      return this.provider === 'local';
    }
  },
  
  // Common fields
  name: {
    type: String,
    required: true
  },
  firstName: String,
  lastName: String,
  
  // OAuth provider fields
  provider: {
    type: String,
    enum: ['local', 'sap', 'google', 'microsoft'],
    default: 'local',
    index: true
  },
  sapId: {
    type: String,
    unique: true,
    sparse: true, // Allows null values
    index: true
  },
  googleId: {
    type: String,
    unique: true,
    sparse: true
  },
  
  // SAP specific data
  sapProfile: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },
  
  // User status
  roles: [{
    type: String,
    enum: ['user', 'admin', 'editor', 'viewer'],
    default: 'user'
  }],
  isActive: {
    type: Boolean,
    default: true
  },
  emailVerified: {
    type: Boolean,
    default: false
  },
  
  // Timestamps
  lastLogin: Date,
  passwordChangedAt: Date
}, {
  timestamps: true
});

// Index for efficient queries
userSchema.index({ provider: 1, sapId: 1 });
userSchema.index({ email: 1, provider: 1 });

// Method to check if password was changed after token was issued
userSchema.methods.changedPasswordAfter = function(JWTTimestamp) {
  if (this.passwordChangedAt) {
    const changedTimestamp = parseInt(
      this.passwordChangedAt.getTime() / 1000,
      10
    );
    return JWTTimestamp < changedTimestamp;
  }
  return false;
};

module.exports = mongoose.model('User', userSchema);

// ============================================================================
// 5. Update Auth Routes with SAP OAuth
// ============================================================================
// routes/auth.routes.js (Add these routes)

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

// ============================================================================
// 6. Example: Making SAP API Calls
// ============================================================================
// services/sap.service.js

const axios = require('axios');
const logger = require('../utils/logger');
const { getSAPAccessToken } = require('../routes/auth.routes');

class SAPService {
  constructor() {
    this.baseURL = process.env.SAP_BASE_URL;
  }

  /**
   * Make authenticated request to SAP API
   */
  async makeRequest(session, endpoint, method = 'GET', data = null) {
    try {
      // Get valid access token (auto-refreshes if needed)
      const accessToken = await getSAPAccessToken(session);

      const config = {
        method,
        url: `${this.baseURL}${endpoint}`,
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        }
      };

      if (data) {
        config.data = data;
      }

      logger.info('Making SAP API request', {
        endpoint,
        method,
        userId: session.userId
      });

      const startTime = Date.now();
      const response = await axios(config);
      const duration = Date.now() - startTime;

      logger.trackDependency(
        'SAP API',
        `${method} ${endpoint}`,
        duration,
        true,
        {
          type: 'HTTP',
          statusCode: response.status
        }
      );

      return response.data;
    } catch (error) {
      logger.error('SAP API request failed', {
        endpoint,
        method,
        error: error.message,
        status: error.response?.status,
        data: error.response?.data
      });

      logger.trackDependency(
        'SAP API',
        `${method} ${endpoint}`,
        0,
        false,
        {
          type: 'HTTP',
          error: error.message,
          statusCode: error.response?.status
        }
      );

      throw error;
    }
  }

  /**
   * Example: Get user profile from SAP
   */
  async getUserProfile(session) {
    return await this.makeRequest(session, '/api/user/profile', 'GET');
  }

  /**
   * Example: Create resource in SAP
   */
  async createResource(session, resourceData) {
    return await this.makeRequest(session, '/api/resources', 'POST', resourceData);
  }

  /**
   * Example: Get SAP business data
   */
  async getBusinessData(session, filters = {}) {
    const queryString = new URLSearchParams(filters).toString();
    const endpoint = `/api/business-data${queryString ? '?' + queryString : ''}`;
    return await this.makeRequest(session, endpoint, 'GET');
  }
}

module.exports = new SAPService();

// ============================================================================
// 7. Update server.js
// ============================================================================
/*
Add to your server.js:

const passport = require('./strategies/sap.strategy');

// Add after other middleware
app.use(passport.initialize());

// Your routes
app.use('/auth', authRoutes);
*/

// ============================================================================
// 8. Frontend Integration Example
// ============================================================================
/*
// React Component Example

import React from 'react';

function LoginPage() {
  const handleSAPLogin = () => {
    // Redirect to SAP OAuth
    window.location.href = 'http://localhost:3000/auth/sap';
  };

  return (
    <div>
      <h1>Login</h1>
      <button onClick={handleSAPLogin}>
        Login with SAP
      </button>
    </div>
  );
}

// Callback Handler
function AuthCallback() {
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const accessToken = urlParams.get('token');
    const refreshToken = urlParams.get('refresh');
    
    if (accessToken && refreshToken) {
      // Store tokens
      localStorage.setItem('accessToken', accessToken);
      localStorage.setItem('refreshToken', refreshToken);
      
      // Redirect to dashboard
      window.location.href = '/dashboard';
    } else {
      const error = urlParams.get('error');
      console.error('Auth failed:', error);
      window.location.href = '/login';
    }
  }, []);

  return <div>Processing authentication...</div>;
}
*/

// ============================================================================
// 9. Testing SAP OAuth
// ============================================================================
/*
1. Start your server:
   npm run dev

2. Open browser and navigate to:
   http://localhost:3000/auth/sap

3. You'll be redirected to SAP login page

4. After successful login, you'll be redirected back to:
   http://localhost:3000/auth/sap/callback

5. Then redirected to your frontend with tokens:
   http://localhost:3000/auth/callback?token=xxx&refresh=xxx

6. Check MongoDB for created user:
   db.users.find({ provider: 'sap' })

7. Check session:
   db.sessions.find({ provider: 'sap' })
*/

// ============================================================================
// 10. Example: Protected Route using SAP Data
// ============================================================================
/*
Add to your API routes:

const sapService = require('../services/sap.service');

router.get('/api/sap/business-data', authenticateToken, async (req, res) => {
  try {
    // Check if user logged in via SAP
    if (req.session.provider !== 'sap') {
      return res.status(403).json({
        success: false,
        error: 'This endpoint requires SAP authentication'
      });
    }

    // Get data from SAP
    const data = await sapService.getBusinessData(req.session, {
      category: req.query.category,
      limit: req.query.limit || 10
    });

    res.json({
      success: true,
      data
    });
  } catch (error) {
    req.logger.error('Failed to fetch SAP business data', {
      error: error.message,
      userId: req.user.id
    });

    res.status(500).json({
      success: false,
      error: 'Failed to fetch data from SAP'
    });
  }
});
*/