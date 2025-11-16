
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