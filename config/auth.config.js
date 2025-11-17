// ============================================================================
// config/auth.config.js
// ============================================================================

module.exports = {
  jwt: {
    accessTokenSecret: process.env.JWT_ACCESS_SECRET,
    refreshTokenSecret: process.env.JWT_REFRESH_SECRET,
    accessTokenExpiry: '15m',
    refreshTokenExpiry: '7d',
    issuer: process.env.JWT_ISSUER || 'your-app-name',
    audience: process.env.JWT_AUDIENCE || 'your-app-api',
    algorithm: 'HS256'
  },
  session: {
    maxActiveSessions: 5, // per user
    inactivityTimeout: 30 * 60 * 1000, // 30 minutes
    reuseDeviceSession: true, // Reuse session from same browser instead of creating new one
    singleSessionPerUser: false // Set to true to allow only one active session per user
  },
  oauth: {
    providers: {
      sap: {
        clientID: process.env.SAP_CLIENT_ID,
        clientSecret: process.env.SAP_CLIENT_SECRET,
        callbackURL: process.env.SAP_CALLBACK_URL
      }
    }
  }
};