# 🔐 Authentication Service with SAP OAuth

Production-grade authentication microservice built with Express.js, MongoDB, and SAP OAuth integration.

## ✨ Features

- ✅ **JWT Authentication** - Secure token-based authentication
- ✅ **SAP OAuth Integration** - Standard OAuth 2.0 redirect flow
- ✅ **SAP ROPC Support** - Direct credential login (optional)
- ✅ **Session Management** - MongoDB-based session storage with encryption
- ✅ **Token Refresh** - Automatic token rotation
- ✅ **Role-Based Access Control** - RBAC for protected routes
- ✅ **Application Insights** - Azure monitoring integration
- ✅ **Comprehensive Logging** - Winston-based structured logging
- ✅ **Security Features** - Helmet, CORS, rate limiting
- ✅ **Health Checks** - Kubernetes-ready probes

## 📋 Prerequisites

- Node.js >= 18.0.0
- MongoDB >= 5.0
- npm >= 9.0.0
- SAP OAuth credentials (Client ID, Secret, Base URL)

## 🚀 Quick Start

### 1. Clone and Install

```bash
# Create project directory
mkdir auth-service && cd auth-service

# Initialize npm (if not already done)
npm init -y

# Install dependencies
npm install express mongoose jsonwebtoken bcryptjs winston helmet cors dotenv express-rate-limit applicationinsights passport passport-oauth2 axios socket.io

# Install dev dependencies
npm install --save-dev nodemon eslint jest supertest
```

### 2. Project Structure

Create this folder structure:

```
auth-service/
├── config/
│   └── auth.config.js
├── models/
│   ├── User.js
│   └── Session.js
├── services/
│   ├── token.service.js
│   ├── session.service.js
│   ├── sap.service.js
│   └── sap-ropc.service.js
├── middlewares/
│   ├── auth.middleware.js
│   └── request-tracking.middleware.js
├── routes/
│   └── auth.routes.js
├── strategies/
│   └── sap.strategy.js
├── utils/
│   └── logger.js
├── logs/
├── .env
├── .env.example
├── .gitignore
├── main.js
├── server.js
├── package.json
└── README.md
```

### 3. Configure Environment

```bash
# Generate secure secrets
npm run generate-secrets

# Copy example env file
cp .env.example .env
```

Edit `.env` with your configuration:

```env
# Application
SERVICE_NAME=auth-service
APP_VERSION=1.0.0
NODE_ENV=development
PORT=3000

# JWT Configuration (use generated secrets)
JWT_ACCESS_SECRET=your-generated-secret-here
JWT_REFRESH_SECRET=your-generated-secret-here
JWT_ISSUER=my-app
JWT_AUDIENCE=my-app-api

# Encryption (use generated key)
ENCRYPTION_KEY=your-generated-encryption-key-here

# MongoDB
MONGODB_URI=mongodb://localhost:27017/auth-db

# Logging
LOG_LEVEL=info

# SAP OAuth Configuration
SAP_BASE_URL=https://your-sap-instance.com
SAP_CLIENT_ID=your-client-id
SAP_CLIENT_SECRET=your-client-secret
SAP_AUTHORIZATION_URL=https://your-sap-instance.com/oauth/authorize
SAP_TOKEN_URL=https://your-sap-instance.com/oauth/token
SAP_USER_INFO_URL=https://your-sap-instance.com/oauth/userinfo
SAP_CALLBACK_URL=http://localhost:3000/auth/sap/callback
SAP_SCOPES=openid email profile

# Frontend
FRONTEND_URL=http://localhost:3000

# Application Insights (Optional)
APPLICATIONINSIGHTS_CONNECTION_STRING=
```

### 4. Copy Files from Artifacts

Copy the code from Claude artifacts into respective files:

- `main.js` ← "main.js - Application Entry Point" artifact
- `server.js` ← "Complete server.js with SAP OAuth Integration" artifact  
- `package.json` ← "package.json - Updated with Main Entry Point" artifact
- All other files from previous artifacts

### 5. Validate Configuration

```bash
# Check if configuration is valid
npm run check-config
```

### 6. Start MongoDB

```bash
# Local MongoDB
mongod

# Or using Docker
docker run -d -p 27017:27017 --name mongodb mongo:latest
```

### 7. Start the Service

```bash
# Development mode (with auto-reload)
npm run dev

# Production mode
npm start
```

You should see:

```
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║  🔐 Auth Service with SAP OAuth Running                  ║
║                                                          ║
║  Environment: development                                ║
║  Port:        3000                                       ║
║  Version:     1.0.0                                      ║
...
╚══════════════════════════════════════════════════════════╝
```

## 🧪 Testing

### Test SAP OAuth Flow

```bash
# Open in browser
http://localhost:3000/auth/sap

# You'll be redirected to SAP login
# After successful login, user will be created automatically
```

### Test with Postman

#### 1. Health Check
```http
GET http://localhost:3000/health
```

#### 2. SAP OAuth Login (Redirect Flow)
```http
GET http://localhost:3000/auth/sap
# Follow redirects in browser
```

#### 3. SAP Direct Login (ROPC)
```http
POST http://localhost:3000/auth/sap/login
Content-Type: application/json

{
  "username": "your-sap-username",
  "password": "your-sap-password"
}
```

Response:
```json
{
  "success": true,
  "data": {
    "accessToken": "eyJhbGc...",
    "refreshToken": "eyJhbGc...",
    "expiresIn": "15m",
    "tokenType": "Bearer",
    "user": {
      "id": "...",
      "email": "user@company.com",
      "name": "John Doe",
      "roles": ["user"]
    }
  }
}
```

#### 4. Access Protected Route
```http
GET http://localhost:3000/api/profile
Authorization: Bearer your_access_token
```

#### 5. Refresh Token
```http
POST http://localhost:3000/auth/refresh
Content-Type: application/json

{
  "refreshToken": "your_refresh_token"
}
```

#### 6. Get Active Sessions
```http
GET http://localhost:3000/auth/sessions
Authorization: Bearer your_access_token
```

#### 7. Logout
```http
POST http://localhost:3000/auth/logout
Authorization: Bearer your_access_token
```

## 📚 API Documentation

### Authentication Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/auth/login` | Email/password login | No |
| GET | `/auth/sap` | Initiate SAP OAuth | No |
| GET | `/auth/sap/callback` | SAP OAuth callback | No |
| POST | `/auth/sap/login` | SAP direct login (ROPC) | No |
| POST | `/auth/refresh` | Refresh access token | No |
| POST | `/auth/logout` | Logout current session | Yes |
| POST | `/auth/logout-all` | Logout all sessions | Yes |
| GET | `/auth/sessions` | Get active sessions | Yes |

### Protected Endpoints

| Method | Endpoint | Description | Required Role |
|--------|----------|-------------|---------------|
| GET | `/api/profile` | Get user profile | Any |
| PUT | `/api/profile` | Update profile | Any |
| GET | `/api/test` | Test protected route | Any |
| GET | `/api/sap/business-data` | Get SAP data | Any (SAP auth) |
| GET | `/api/admin/users` | List all users | Admin |

### Health Check Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Full health status |
| GET | `/ready` | Readiness probe |
| GET | `/alive` | Liveness probe |

## 🔧 Configuration Options

### Session Management

Edit `config/auth.config.js`:

```javascript
session: {
  maxActiveSessions: 5,              // Max concurrent sessions per user
  inactivityTimeout: 30 * 60 * 1000, // 30 minutes
  reuseDeviceSession: true,          // Reuse session from same browser
  singleSessionPerUser: false        // Force single session only
}
```

### JWT Settings

```javascript
jwt: {
  accessTokenExpiry: '15m',   // Short-lived access token
  refreshTokenExpiry: '7d',   // Long-lived refresh token
  issuer: 'your-app-name',
  audience: 'your-app-api'
}
```

## 🔒 Security

### Best Practices Implemented

- ✅ JWT tokens with signature verification
- ✅ Refresh token rotation
- ✅ Session encryption (AES-256)
- ✅ Rate limiting on auth endpoints
- ✅ CORS configuration
- ✅ Helmet security headers
- ✅ Request logging and tracking
- ✅ Input validation
- ✅ SQL injection protection (using Mongoose)

### Production Checklist

- [ ] Change all default secrets
- [ ] Enable HTTPS
- [ ] Configure Application Insights
- [ ] Set up proper CORS origins
- [ ] Enable rate limiting
- [ ] Review and set session limits
- [ ] Configure proper MongoDB replica set
- [ ] Set up backup strategy
- [ ] Configure logging retention
- [ ] Set up monitoring alerts

## 📊 Monitoring

### Application Insights Integration

The service automatically tracks:
- Authentication events
- Failed login attempts
- Token refresh operations
- API performance metrics
- Database query performance
- External API calls (SAP)
- Error rates and exceptions

### View Logs

```bash
# All logs
npm run logs

# Error logs only
npm run logs:error

# Auth-specific logs
npm run logs:auth

# Real-time
tail -f logs/combined.log
```

### MongoDB Monitoring

```javascript
// Check active sessions
db.sessions.countDocuments({ isActive: true })

// Check users by provider
db.users.aggregate([
  { $group: { _id: "$provider", count: { $sum: 1 } } }
])

// Find expired sessions
db.sessions.find({ expiresAt: { $lt: new Date() } }).count()
```

## 🐛 Troubleshooting

### MongoDB Connection Error

```
Error: connect ECONNREFUSED 127.0.0.1:27017
```

**Solution:** Start MongoDB
```bash
mongod
# or
docker start mongodb
```

### Port Already in Use

```
Error: listen EADDRINUSE: address already in use :::3000
```

**Solution:** Change port or kill process
```bash
# Change port in .env
PORT=3001

# Or kill existing process
lsof -ti:3000 | xargs kill -9
```

### SAP OAuth Error: redirect_uri_mismatch

**Solution:** Ensure `SAP_CALLBACK_URL` in `.env` exactly matches URL registered in SAP OAuth app configuration.

### Invalid Client Error

**Solution:** Verify `SAP_CLIENT_ID` and `SAP_CLIENT_SECRET` are correct and the client is enabled in SAP.

### User Info Endpoint Failed

**Solution:** Check `SAP_USER_INFO_URL` is correct. Try alternatives:
- `/userinfo`
- `/oauth2/userinfo`
- `/oauth/userinfo`

## 🚀 Deployment

### Using PM2

```bash
npm install -g pm2

# Start
pm2 start main.js --name auth-service

# Monitor
pm2 monit

# Logs
pm2 logs auth-service

# Restart
pm2 restart auth-service

# Stop
pm2 stop auth-service
```

### Using Docker

```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
EXPOSE 3000
CMD ["node", "main.js"]
```

Build and run:
```bash
docker build -t auth-service .
docker run -p 3000:3000 --env-file .env auth-service
```

### Environment Variables for Production

```env
NODE_ENV=production
PORT=3000
MONGODB_URI=mongodb+srv://user:pass@cluster.mongodb.net/auth-db
FRONTEND_URL=https://your-frontend-domain.com
SAP_CALLBACK_URL=https://your-backend-domain.com/auth/sap/callback
APPLICATIONINSIGHTS_CONNECTION_STRING=InstrumentationKey=...
```

## 📖 Additional Resources

- [SAP OAuth Documentation](https://help.sap.com/docs/IDENTITY_AUTHENTICATION)
- [Express.js Best Practices](https://expressjs.com/en/advanced/best-practice-security.html)
- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)
- [MongoDB Security Checklist](https://docs.mongodb.com/manual/administration/security-checklist/)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 📄 License

MIT

## 🆘 Support

For issues or questions:
1. Check logs in `logs/` directory
2. Verify configuration with `npm run check-config`
3. Check MongoDB is running
4. Verify all environment variables are set

---

**Made with ❤️ for secure authentication**