# SAP OAuth Setup Guide - Step by Step

## 📋 Prerequisites

✅ You have received from SAP:
- Client ID
- Client Secret  
- Base URL

✅ Your existing auth service is running

## 🚀 Step-by-Step Setup

### Step 1: Install Additional Dependencies

```bash
npm install passport passport-oauth2 axios
```

### Step 2: Update Environment Variables

Add to your `.env` file:

```env
# SAP OAuth Configuration
SAP_BASE_URL=https://your-sap-instance.com
SAP_CLIENT_ID=your-actual-client-id-here
SAP_CLIENT_SECRET=your-actual-client-secret-here

# These URLs might be different - check SAP documentation
SAP_AUTHORIZATION_URL=https://your-sap-instance.com/oauth/authorize
SAP_TOKEN_URL=https://your-sap-instance.com/oauth/token
SAP_USER_INFO_URL=https://your-sap-instance.com/oauth/userinfo

# Callback URL (must match what you registered in SAP)
SAP_CALLBACK_URL=http://localhost:3000/auth/sap/callback

# Scopes (adjust based on SAP requirements)
SAP_SCOPES=openid email profile

# Backend URL
BACKEND_URL=http://localhost:3000
```

**Important Notes:**
- Replace `your-sap-instance.com` with actual SAP domain
- The URLs (`/oauth/authorize`, `/oauth/token`, etc.) might be different for your SAP setup
- Common SAP OAuth endpoints:
  - SAP Cloud Platform: `https://<subdomain>.authentication.<region>.hana.ondemand.com`
  - SAP BTP: `https://<subdomain>.accounts.ondemand.com`
  - Custom SAP: Check your SAP administrator

### Step 3: Verify SAP Endpoint URLs

Contact your SAP admin or check SAP documentation to confirm:

```bash
# Test if endpoints are accessible
curl https://your-sap-instance.com/oauth/authorize

# Or use Postman to verify
```

Common SAP OAuth URL patterns:
```
Authorization: https://<your-domain>/oauth/authorize
Token:        https://<your-domain>/oauth/token  
UserInfo:     https://<your-domain>/oauth/userinfo
```

### Step 4: Create Required Files

#### A. Create User Model

Create file: `models/User.js` (copy from artifact)

#### B. Create SAP Strategy

Create file: `strategies/sap.strategy.js` (copy from artifact)

#### C. Create SAP Service

Create file: `services/sap.service.js` (copy from artifact)

#### D. Update Auth Routes

Edit: `routes/auth.routes.js` - Add SAP routes from artifact

### Step 5: Update server.js

Add these lines to `server.js`:

```javascript
// Add near the top with other requires
const passport = require('./strategies/sap.strategy');

// Add after other middleware (after express.json())
app.use(passport.initialize());
```

### Step 6: Initialize Database Indexes

```bash
# Update init-indexes.js to include User model
node scripts/init-indexes.js
```

Or manually in MongoDB:

```javascript
db.users.createIndex({ email: 1 }, { unique: true })
db.users.createIndex({ sapId: 1 }, { unique: true, sparse: true })
db.users.createIndex({ provider: 1, sapId: 1 })
```

### Step 7: Test the Setup

#### Option A: Using Browser

1. **Start your server:**
   ```bash
   npm run dev
   ```

2. **Open browser and navigate to:**
   ```
   http://localhost:3000/auth/sap
   ```

3. **You should be redirected to SAP login page**

4. **After login, you'll be redirected back with tokens**

#### Option B: Using Postman (for testing flow)

1. **Initiate OAuth Flow:**
   - Method: GET
   - URL: `http://localhost:3000/auth/sap`
   - This will redirect you to SAP

2. **Follow the redirect to SAP login**

3. **After successful login, check:**
   - MongoDB users collection: `db.users.find()`
   - MongoDB sessions collection: `db.sessions.find()`

### Step 8: Verify User Creation

```bash
# Connect to MongoDB
mongosh

# Switch to your database
use auth-db

# Check if user was created
db.users.find().pretty()

# You should see something like:
{
  _id: ObjectId("..."),
  sapId: "user@sap.com",
  email: "user@company.com",
  name: "John Doe",
  provider: "sap",
  roles: ["user"],
  sapProfile: { ... },
  createdAt: ISODate("2025-..."),
  updatedAt: ISODate("2025-...")
}

# Check session
db.sessions.find({ provider: 'sap' }).pretty()
```

## 🔧 Common SAP OAuth URL Configurations

### SAP Cloud Platform Identity Authentication

```env
SAP_BASE_URL=https://<tenant>.accounts.ondemand.com
SAP_AUTHORIZATION_URL=https://<tenant>.accounts.ondemand.com/oauth2/authorize
SAP_TOKEN_URL=https://<tenant>.accounts.ondemand.com/oauth2/token
SAP_USER_INFO_URL=https://<tenant>.accounts.ondemand.com/oauth2/userinfo
```

### SAP BTP (Business Technology Platform)

```env
SAP_BASE_URL=https://<subdomain>.authentication.<region>.hana.ondemand.com
SAP_AUTHORIZATION_URL=https://<subdomain>.authentication.<region>.hana.ondemand.com/oauth/authorize
SAP_TOKEN_URL=https://<subdomain>.authentication.<region>.hana.ondemand.com/oauth/token
SAP_USER_INFO_URL=https://<subdomain>.authentication.<region>.hana.ondemand.com/userinfo
```

### SAP SuccessFactors

```env
SAP_BASE_URL=https://api<datacenter>.successfactors.com
SAP_AUTHORIZATION_URL=https://api<datacenter>.successfactors.com/oauth/authorize
SAP_TOKEN_URL=https://api<datacenter>.successfactors.com/oauth/token
SAP_USER_INFO_URL=https://api<datacenter>.successfactors.com/odata/v2/User
```

## 🧪 Testing Scenarios

### Test 1: First-time User Login

```bash
# 1. Open browser
http://localhost:3000/auth/sap

# 2. Login with SAP credentials

# 3. Verify in MongoDB
db.users.countDocuments({ provider: 'sap' })
# Should return: 1

# 4. Verify session
db.sessions.countDocuments({ provider: 'sap', isActive: true })
# Should return: 1
```

### Test 2: Existing User Login

```bash
# 1. Login again with same SAP account
http://localhost:3000/auth/sap

# 2. Verify user count (should still be 1)
db.users.countDocuments({ provider: 'sap' })
# Should return: 1 (not 2)

# 3. Verify session was reused (if same browser)
db.sessions.countDocuments({ provider: 'sap', isActive: true })
# Should return: 1 (same session updated)
```

### Test 3: Making SAP API Calls

```javascript
// In your API route
router.get('/api/test-sap', authenticateToken, async (req, res) => {
  try {
    const sapService = require('../services/sap.service');
    
    // Example: Get user profile from SAP
    const profile = await sapService.makeRequest(
      req.session,
      '/api/user/profile',
      'GET'
    );

    res.json({
      success: true,
      data: profile
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});
```

## 🔍 Troubleshooting

### Issue 1: "Redirect URI Mismatch"

**Error:** `redirect_uri_mismatch` or similar

**Solution:**
1. Check SAP OAuth app configuration
2. Ensure `SAP_CALLBACK_URL` in `.env` matches exactly what's registered in SAP
3. Include protocol (`http://` or `https://`)
4. Port number must match if specified

```env
# Make sure this EXACTLY matches SAP configuration
SAP_CALLBACK_URL=http://localhost:3000/auth/sap/callback
```

### Issue 2: "Invalid Client"

**Error:** `invalid_client`

**Solution:**
1. Verify `SAP_CLIENT_ID` and `SAP_CLIENT_SECRET` are correct
2. Check if client is enabled in SAP
3. Verify scopes are allowed for your client

### Issue 3: "User Info Endpoint Failed"

**Error:** 401 or 403 on userinfo endpoint

**Solution:**
1. Verify `SAP_USER_INFO_URL` is correct
2. Check if `openid` scope is included
3. Try alternative endpoints:
   ```env
   # Try these alternatives
   SAP_USER_INFO_URL=https://<domain>/userinfo
   SAP_USER_INFO_URL=https://<domain>/oauth2/userinfo
   SAP_USER_INFO_URL=https://<domain>/oauth/userinfo
   ```

### Issue 4: "Token Expired" on API Calls

**Error:** Token expired when making SAP API calls

**Solution:** The system auto-refreshes tokens, but check:

```javascript
// Verify token refresh is working
db.sessions.find({ provider: 'sap' }, { providerTokens: 1 })

// Check logs
tail -f logs/combined.log | grep "SAP_TOKEN_REFRESHED"
```

### Issue 5: Cannot Find User Model

**Error:** `Cannot find module '../models/User'`

**Solution:** Make sure User model file exists:
```bash
ls -la models/User.js
```

## 📊 Monitoring SAP OAuth

### Check Active SAP Sessions

```javascript
// MongoDB query
db.sessions.aggregate([
  { $match: { provider: 'sap', isActive: true } },
  { $group: {
      _id: '$userId',
      sessionCount: { $sum: 1 },
      lastActivity: { $max: '$lastActivity' }
  }}
])
```

### View Logs

```bash
# All SAP-related logs
tail -f logs/combined.log | grep SAP

# SAP authentication events
tail -f logs/auth.log | grep "SAP_"

# SAP errors