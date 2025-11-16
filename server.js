// ============================================================================
// server.js - Complete Production Server with SAP OAuth
// ============================================================================
const express = require('express');
const mongoose = require('mongoose');
const helmet = require('helmet');
const cors = require('cors');
const passport = require('passport');
require('dotenv').config();

// Import routes and middleware
const authRoutes = require('./routes/auth.routes');
const { authenticateToken, requireRole } = require('./middlewares/auth.middleware');
const { requestTracking, errorTracking } = require('./middlewares/request-tracking.middleware');
const logger = require('./utils/logger');

// Initialize SAP strategy
require('./strategies/sap.strategy');

const app = express();

// ============================================================================
// SECURITY MIDDLEWARE
// ============================================================================
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"],
        },
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    }
}));

// ============================================================================
// CORS CONFIGURATION
// ============================================================================
app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:3000',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-ID']
}));

// ============================================================================
// BODY PARSING
// ============================================================================
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ============================================================================
// PASSPORT INITIALIZATION
// ============================================================================
app.use(passport.initialize());

// ============================================================================
// REQUEST TRACKING
// ============================================================================
app.use(requestTracking);

// ============================================================================
// HEALTH CHECK ENDPOINTS
// ============================================================================
app.get('/health', async (req, res) => {
    const health = {
        status: 'ok',
        timestamp: new Date().toISOString(),
        service: process.env.SERVICE_NAME || 'auth-service',
        version: process.env.APP_VERSION || '1.0.0',
        uptime: process.uptime(),
        checks: {}
    };

    try {
        // Check MongoDB
        const mongoState = mongoose.connection.readyState;
        health.checks.mongodb = {
            status: mongoState === 1 ? 'ok' : 'error',
            details: {
                state: ['disconnected', 'connected', 'connecting', 'disconnecting'][mongoState]
            }
        };

        // Check memory
        const memoryUsage = process.memoryUsage();
        health.checks.memory = {
            status: memoryUsage.heapUsed < memoryUsage.heapTotal * 0.9 ? 'ok' : 'warning',
            details: {
                heapUsed: Math.round(memoryUsage.heapUsed / 1024 / 1024) + 'MB',
                heapTotal: Math.round(memoryUsage.heapTotal / 1024 / 1024) + 'MB',
                rss: Math.round(memoryUsage.rss / 1024 / 1024) + 'MB'
            }
        };

        // Check Application Insights
        const appInsights = require('applicationinsights');
        health.checks.applicationInsights = {
            status: appInsights.defaultClient ? 'ok' : 'disabled',
            details: {
                enabled: !!process.env.APPLICATIONINSIGHTS_CONNECTION_STRING
            }
        };

        const hasErrors = Object.values(health.checks).some(check => check.status === 'error');
        health.status = hasErrors ? 'error' : 'ok';

        res.status(hasErrors ? 503 : 200).json(health);
    } catch (error) {
        logger.error('Health check failed', { error: error.message });
        res.status(503).json({ ...health, status: 'error', error: error.message });
    }
});

app.get('/ready', (req, res) => {
    const isReady = mongoose.connection.readyState === 1;
    res.status(isReady ? 200 : 503).json({
        status: isReady ? 'ready' : 'not ready'
    });
});

app.get('/alive', (req, res) => {
    res.status(200).json({ status: 'alive' });
});

// ============================================================================
// API ROUTES
// ============================================================================

// Auth routes (public)
app.use('/auth', authRoutes);

// Protected routes - User Profile
app.get('/api/profile', authenticateToken, async (req, res) => {
    try {
        const User = require('./models/User');
        const user = await User.findById(req.user.id).select('-password');

        if (!user) {
            return res.status(404).json({
                success: false,
                error: 'User not found',
                code: 'USER_NOT_FOUND'
            });
        }

        req.logger.info('Profile accessed', { userId: req.user.id });

        res.json({
            success: true,
            data: {
                id: user._id,
                email: user.email,
                name: user.name,
                firstName: user.firstName,
                lastName: user.lastName,
                roles: user.roles,
                provider: user.provider,
                emailVerified: user.emailVerified,
                lastLogin: user.lastLogin,
                createdAt: user.createdAt
            }
        });
    } catch (error) {
        req.logger.error('Failed to fetch profile', {
            error: error.message,
            userId: req.user.id
        });

        res.status(500).json({
            success: false,
            error: 'Failed to fetch profile'
        });
    }
});

// Protected route - Update Profile
app.put('/api/profile', authenticateToken, async (req, res) => {
    try {
        const User = require('./models/User');
        const { name, firstName, lastName } = req.body;

        const user = await User.findByIdAndUpdate(
            req.user.id,
            { name, firstName, lastName },
            { new: true, runValidators: true }
        ).select('-password');

        req.logger.info('Profile updated', { userId: req.user.id });

        res.json({
            success: true,
            data: user
        });
    } catch (error) {
        req.logger.error('Failed to update profile', {
            error: error.message,
            userId: req.user.id
        });

        res.status(500).json({
            success: false,
            error: 'Failed to update profile'
        });
    }
});

// Example: SAP Business Data endpoint (requires SAP authentication)
app.get('/api/sap/business-data', authenticateToken, async (req, res) => {
    try {
        // Check if user authenticated via SAP
        if (req.session.provider !== 'sap') {
            return res.status(403).json({
                success: false,
                error: 'This endpoint requires SAP authentication',
                code: 'SAP_AUTH_REQUIRED'
            });
        }

        const sapService = require('./services/sap.service');

        // Get data from SAP API
        const data = await sapService.getBusinessData(req.session, {
            category: req.query.category,
            limit: parseInt(req.query.limit) || 10
        });

        req.logger.info('SAP business data accessed', {
            userId: req.user.id,
            category: req.query.category
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

// Admin only route
app.get('/api/admin/users',
    authenticateToken,
    requireRole('admin'),
    async (req, res) => {
        try {
            const User = require('./models/User');

            const page = parseInt(req.query.page) || 1;
            const limit = parseInt(req.query.limit) || 10;
            const skip = (page - 1) * limit;

            const users = await User.find()
                .select('-password')
                .skip(skip)
                .limit(limit)
                .sort({ createdAt: -1 });

            const total = await User.countDocuments();

            req.logger.info('Admin users list accessed', {
                adminId: req.user.id,
                page,
                limit
            });

            res.json({
                success: true,
                data: {
                    users,
                    pagination: {
                        page,
                        limit,
                        total,
                        pages: Math.ceil(total / limit)
                    }
                }
            });
        } catch (error) {
            req.logger.error('Admin operation failed', {
                error: error.message,
                adminId: req.user.id
            });

            res.status(500).json({
                success: false,
                error: 'Operation failed'
            });
        }
    }
);

// Test route - Protected
app.get('/api/test', authenticateToken, (req, res) => {
    res.json({
        success: true,
        message: 'Protected route accessed successfully',
        user: req.user,
        timestamp: new Date().toISOString()
    });
});

// ============================================================================
// 404 HANDLER
// ============================================================================
app.use((req, res) => {
    res.status(404).json({
        success: false,
        error: 'Route not found',
        code: 'NOT_FOUND',
        path: req.path
    });
});

// ============================================================================
// ERROR HANDLING
// ============================================================================
app.use(errorTracking);

// ============================================================================
// GRACEFUL SHUTDOWN
// ============================================================================
const gracefulShutdown = async (signal) => {
    logger.info(`${signal} received, starting graceful shutdown`);

    try {
        // Stop accepting new connections
        if (server) {
            server.close(() => {
                logger.info('HTTP server closed');
            });
        }

        // Flush Application Insights
        await logger.flush();
        logger.info('Application Insights flushed');

        // Close database connections
        await mongoose.connection.close();
        logger.info('MongoDB connection closed');

        logger.info('Graceful shutdown completed');
        process.exit(0);
    } catch (error) {
        logger.error('Error during shutdown', {
            error: error.message,
            stack: error.stack
        });
        process.exit(1);
    }
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// ============================================================================
// UNHANDLED ERRORS
// ============================================================================
process.on('unhandledRejection', (reason, promise) => {
    logger.error('Unhandled Rejection', {
        reason: reason instanceof Error ? reason.message : reason,
        stack: reason instanceof Error ? reason.stack : undefined
    });
});

process.on('uncaughtException', (error) => {
    logger.error('Uncaught Exception', {
        error: error.message,
        stack: error.stack
    });

    setTimeout(() => {
        process.exit(1);
    }, 1000);
});

// ============================================================================
// DATABASE CONNECTION & SERVER START
// ============================================================================
let server;

async function startServer() {
    try {
        // Connect to MongoDB
        await mongoose.connect(process.env.MONGODB_URI, {
            serverSelectionTimeoutMS: 5000,
            socketTimeoutMS: 45000,
        });

        logger.info('MongoDB connected successfully', {
            database: mongoose.connection.name
        });

        logger.trackDependency('MongoDB', 'connect', 0, true, {
            type: 'Database',
            database: mongoose.connection.name
        });

        // Create indexes
        await createIndexes();

        // Start session cleanup job
        const sessionService = require('./services/session.service');
        setInterval(() => {
            sessionService.cleanupExpiredSessions()
                .then(result => {
                    if (result.deletedCount > 0) {
                        logger.info('Session cleanup completed', {
                            deletedCount: result.deletedCount
                        });
                    }
                })
                .catch(error => {
                    logger.error('Session cleanup failed', {
                        error: error.message
                    });
                });
        }, 3600000); // Every hour

        // Start server
        const PORT = process.env.PORT || 3000;
        server = app.listen(PORT, () => {
            logger.info(`🚀 Server started successfully`, {
                port: PORT,
                environment: process.env.NODE_ENV || 'development',
                version: process.env.APP_VERSION || '1.0.0',
                nodeVersion: process.version
            });

            console.log(`
                        ╔══════════════════════════════════════════════════════════╗
                        ║                                                          ║
                        ║  🔐 Auth Service with SAP OAuth Running                  ║
                        ║                                                          ║
                        ║  Environment: ${(process.env.NODE_ENV || 'development').padEnd(43)} ║
                        ║  Port:        ${String(PORT).padEnd(43)} ║
                        ║  Version:     ${(process.env.APP_VERSION || '1.0.0').padEnd(43)} ║
                        ║                                                          ║
                        ║  Authentication Endpoints:                               ║
                        ║  - POST   /auth/login           (Email/Password)         ║
                        ║  - GET    /auth/sap             (SAP OAuth Redirect)     ║
                        ║  - GET    /auth/sap/callback    (SAP OAuth Callback)     ║
                        ║  - POST   /auth/sap/login       (SAP ROPC - Direct)      ║
                        ║  - POST   /auth/refresh         (Token Refresh)          ║
                        ║  - POST   /auth/logout          (Logout)                 ║
                        ║  - POST   /auth/logout-all      (Logout All Sessions)    ║
                        ║  - GET    /auth/sessions        (Active Sessions)        ║
                        ║                                                          ║
                        ║  Protected Endpoints:                                    ║
                        ║  - GET    /api/profile          (User Profile)           ║
                        ║  - PUT    /api/profile          (Update Profile)         ║
                        ║  - GET    /api/test             (Test Protected)         ║
                        ║  - GET    /api/sap/business-data (SAP Data)              ║
                        ║  - GET    /api/admin/users      (Admin Only)             ║
                        ║                                                          ║
                        ║  Health Checks:                                          ║
                        ║  - GET    /health               (Health Status)          ║
                        ║  - GET    /ready                (Readiness Probe)        ║
                        ║  - GET    /alive                (Liveness Probe)         ║
                        ║                                                          ║
                        ╚══════════════════════════════════════════════════════════╝

                        👉 Test SAP OAuth: http://localhost:${PORT}/auth/sap
                        👉 API Documentation: http://localhost:${PORT}/health
      `);
        });

        // Handle server errors
        server.on('error', (error) => {
            logger.error('Server error', {
                error: error.message,
                code: error.code
            });

            if (error.code === 'EADDRINUSE') {
                logger.error(`Port ${PORT} is already in use`);
            }

            process.exit(1);
        });

    } catch (err) {
        logger.error('Failed to start server', {
            error: err.message,
            stack: err.stack
        });

        logger.trackDependency('MongoDB', 'connect', 0, false, {
            type: 'Database',
            error: err.message
        });

        console.error('❌ Failed to start server');
        console.error(`Error: ${err.message}`);
        process.exit(1);
    }
}

// Create database indexes
async function createIndexes() {
    try {
        const User = require('./models/User');
        const Session = require('./models/Session');

        // User indexes
        await User.collection.createIndex({ email: 1 }, { unique: true });
        await User.collection.createIndex({ sapId: 1 }, { unique: true, sparse: true });
        await User.collection.createIndex({ provider: 1, sapId: 1 });
        await User.collection.createIndex({ email: 1, provider: 1 });

        // Session indexes
        await Session.collection.createIndex({ userId: 1, isActive: 1 });
        await Session.collection.createIndex({ refreshTokenHash: 1 }, { unique: true });
        await Session.collection.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
        await Session.collection.createIndex({ userId: 1, lastActivity: -1 });

        logger.info('Database indexes created successfully');
    } catch (error) {
        logger.error('Failed to create indexes', { error: error.message });
    }
}

// Start the server
startServer();

module.exports = app;