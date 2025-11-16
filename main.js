// ============================================================================
// main.js - Application Entry Point
// ============================================================================
// This file serves as the main entry point for the application.
// It handles environment setup, validation, and starts the server.
// ============================================================================

'use strict';

const path = require('path');
const fs = require('fs');

// ============================================================================
// ENVIRONMENT CONFIGURATION
// ============================================================================

// Load environment variables
require('dotenv').config();

// Set default NODE_ENV if not specified
process.env.NODE_ENV = process.env.NODE_ENV || 'development';

// ============================================================================
// ENVIRONMENT VALIDATION
// ============================================================================

const requiredEnvVars = [
    'MONGODB_URI',
    'JWT_ACCESS_SECRET',
    'JWT_REFRESH_SECRET',
    'ENCRYPTION_KEY'
];

const missingVars = requiredEnvVars.filter(varName => !process.env[varName]);

if (missingVars.length > 0) {
    console.error('❌ Missing required environment variables:');
    missingVars.forEach(varName => {
        console.error(`   - ${varName}`);
    });
    console.error('\n💡 Please check your .env file');
    console.error('   Copy .env.example to .env and fill in the values\n');
    process.exit(1);
}

// Validate JWT secrets length (minimum 32 characters for security)
if (process.env.JWT_ACCESS_SECRET.length < 32) {
    console.error('❌ JWT_ACCESS_SECRET must be at least 32 characters long');
    process.exit(1);
}

if (process.env.JWT_REFRESH_SECRET.length < 32) {
    console.error('❌ JWT_REFRESH_SECRET must be at least 32 characters long');
    process.exit(1);
}

if (process.env.ENCRYPTION_KEY.length < 32) {
    console.error('❌ ENCRYPTION_KEY must be at least 32 characters long');
    process.exit(1);
}

// ============================================================================
// DIRECTORY SETUP
// ============================================================================

// Ensure logs directory exists
const logsDir = path.join(__dirname, 'logs');
if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir, { recursive: true });
    console.log('📁 Created logs directory');
}

// ============================================================================
// CONFIGURATION VALIDATION
// ============================================================================

function validateConfiguration() {
    const warnings = [];
    const errors = [];

    // Check SAP OAuth configuration if being used
    const sapConfigVars = [
        'SAP_BASE_URL',
        'SAP_CLIENT_ID',
        'SAP_CLIENT_SECRET',
        'SAP_AUTHORIZATION_URL',
        'SAP_TOKEN_URL',
        'SAP_USER_INFO_URL',
        'SAP_CALLBACK_URL'
    ];

    const hasSomeConfig = sapConfigVars.some(varName => process.env[varName]);
    const hasAllConfig = sapConfigVars.every(varName => process.env[varName]);

    if (hasSomeConfig && !hasAllConfig) {
        warnings.push('⚠️  Partial SAP OAuth configuration detected. SAP authentication may not work.');
        const missingSapVars = sapConfigVars.filter(varName => !process.env[varName]);
        warnings.push(`   Missing: ${missingSapVars.join(', ')}`);
    }

    // Check Application Insights
    if (!process.env.APPLICATIONINSIGHTS_CONNECTION_STRING) {
        warnings.push('⚠️  Application Insights is not configured. Advanced monitoring disabled.');
    }

    // Check FRONTEND_URL
    if (!process.env.FRONTEND_URL) {
        warnings.push('⚠️  FRONTEND_URL not set. Using default: http://localhost:3000');
    }

    // Validate MongoDB URI format
    if (!process.env.MONGODB_URI.startsWith('mongodb://') &&
        !process.env.MONGODB_URI.startsWith('mongodb+srv://')) {
        errors.push('❌ Invalid MONGODB_URI format. Must start with mongodb:// or mongodb+srv://');
    }

    // Production checks
    if (process.env.NODE_ENV === 'production') {
        if (process.env.JWT_ACCESS_SECRET === 'your-super-secret-access-key-min-32-chars') {
            errors.push('❌ PRODUCTION: You must change default JWT_ACCESS_SECRET!');
        }

        if (process.env.JWT_REFRESH_SECRET === 'your-super-secret-refresh-key-min-32-chars') {
            errors.push('❌ PRODUCTION: You must change default JWT_REFRESH_SECRET!');
        }

        if (process.env.ENCRYPTION_KEY === 'your-32-character-encryption-key') {
            errors.push('❌ PRODUCTION: You must change default ENCRYPTION_KEY!');
        }

        if (!process.env.APPLICATIONINSIGHTS_CONNECTION_STRING) {
            warnings.push('⚠️  PRODUCTION: Application Insights recommended for production monitoring');
        }
    }

    // Display warnings
    if (warnings.length > 0) {
        console.log('\n📋 Configuration Warnings:');
        warnings.forEach(warning => console.log(warning));
    }

    // Display errors and exit if any
    if (errors.length > 0) {
        console.error('\n❌ Configuration Errors:');
        errors.forEach(error => console.error(error));
        console.error('\n');
        process.exit(1);
    }

    return warnings.length === 0;
}

// ============================================================================
// STARTUP BANNER
// ============================================================================

function displayStartupBanner() {
    const configStatus = validateConfiguration();

    console.log('\n');
    console.log('╔══════════════════════════════════════════════════════════╗');
    console.log('║                                                          ║');
    console.log('║        🔐 Authentication Service Starting...             ║');
    console.log('║                                                          ║');
    console.log('╚══════════════════════════════════════════════════════════╝');
    console.log('');
    console.log(`📦 Service:      ${process.env.SERVICE_NAME || 'auth-service'}`);
    console.log(`🏷️  Version:      ${process.env.APP_VERSION || '1.0.0'}`);
    console.log(`🌍 Environment:  ${process.env.NODE_ENV}`);
    console.log(`🔌 Port:         ${process.env.PORT || 3000}`);
    console.log(`📊 Node.js:      ${process.version}`);
    console.log('');
    console.log('📂 Configuration:');
    console.log(`   ✅ MongoDB:              Configured`);
    console.log(`   ✅ JWT:                  Configured`);
    console.log(`   ${process.env.APPLICATIONINSIGHTS_CONNECTION_STRING ? '✅' : '⚠️ '} Application Insights: ${process.env.APPLICATIONINSIGHTS_CONNECTION_STRING ? 'Enabled' : 'Disabled'}`);

    // SAP OAuth status
    const hasSapConfig = process.env.SAP_CLIENT_ID &&
        process.env.SAP_CLIENT_SECRET &&
        process.env.SAP_BASE_URL;
    console.log(`   ${hasSapConfig ? '✅' : '⚠️ '} SAP OAuth:           ${hasSapConfig ? 'Configured' : 'Not Configured'}`);

    console.log('');
    console.log('🔧 Features:');
    console.log('   ✅ JWT Authentication');
    console.log('   ✅ Session Management');
    console.log('   ✅ Token Refresh');
    console.log('   ✅ Role-based Access Control');
    console.log(`   ${hasSapConfig ? '✅' : '⚠️ '} SAP OAuth Integration`);
    console.log('   ✅ Request Tracking');
    console.log('   ✅ Security Logging');
    console.log('');

    if (!configStatus) {
        console.log('⚠️  Some warnings detected (see above)\n');
    }

    console.log('🚀 Starting server...\n');
}

// ============================================================================
// ERROR HANDLERS FOR STARTUP
// ============================================================================

process.on('warning', (warning) => {
    console.warn('⚠️  Node.js Warning:', warning.name);
    console.warn('   Message:', warning.message);
    console.warn('   Stack:', warning.stack);
});

// ============================================================================
// MAIN EXECUTION
// ============================================================================

async function main() {
    try {
        // Display startup banner
        displayStartupBanner();

        // Start the server
        require('./server');

    } catch (error) {
        console.error('\n❌ Failed to start application');
        console.error('Error:', error.message);
        if (error.stack) {
            console.error('\nStack Trace:');
            console.error(error.stack);
        }
        console.error('');
        process.exit(1);
    }
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

// Function to generate secure secrets (for development setup)
function generateSecrets() {
    const crypto = require('crypto');

    console.log('\n🔐 Generated Secure Secrets (add to .env):');
    console.log('');
    console.log(`JWT_ACCESS_SECRET=${crypto.randomBytes(32).toString('hex')}`);
    console.log(`JWT_REFRESH_SECRET=${crypto.randomBytes(32).toString('hex')}`);
    console.log(`ENCRYPTION_KEY=${crypto.randomBytes(32).toString('hex')}`);
    console.log('');
}

// Command line arguments handling
const args = process.argv.slice(2);

if (args.includes('--generate-secrets')) {
    generateSecrets();
    process.exit(0);
}

if (args.includes('--help') || args.includes('-h')) {
    console.log(`
                Usage: node main.js [options]

                Options:
                --help, -h              Show this help message
                --generate-secrets      Generate secure random secrets for .env
                --check-config          Validate configuration without starting server

                Environment Variables:
                Required:
                    MONGODB_URI            MongoDB connection string
                    JWT_ACCESS_SECRET      Secret for access tokens (min 32 chars)
                    JWT_REFRESH_SECRET     Secret for refresh tokens (min 32 chars)
                    ENCRYPTION_KEY         Encryption key (min 32 chars)

                Optional:
                    NODE_ENV               Environment (development/production/test)
                    PORT                   Server port (default: 3000)
                    LOG_LEVEL              Logging level (default: info)
                    FRONTEND_URL           Frontend URL for CORS
                    
                SAP OAuth (Optional):
                    SAP_BASE_URL           SAP instance base URL
                    SAP_CLIENT_ID          SAP OAuth client ID
                    SAP_CLIENT_SECRET      SAP OAuth client secret
                    SAP_AUTHORIZATION_URL  SAP authorization endpoint
                    SAP_TOKEN_URL          SAP token endpoint
                    SAP_USER_INFO_URL      SAP user info endpoint
                    SAP_CALLBACK_URL       OAuth callback URL

                Monitoring (Optional):
                    APPLICATIONINSIGHTS_CONNECTION_STRING  Azure Application Insights

                Examples:
                npm start                    Start the server
                node main.js --generate-secrets  Generate secure secrets
                node main.js --check-config     Validate configuration

                For more information, see README.md
  `);
    process.exit(0);
}

if (args.includes('--check-config')) {
    console.log('\n🔍 Checking configuration...\n');
    const isValid = validateConfiguration();

    if (isValid) {
        console.log('\n✅ Configuration is valid!\n');
        process.exit(0);
    } else {
        console.log('\n⚠️  Configuration has warnings (see above)\n');
        process.exit(0);
    }
}

// ============================================================================
// START APPLICATION
// ============================================================================

main();

// Export for testing
module.exports = { validateConfiguration, generateSecrets };