// ============================================================================
// services/token.service.js
// ============================================================================

const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const config = require('../config/auth.config');
const logger = require('../utils/logger');

class TokenService {
    /**
     * Generate access token with claims
     */
    generateAccessToken(payload) {
        const tokenPayload = {
            sub: payload.userId,
            email: payload.email,
            roles: payload.roles || [],
            sessionId: payload.sessionId,
            type: 'access'
        };

        const token = jwt.sign(tokenPayload, config.jwt.accessTokenSecret, {
            expiresIn: config.jwt.accessTokenExpiry,
            issuer: config.jwt.issuer,
            audience: config.jwt.audience,
            algorithm: config.jwt.algorithm,
            jwtid: crypto.randomUUID()
        });

        logger.logAuthEvent('ACCESS_TOKEN_GENERATED', {
            userId: payload.userId,
            sessionId: payload.sessionId
        });

        return token;
    }

    /**
     * Generate refresh token
     */
    generateRefreshToken(payload) {
        const tokenPayload = {
            sub: payload.userId,
            sessionId: payload.sessionId,
            type: 'refresh'
        };

        const token = jwt.sign(tokenPayload, config.jwt.refreshTokenSecret, {
            expiresIn: config.jwt.refreshTokenExpiry,
            issuer: config.jwt.issuer,
            audience: config.jwt.audience,
            algorithm: config.jwt.algorithm,
            jwtid: crypto.randomUUID()
        });

        logger.logAuthEvent('REFRESH_TOKEN_GENERATED', {
            userId: payload.userId,
            sessionId: payload.sessionId
        });

        return token;
    }

    /**
     * Generate token pair (access + refresh)
     */
    generateTokenPair(payload) {
        return {
            accessToken: this.generateAccessToken(payload),
            refreshToken: this.generateRefreshToken(payload)
        };
    }

    /**
     * Verify access token with full validation
     */
    verifyAccessToken(token) {
        try {
            const decoded = jwt.verify(token, config.jwt.accessTokenSecret, {
                issuer: config.jwt.issuer,
                audience: config.jwt.audience,
                algorithms: [config.jwt.algorithm]
            });

            if (decoded.type !== 'access') {
                throw new Error('Invalid token type');
            }

            logger.debug('Access token verified', {
                userId: decoded.sub,
                sessionId: decoded.sessionId
            });

            return {
                valid: true,
                decoded
            };
        } catch (error) {
            logger.logSecurityEvent('ACCESS_TOKEN_VERIFICATION_FAILED', {
                error: error.message,
                token: token.substring(0, 20) + '...'
            });

            return {
                valid: false,
                error: error.message,
                expired: error.name === 'TokenExpiredError'
            };
        }
    }

    /**
     * Verify refresh token
     */
    verifyRefreshToken(token) {
        try {
            const decoded = jwt.verify(token, config.jwt.refreshTokenSecret, {
                issuer: config.jwt.issuer,
                audience: config.jwt.audience,
                algorithms: [config.jwt.algorithm]
            });

            if (decoded.type !== 'refresh') {
                throw new Error('Invalid token type');
            }

            logger.debug('Refresh token verified', {
                userId: decoded.sub,
                sessionId: decoded.sessionId
            });

            return {
                valid: true,
                decoded
            };
        } catch (error) {
            logger.logSecurityEvent('REFRESH_TOKEN_VERIFICATION_FAILED', {
                error: error.message
            });

            return {
                valid: false,
                error: error.message,
                expired: error.name === 'TokenExpiredError'
            };
        }
    }
}

module.exports = new TokenService();