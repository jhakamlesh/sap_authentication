
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