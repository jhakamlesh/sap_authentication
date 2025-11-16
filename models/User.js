
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
        required: function () {
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
userSchema.methods.changedPasswordAfter = function (JWTTimestamp) {
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