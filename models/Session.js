const mongoose = require('mongoose');
const crypto = require('crypto');

const sessionSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  refreshToken: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  refreshTokenHash: {
    type: String,
    required: true
  },
  deviceInfo: {
    userAgent: String,
    ip: String,
    platform: String,
    browser: String
  },
  isActive: {
    type: Boolean,
    default: true,
    index: true
  },
  lastActivity: {
    type: Date,
    default: Date.now
  },
  expiresAt: {
    type: Date,
    required: true,
    index: true
  },
  // For OAuth providers
  provider: {
    type: String,
    enum: ['local', 'sap', 'google', 'microsoft'],
    default: 'local'
  },
  providerTokens: {
    accessToken: String, // Encrypted
    refreshToken: String, // Encrypted
    expiresAt: Date
  },
  metadata: {
    loginMethod: String,
    loginAt: {
      type: Date,
      default: Date.now
    },
    location: String
  }
}, {
  timestamps: true
});

// Index for cleaning up expired sessions
sessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// Encrypt sensitive provider tokens
sessionSchema.pre('save', function(next) {
  if (this.providerTokens && this.providerTokens.accessToken && !this.providerTokens.accessToken.includes(':')) {
    this.providerTokens.accessToken = encrypt(this.providerTokens.accessToken);
  }
  if (this.providerTokens && this.providerTokens.refreshToken && !this.providerTokens.refreshToken.includes(':')) {
    this.providerTokens.refreshToken = encrypt(this.providerTokens.refreshToken);
  }
  next();
});

// Helper to hash refresh tokens
sessionSchema.statics.hashToken = function(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
};

// Decrypt tokens when needed
sessionSchema.methods.getDecryptedTokens = function() {
  if (!this.providerTokens) return null;
  return {
    accessToken: decrypt(this.providerTokens.accessToken),
    refreshToken: decrypt(this.providerTokens.refreshToken),
    expiresAt: this.providerTokens.expiresAt
  };
};

// Simple encryption helpers using AES-256-CBC
function encrypt(text) {
  if (!text) return null;
  try {
    const algorithm = 'aes-256-cbc';
    const key = crypto.scryptSync(process.env.ENCRYPTION_KEY, 'salt', 32);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
  } catch (error) {
    console.error('Encryption error:', error);
    return text;
  }
}

function decrypt(text) {
  if (!text) return null;
  try {
    const algorithm = 'aes-256-cbc';
    const key = crypto.scryptSync(process.env.ENCRYPTION_KEY, 'salt', 32);
    const parts = text.split(':');
    const iv = Buffer.from(parts[0], 'hex');
    const encryptedText = parts[1];
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (error) {
    console.error('Decryption error:', error);
    return text;
  }
}

module.exports = mongoose.model('Session', sessionSchema);