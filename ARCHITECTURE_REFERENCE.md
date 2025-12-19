🔐 Enterprise-Grade Authentication System Architecture
📋 Architecture Decision Record (ADR)
Context
We need a authentication system that handles millions of users with zero-trust security principles, capable of detecting and preventing attacks in real-time while maintaining sub-150ms response times.
Decision
We'll implement a multi-layered, defense-in-depth authentication architecture with:

Dual-token JWT system (short-lived access + long-lived refresh)
Automatic token rotation on every refresh
Redis-based token registry (allowlist pattern, not blacklist)
Device fingerprinting for anomaly detection
Progressive rate limiting (IP + user-based)
Stateless access tokens + stateful refresh tokens
Refresh token families to detect token theft
HttpOnly, Secure, SameSite cookies for web clients
Audit logging for all authentication events

Rationale
PatternWhy We Chose ItAlternative RejectedAllowlist (not blacklist)Scales better, explicit securityBlacklist grows infinitelyRefresh token rotationDetects token theft immediatelyStatic refresh tokens are vulnerableToken familiesInvalidates entire chain on reuseSingle token revocation insufficientDevice fingerprintingDetects session hijackingIP-only detection fails with VPNsHttpOnly cookiesXSS-proofLocalStorage vulnerable to XSSRedis registrySub-5ms lookup, TTL auto-cleanupDB queries too slow

🛡️ Threat Model & Mitigations
Attack Vectors & Our Defense
╔════════════════════════════════════════════════════════════════╗
║ THREAT │ MITIGATION STRATEGY ║
╠════════════════════════════════════════════════════════════════╣
║ Brute Force Login │ Progressive rate limiting ║
║ │ Account lockout after 5 attempts ║
║ │ CAPTCHA after 3 failures ║
╠════════════════════════════════════════════════════════════════╣
║ Token Theft (XSS) │ HttpOnly + Secure cookies ║
║ │ CSP headers ║
║ │ No tokens in localStorage ║
╠════════════════════════════════════════════════════════════════╣
║ Token Theft (Network) │ HTTPS only, HSTS enabled ║
║ │ Short access token TTL (15min) ║
╠════════════════════════════════════════════════════════════════╣
║ Refresh Token Reuse │ Token family rotation ║
║ │ Invalidate entire chain on reuse ║
╠════════════════════════════════════════════════════════════════╣
║ Session Hijacking │ Device fingerprinting ║
║ │ IP + User-Agent tracking ║
║ │ Anomaly detection ║
╠════════════════════════════════════════════════════════════════╣
║ CSRF │ SameSite=Strict cookies ║
║ │ Double-submit cookie pattern ║
╠════════════════════════════════════════════════════════════════╣
║ Timing Attacks │ Constant-time password comparison ║
║ │ Generic error messages ║
╠════════════════════════════════════════════════════════════════╣
║ Password Database Leak │ Argon2id hashing (not bcrypt) ║
║ │ Per-user salt ║
║ │ Pepper in environment variable ║
╠════════════════════════════════════════════════════════════════╣
║ Privilege Escalation │ RBAC with principle of least priv ║
║ │ Permission checks at every layer ║
╚════════════════════════════════════════════════════════════════╝

🗄️ MongoDB Schema Design
User Collection
javascript// backend/features/auth/models/user.model.js

import mongoose from 'mongoose';
import argon2 from 'argon2';

const userSchema = new mongoose.Schema(
{
email: {
type: String,
required: true,
unique: true,
lowercase: true,
trim: true,
index: true, // For login queries
match: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
},

    password: {
      type: String,
      required: true,
      select: false, // Never return in queries by default
      minlength: 8,
    },

    profile: {
      firstName: { type: String, required: true, trim: true },
      lastName: { type: String, required: true, trim: true },
      phoneNumber: { type: String, sparse: true },
    },

    roles: {
      type: [String],
      enum: ['user', 'admin', 'moderator', 'superadmin'],
      default: ['user'],
      index: true, // For role-based queries
    },

    permissions: {
      type: [String],
      default: [],
      // e.g., ['posts:create', 'posts:delete', 'users:manage']
    },

    security: {
      emailVerified: { type: Boolean, default: false },
      emailVerificationToken: { type: String, select: false },
      emailVerificationExpires: { type: Date, select: false },

      passwordChangedAt: Date,
      passwordResetToken: { type: String, select: false },
      passwordResetExpires: { type: Date, select: false },

      twoFactorEnabled: { type: Boolean, default: false },
      twoFactorSecret: { type: String, select: false },

      failedLoginAttempts: { type: Number, default: 0 },
      lockUntil: Date,

      lastPasswordChange: Date,
      passwordHistory: {
        type: [String],
        select: false,
        maxlength: 5, // Prevent password reuse
      },
    },

    status: {
      type: String,
      enum: ['active', 'suspended', 'deleted'],
      default: 'active',
      index: true,
    },

    metadata: {
      lastLogin: Date,
      lastLoginIp: String,
      lastLoginDevice: String,
      loginCount: { type: Number, default: 0 },
      createdIp: String,
      createdDevice: String,
    },

},
{
timestamps: true, // Adds createdAt, updatedAt
collection: 'users',
}
);

// ============= INDEXES =============

// Compound index for email + status (most common query)
userSchema.index({ email: 1, status: 1 });

// For admin dashboard queries
userSchema.index({ createdAt: -1 });
userSchema.index({ 'metadata.lastLogin': -1 });

// For role-based access control
userSchema.index({ roles: 1, status: 1 });

// Partial index for locked accounts (memory efficient)
userSchema.index(
{ 'security.lockUntil': 1 },
{ partialFilterExpression: { 'security.lockUntil': { $gt: new Date() } } }
);

// ============= SHARDING STRATEGY =============
// Shard key: { email: 'hashed' }
// Rationale: Email is immutable, evenly distributed, used in all queries
// Alternative: { \_id: 'hashed' } if email changes are allowed

// ============= VIRTUAL FIELDS =============

userSchema.virtual('fullName').get(function () {
return `${this.profile.firstName} ${this.profile.lastName}`;
});

userSchema.virtual('isLocked').get(function () {
return !!(this.security.lockUntil && this.security.lockUntil > Date.now());
});

// ============= MIDDLEWARE =============

// Hash password before saving
userSchema.pre('save', async function (next) {
if (!this.isModified('password')) return next();

try {
// Argon2id: Memory-hard, side-channel resistant
// Better than bcrypt for modern threats
this.password = await argon2.hash(this.password, {
type: argon2.argon2id,
memoryCost: 2 \*\* 16, // 64 MB
timeCost: 3,
parallelism: 1,
});

    // Track password change timestamp
    if (!this.isNew) {
      this.security.passwordChangedAt = Date.now() - 1000; // 1s buffer for JWT
    }

    next();

} catch (error) {
next(error);
}
});

// ============= INSTANCE METHODS =============

// Constant-time password verification
userSchema.methods.verifyPassword = async function (candidatePassword) {
try {
return await argon2.verify(this.password, candidatePassword);
} catch (error) {
return false;
}
};

// Check if password was changed after JWT was issued
userSchema.methods.changedPasswordAfter = function (jwtTimestamp) {
if (this.security.passwordChangedAt) {
const changedTimestamp = parseInt(
this.security.passwordChangedAt.getTime() / 1000,
10
);
return jwtTimestamp < changedTimestamp;
}
return false;
};

// Handle failed login attempts with progressive lockout
userSchema.methods.handleFailedLogin = async function () {
this.security.failedLoginAttempts += 1;

// Lock after 5 failed attempts
if (this.security.failedLoginAttempts >= 5) {
// Progressive lockout: 15min, 1hr, 24hr
const lockDuration =
this.security.failedLoginAttempts === 5
? 15 _ 60 _ 1000 // 15 minutes
: this.security.failedLoginAttempts === 6
? 60 _ 60 _ 1000 // 1 hour
: 24 _ 60 _ 60 \* 1000; // 24 hours

    this.security.lockUntil = Date.now() + lockDuration;

}

await this.save();
};

// Reset login attempts on successful login
userSchema.methods.resetLoginAttempts = async function () {
this.security.failedLoginAttempts = 0;
this.security.lockUntil = undefined;
await this.save();
};

// ============= STATIC METHODS =============

// Find user by email (safe - doesn't expose password)
userSchema.statics.findByEmail = function (email) {
return this.findOne({ email: email.toLowerCase(), status: 'active' });
};

// Find user with password (for login only)
userSchema.statics.findByEmailWithPassword = function (email) {
return this.findOne({ email: email.toLowerCase(), status: 'active' }).select(
'+password +security'
);
};

// ============= EXPORT =============

export default mongoose.model('User', userSchema);
Refresh Token Collection (Separate for Security)
javascript// backend/features/auth/models/refreshToken.model.js

import mongoose from 'mongoose';

const refreshTokenSchema = new mongoose.Schema(
{
userId: {
type: mongoose.Schema.Types.ObjectId,
ref: 'User',
required: true,
index: true,
},

    token: {
      type: String,
      required: true,
      unique: true,
      index: true, // For fast lookup
    },

    family: {
      type: String,
      required: true,
      index: true, // For revoking entire token families
    },

    // Device fingerprint components
    deviceFingerprint: {
      userAgent: String,
      ip: String,
      deviceId: String, // Client-generated stable ID
      hash: {
        type: String,
        required: true,
        index: true,
      },
    },

    expiresAt: {
      type: Date,
      required: true,
      index: true, // For TTL cleanup
    },

    createdAt: {
      type: Date,
      default: Date.now,
      expires: 90 * 24 * 60 * 60, // TTL: Auto-delete after 90 days
    },

    revokedAt: Date,
    replacedBy: String, // Token that replaced this one

    metadata: {
      createdIp: String,
      createdUserAgent: String,
      lastUsedAt: Date,
      lastUsedIp: String,
    },

},
{
timestamps: false,
collection: 'refresh_tokens',
}
);

// ============= INDEXES =============

// Compound index for user + active tokens
refreshTokenSchema.index({ userId: 1, expiresAt: 1 });
refreshTokenSchema.index({ userId: 1, revokedAt: 1 });

// For token family revocation
refreshTokenSchema.index({ family: 1, revokedAt: 1 });

// For device fingerprint matching
refreshTokenSchema.index({ 'deviceFingerprint.hash': 1 });

// ============= SHARDING STRATEGY =============
// Shard key: { userId: 1, family: 1 }
// Rationale: Queries are always scoped to user, family ensures distribution

// ============= STATIC METHODS =============

refreshTokenSchema.statics.revokeFamily = async function (family) {
return this.updateMany(
{ family, revokedAt: null },
{ revokedAt: new Date() }
);
};

refreshTokenSchema.statics.revokeAllUserTokens = async function (userId) {
return this.updateMany(
{ userId, revokedAt: null },
{ revokedAt: new Date() }
);
};

refreshTokenSchema.statics.cleanupExpired = async function () {
return this.deleteMany({
expiresAt: { $lt: new Date() },
});
};

export default mongoose.model('RefreshToken', refreshTokenSchema);

🔴 Redis Architecture
Redis Key Patterns
javascript// backend/features/auth/config/redis-keys.js

export const REDIS_KEYS = {
// Access token allowlist (short TTL, memory efficient)
ACCESS_TOKEN: (tokenId) => `auth:access:${tokenId}`, // TTL: 15min

// Rate limiting
RATE_LIMIT_LOGIN: (ip) => `rate:login:${ip}`, // TTL: 15min
RATE_LIMIT_REFRESH: (userId) => `rate:refresh:${userId}`, // TTL: 1hr
RATE_LIMIT_API: (userId) => `rate:api:${userId}`, // TTL: 1min

// Suspicious activity tracking
FAILED_ATTEMPTS: (email) => `auth:failed:${email}`, // TTL: 1hr
SUSPICIOUS_IP: (ip) => `auth:suspicious:${ip}`, // TTL: 24hr

// Session tracking
ACTIVE_SESSIONS: (userId) => `auth:sessions:${userId}`, // SET
DEVICE_FINGERPRINT: (userId, deviceId) =>
`auth:device:${userId}:${deviceId}`, // TTL: 90 days

// Email verification & password reset
EMAIL_VERIFY_TOKEN: (token) => `auth:verify:${token}`, // TTL: 24hr
PASSWORD_RESET_TOKEN: (token) => `auth:reset:${token}`, // TTL: 1hr

// Lockout cache (prevent DB hits)
USER_LOCKED: (userId) => `auth:locked:${userId}`, // TTL: from DB
};

export const REDIS_TTL = {
ACCESS_TOKEN: 15 _ 60, // 15 minutes
REFRESH_TOKEN: 90 _ 24 _ 60 _ 60, // 90 days
RATE_LIMIT_LOGIN: 15 _ 60, // 15 minutes
RATE_LIMIT_REFRESH: 60 _ 60, // 1 hour
RATE_LIMIT_API: 60, // 1 minute
FAILED_ATTEMPTS: 60 _ 60, // 1 hour
SUSPICIOUS_IP: 24 _ 60 _ 60, // 24 hours
EMAIL_VERIFY: 24 _ 60 _ 60, // 24 hours
PASSWORD_RESET: 60 _ 60, // 1 hour
};
Redis Service Layer
javascript// backend/features/auth/services/redis-auth.service.js

import redisClient from '../../../config/redis.js';
import { REDIS_KEYS, REDIS_TTL } from '../config/redis-keys.js';
import logger from '../../../utils/logger.js';

class RedisAuthService {
/\*\*

- Store access token in allowlist
  \*/
  async storeAccessToken(tokenId, userId, ttl = REDIS_TTL.ACCESS_TOKEN) {
  try {
  const key = REDIS_KEYS.ACCESS_TOKEN(tokenId);
  await redisClient.setex(key, ttl, userId);
  return true;
  } catch (error) {
  logger.error('Redis: Failed to store access token', { error, tokenId });
  return false;
  }
  }

/\*\*

- Verify access token exists in allowlist
  \*/
  async verifyAccessToken(tokenId) {
  try {
  const key = REDIS_KEYS.ACCESS_TOKEN(tokenId);
  const userId = await redisClient.get(key);
  return userId;
  } catch (error) {
  logger.error('Redis: Failed to verify access token', { error, tokenId });
  return null;
  }
  }

/\*\*

- Revoke access token
  \*/
  async revokeAccessToken(tokenId) {
  try {
  const key = REDIS_KEYS.ACCESS_TOKEN(tokenId);
  await redisClient.del(key);
  return true;
  } catch (error) {
  logger.error('Redis: Failed to revoke access token', { error, tokenId });
  return false;
  }
  }

/\*\*

- Rate limiting with sliding window
  \*/
  async checkRateLimit(key, maxAttempts, windowSeconds) {
  try {
  const current = await redisClient.incr(key);
      if (current === 1) {
        await redisClient.expire(key, windowSeconds);
      }

      return {
        allowed: current <= maxAttempts,
        remaining: Math.max(0, maxAttempts - current),
        resetAt: Date.now() + windowSeconds * 1000,
      };
  } catch (error) {
  logger.error('Redis: Rate limit check failed', { error, key });
  return { allowed: true, remaining: maxAttempts, resetAt: Date.now() };
  }
  }

/\*\*

- Track failed login attempts
  \*/
  async incrementFailedAttempts(email) {
  try {
  const key = REDIS_KEYS.FAILED_ATTEMPTS(email);
  const attempts = await redisClient.incr(key);
      if (attempts === 1) {
        await redisClient.expire(key, REDIS_TTL.FAILED_ATTEMPTS);
      }

      return attempts;
  } catch (error) {
  logger.error('Redis: Failed to increment login attempts', { error, email });
  return 0;
  }
  }

/\*\*

- Get failed login attempts count
  \*/
  async getFailedAttempts(email) {
  try {
  const key = REDIS_KEYS.FAILED_ATTEMPTS(email);
  const attempts = await redisClient.get(key);
  return parseInt(attempts) || 0;
  } catch (error) {
  logger.error('Redis: Failed to get login attempts', { error, email });
  return 0;
  }
  }

/\*\*

- Clear failed attempts on successful login
  \*/
  async clearFailedAttempts(email) {
  try {
  const key = REDIS_KEYS.FAILED_ATTEMPTS(email);
  await redisClient.del(key);
  return true;
  } catch (error) {
  logger.error('Redis: Failed to clear login attempts', { error, email });
  return false;
  }
  }

/\*\*

- Mark IP as suspicious
  \*/
  async markSuspiciousIP(ip, reason) {
  try {
  const key = REDIS_KEYS.SUSPICIOUS_IP(ip);
  await redisClient.setex(
  key,
  REDIS_TTL.SUSPICIOUS_IP,
  JSON.stringify({ reason, timestamp: Date.now() })
  );
  return true;
  } catch (error) {
  logger.error('Redis: Failed to mark suspicious IP', { error, ip });
  return false;
  }
  }

/\*\*

- Check if IP is suspicious
  \*/
  async isSuspiciousIP(ip) {
  try {
  const key = REDIS_KEYS.SUSPICIOUS_IP(ip);
  const data = await redisClient.get(key);
  return data ? JSON.parse(data) : null;
  } catch (error) {
  logger.error('Redis: Failed to check suspicious IP', { error, ip });
  return null;
  }
  }

/\*\*

- Track active sessions for a user
  \*/
  async addActiveSession(userId, sessionId, deviceInfo) {
  try {
  const key = REDIS_KEYS.ACTIVE_SESSIONS(userId);
  const sessionData = JSON.stringify({
  sessionId,
  deviceInfo,
  createdAt: Date.now(),
  });
      await redisClient.sadd(key, sessionData);
      return true;
  } catch (error) {
  logger.error('Redis: Failed to add active session', { error, userId });
  return false;
  }
  }

/\*\*

- Remove active session
  \*/
  async removeActiveSession(userId, sessionId) {
  try {
  const key = REDIS_KEYS.ACTIVE_SESSIONS(userId);
  const members = await redisClient.smembers(key);
      for (const member of members) {
        const data = JSON.parse(member);
        if (data.sessionId === sessionId) {
          await redisClient.srem(key, member);
          break;
        }
      }

      return true;
  } catch (error) {
  logger.error('Redis: Failed to remove active session', { error, userId });
  return false;
  }
  }

/\*\*

- Get all active sessions for a user
  \*/
  async getActiveSessions(userId) {
  try {
  const key = REDIS_KEYS.ACTIVE_SESSIONS(userId);
  const members = await redisClient.smembers(key);
  return members.map((m) => JSON.parse(m));
  } catch (error) {
  logger.error('Redis: Failed to get active sessions', { error, userId });
  return [];
  }
  }

/\*\*

- Revoke all user sessions
  \*/
  async revokeAllUserSessions(userId) {
  try {
  const key = REDIS_KEYS.ACTIVE_SESSIONS(userId);
  await redisClient.del(key);
  return true;
  } catch (error) {
  logger.error('Redis: Failed to revoke all sessions', { error, userId });
  return false;
  }
  }

/\*\*

- Cache user lockout status
  \*/
  async cacheUserLock(userId, lockUntil) {
  try {
  const key = REDIS_KEYS.USER_LOCKED(userId);
  const ttl = Math.ceil((lockUntil - Date.now()) / 1000);
      if (ttl > 0) {
        await redisClient.setex(key, ttl, lockUntil.toString());
        return true;
      }

      return false;
  } catch (error) {
  logger.error('Redis: Failed to cache user lock', { error, userId });
  return false;
  }
  }

/\*\*

- Check if user is locked (cached)
  \*/
  async isUserLocked(userId) {
  try {
  const key = REDIS_KEYS.USER_LOCKED(userId);
  const lockUntil = await redisClient.get(key);
        if (lockUntil) {
          return parseInt(lockUntil) > Date.now();
        }

        return false;
      } catch (error) {
        logger.error('Redis: Failed to check user lock', { error, userId });
        return false;
      }
  }
  }

export default new RedisAuthService();

```

---

## 📁 Feature-Based Folder Structure
```

backend/
├── config/
│ ├── database.js # MongoDB connection
│ ├── redis.js # Redis connection
│ ├── environment.js # Environment variables
│ └── security.js # Security configs (CORS, helmet, etc.)
│
├── features/
│ └── auth/
│ ├── models/
│ │ ├── user.model.js
│ │ └── refreshToken.model.js
│ │
│ ├── controllers/
│ │ ├── auth.controller.js # Login, logout, refresh
│ │ ├── register.controller.js # User registration
│ │ └── password.controller.js # Password reset
│ │
│ ├── services/
│ │ ├── auth.service.js # Core auth logic
│ │ ├── token.service.js # JWT generation/verification
│ │ ├── redis-auth.service.js # Redis operations
│ │ ├── device.service.js # Device fingerprinting
│ │ └── email.service.js # Email verification
│ │
│ ├── middleware/
│ │ ├── authenticate.js # Verify access token
│ │ ├── authorize.js # Check roles/permissions
│ │ ├── rate-limit.js # Rate limiting
│ │ └── validate.js # Request validation
│ │
│ ├── validators/
│ │ ├── auth.validator.js
│ │ └── user.validator.js
│ │
│ ├── routes/
│ │ └── auth.routes.js
│ │
│ ├── config/
│ │ └── redis-keys.js
│ │
│ ├── utils/
│ │ ├── crypto.utils.js
│ │ └── device-fingerprint.utils.js
│ │
│ └── tests/
│ ├── auth.test.js
│ ├── token.test.js
│ └── rate-limit.test.js
│
├── middleware/ # Global middleware
│ ├── error-handler.js
│ ├── request-logger.js
│ ├── security.js
│ └── not-found.js
│
├── utils/
│ ├── logger.js # Winston logger
│ ├── app-error.js # Custom error class
│ └── async-handler.js # Async wrapper
│
├── app.js # Express app setup
└── server.js # Entry point

🔑 Token Architecture
Token Service (JWT Generation & Verification)
javascript// backend/features/auth/services/token.service.js

import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import User from '../models/user.model.js';
import RefreshToken from '../models/refreshToken.model.js';
import redisAuthService from './redis-auth.service.js';
import deviceService from './device.service.js';
import logger from '../../../utils/logger.js';
import AppError from '../../../utils/app-error.js';

class TokenService {
/\*\*

- Generate access token (short-lived, stateless)
  \*/
  generateAccessToken(userId, roles, permissions) {
  const tokenId = uuidv4(); // For allowlist tracking


    const payload = {
      sub: userId,
      jti: tokenId, // JWT ID for revocation
      roles,
      permissions,
      type: 'access',
      iat: Math.floor(Date.now() / 1000),
    };

    const token = jwt.sign(payload, process.env.JWT_ACCESS_SECRET, {
      expiresIn: '15m', // Short-lived for security
      issuer: 'your-app-name',
      audience: 'your-app-users',
    });

    // Store in Redis allowlist (async, don't wait)
    redisAuthService.storeAccessToken(tokenId, userId).catch((err) => {
      logger.error('Failed to store access token in Redis', { err, tokenId });
    });

    return { token, tokenId, expiresIn: 15 * 60 };

}

/\*\*

- Generate refresh token (long-lived, stateful)
  \*/
  async generateRefreshToken(userId, deviceInfo, ipAddress) {
  try {
  // Create token family (for detecting token reuse)
  const family = uuidv4();
      // Generate cryptographically secure token
      const token = crypto.randomBytes(64).toString('base64url');

      // Create device fingerprint
      const fingerprint = deviceService.generateFingerprint(deviceInfo, ipAddress);

      // Store in database
      const refreshToken = await RefreshToken.create({
        userId,
        token,
        family,
        deviceFingerprint: {
          userAgent: deviceInfo.userAgent,
          ip: ipAddress,
          deviceId: deviceInfo.deviceId,
          hash: fingerprint,
        },
        expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000), // 90 days
        metadata: {
          createdIp: ipAddress,
          createdUserAgent: deviceInfo.userAgent,
        },
      });

      logger.info('Refresh token generated', {
        userId,
        family,
        ip: ipAddress,
      });

      return {
        token,
        family,
        expiresAt: refreshToken.expiresAt,
      };
  } catch (error) {
  logger.error('Failed to generate refresh token', { error, userId });
  throw new AppError('Failed to generate refresh token', 500);
  }
  }

/\*\*

- Verify access token
  \*/
  async verifyAccessToken(token) {
  try {
  // Decode and verify JWT
  const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET, {
  issuer: 'your-app-name',
  audience: 'your-app-users',
  });
        // Check if token exists in allowlist (prevents revoked tokens)
        const exists = await redisAuthService.verifyAccessToken(decoded.jti);

        if (!exists) {
          throw new AppError('Token has been revoked', 401);
        }

        // Check if user still exists and is active
        const user = await User.findById(decoded.sub).select('status security.passwordChangedAt');

        if (!user || user.status !== 'active') {
          throw new AppError('User no longer exists or is inactive', 401);
        }

        // Check if password was changed after token was issued
        if (user.chanContinuegedPasswordAfter(decoded.iat)) {
  throw new AppError('Password recently changed. Please login again.', 401);
  }
  return {
  userId: decoded.sub,
  roles: decoded.roles,
  permissions: decoded.permissions,
  tokenId: decoded.jti,
  };
  } catch (error) {
  if (error.name === 'TokenExpiredError') {
  throw new AppError('Access token expired', 401);
  }
  if (error.name === 'JsonWebTokenError') {
  throw new AppError('Invalid access token', 401);
  }
  throw error;
  }
  }
  /\*\*

Verify and rotate refresh token
\*/
async verifyAndRotateRefreshToken(token, deviceInfo, ipAddress) {
try {
// Find token in database
const refreshToken = await RefreshToken.findOne({
token,
revokedAt: null,
}).populate('userId', 'status roles permissions');
if (!refreshToken) {
// Token doesn't exist or was revoked
throw new AppError('Invalid or revoked refresh token', 401);
}
// Check if token expired
if (refreshToken.expiresAt < new Date()) {
await refreshToken.updateOne({ revokedAt: new Date() });
throw new AppError('Refresh token expired', 401);
}
// Check if token was already used (token reuse detection)
if (refreshToken.replacedBy) {
// SECURITY ALERT: Token reuse detected!
// Revoke entire token family (all tokens in the chain)
await RefreshToken.revokeFamily(refreshToken.family);
await redisAuthService.revokeAllUserSessions(refreshToken.userId.\_id);
logger.warn('Token reuse detected! Entire family revoked.', {
userId: refreshToken.userId.\_id,
family: refreshToken.family,
ip: ipAddress,
});
throw new AppError('Token reuse detected. All sessions revoked.', 401);
}
// Verify device fingerprint (detect session hijacking)
const currentFingerprint = deviceService.generateFingerprint(deviceInfo, ipAddress);
if (refreshToken.deviceFingerprint.hash !== currentFingerprint) {
logger.warn('Device fingerprint mismatch', {
userId: refreshToken.userId.\_id,
originalIp: refreshToken.deviceFingerprint.ip,
currentIp: ipAddress,
});
// Don't reject immediately, but flag as suspicious
await redisAuthService.markSuspiciousIP(ipAddress, 'Device fingerprint mismatch');
}
// Check user status
if (refreshToken.userId.status !== 'active') {
throw new AppError('User account is not active', 401);
}
// Generate new token pair (rotation)
const newAccessToken = this.generateAccessToken(
refreshToken.userId.\_id,
refreshToken.userId.roles,
refreshToken.userId.permissions
);
const newRefreshToken = await this.generateRefreshToken(
refreshToken.userId.\_id,
deviceInfo,
ipAddress
);
// Mark old refresh token as replaced (but don't revoke yet)
await refreshToken.updateOne({
replacedBy: newRefreshToken.token,
'metadata.lastUsedAt': new Date(),
'metadata.lastUsedIp': ipAddress,
});
// Update new token to same family (for chain tracking)
await RefreshToken.findOneAndUpdate(
{ token: newRefreshToken.token },
{ family: refreshToken.family }
);
logger.info('Refresh token rotated successfully', {
userId: refreshToken.userId.\_id,
family: refreshToken.family,
});
return {
accessToken: newAccessToken.token,
refreshToken: newRefreshToken.token,
user: {
id: refreshToken.userId.\_id,
roles: refreshToken.userId.roles,
permissions: refreshToken.userId.permissions,
},
};
} catch (error) {
if (error instanceof AppError) throw error;
logger.error('Refresh token verification failed', { error });
throw new AppError('Invalid refresh token', 401);
}
}

/\*\*

Revoke access token
\*/
async revokeAccessToken(tokenId) {
return await redisAuthService.revokeAccessToken(tokenId);
}

/\*\*

Revoke refresh token
\*/
async revokeRefreshToken(token) {
try {
await RefreshToken.updateOne(
{ token, revokedAt: null },
{ revokedAt: new Date() }
);
return true;
} catch (error) {
logger.error('Failed to revoke refresh token', { error });
return false;
}
}

/\*\*

Revoke all user tokens (logout from all devices)
\*/
async revokeAllUserTokens(userId) {
try {
// Revoke all refresh tokens
await RefreshToken.revokeAllUserTokens(userId);
// Clear Redis sessions
await redisAuthService.revokeAllUserSessions(userId);
logger.info('All user tokens revoked', { userId });
return true;
} catch (error) {
logger.error('Failed to revoke all user tokens', { error, userId });
return false;
}
}
}

export default new TokenService();

---

## 🛠️ Device Fingerprinting Service

```javascript
// backend/features/auth/services/device.service.js

import crypto from "crypto";
import UAParser from "ua-parser-js";

class DeviceService {
  /**
   * Generate device fingerprint hash
   */
  generateFingerprint(deviceInfo, ipAddress) {
    const components = [
      ipAddress,
      deviceInfo.userAgent || "",
      deviceInfo.deviceId || "", // Client-provided stable ID
      deviceInfo.acceptLanguage || "",
      deviceInfo.screenResolution || "",
      deviceInfo.timezone || "",
    ];

    const fingerprintString = components.join("|");

    return crypto.createHash("sha256").update(fingerprintString).digest("hex");
  }

  /**
   * Parse user agent
   */
  parseUserAgent(userAgentString) {
    const parser = new UAParser(userAgentString);
    const result = parser.getResult();

    return {
      browser: `${result.browser.name} ${result.browser.version}`,
      os: `${result.os.name} ${result.os.version}`,
      device: result.device.type || "desktop",
      deviceModel: result.device.model || "unknown",
    };
  }

  /**
   * Extract device info from request
   */
  extractDeviceInfo(req) {
    return {
      userAgent: req.headers["user-agent"],
      deviceId: req.headers["x-device-id"], // Client should send stable ID
      acceptLanguage: req.headers["accept-language"],
      screenResolution: req.headers["x-screen-resolution"],
      timezone: req.headers["x-timezone"],
    };
  }

  /**
   * Detect suspicious device changes
   */
  isDeviceSuspicious(storedFingerprint, currentFingerprint, threshold = 0.3) {
    // Simple Hamming distance check
    // In production, use more sophisticated anomaly detection

    let differences = 0;
    const maxLength = Math.max(
      storedFingerprint.length,
      currentFingerprint.length
    );

    for (let i = 0; i < maxLength; i++) {
      if (storedFingerprint[i] !== currentFingerprint[i]) {
        differences++;
      }
    }

    const similarity = 1 - differences / maxLength;
    return similarity < threshold;
  }
}

export default new DeviceService();
```
