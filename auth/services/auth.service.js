const bcrypt = require("bcrypt");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const redisService = require("./redis.service");
const emailService = require("./email.service");
const authRepository = require("../repositories/auth.repository");
const emailRepository = require("../repositories/email.repository");
const refreshRepository = require("../repositories/refresh.repository");
const RefreshToken = require("../models/refreshToken.model");
const parseDeviceType = require("../../utils/parseDeviceType");
const parseOS = require("../../utils/parseOS");
const parseBrowser = require("../../utils/parseBrowser");
const { v4: uuidv4 } = require("uuid");

class AuthService {
  async register({ email, password, ipAddress }) {
    try {
      // Check ip and email limits
      const ipLimit = await redisService.checkSlidingWindowRateLimit(
        `ratelimit:register:ip:${ipAddress}`,
        3,
        3600 // 1 hour
      );
      if (!ipLimit.allowed)
        throw new Error(
          "Too many registration attempts from this IP. Please try again later."
        );

      const emailLimit = await redisService.checkRateLimit(
        `ratelimit:register:email:${email}`,
        1,
        86400 // 24 hours
      );
      if (!emailLimit.allowed)
        throw new Error(
          "Registration limit exceeded for this email. Please try again tomorrow."
        );

      // Check if user exists and is verified
      const existingUser = await authRepository.findByEmail(email);

      if (existingUser && existingUser.isEmailVerified)
        throw new Error("User already exists");

      if (existingUser && !existingUser.isEmailVerified) {
        const ageMs = Date.now() - existingUser.createdAt.getTime();

        if (ageMs < 24 * 60 * 60 * 1000) {
          throw new Error("Verification pending");
        }

        await authRepository.hardDeleteUser(existingUser.userId);
      }

      // Hash password
      const hashedPassword = await bcrypt.hash(password, 12);
      password = null;

      // Create user
      const user = await authRepository.createUser({
        email: email.toLowerCase(),
        passwordHash: hashedPassword,
      });

      // Create email verification token
      const emailToken = crypto.randomBytes(32).toString("hex");

      // Create email verification record
      await emailRepository.create({
        userId: user.userId,
        tokenType: "email_verification",
        tokenHash: crypto.createHash("sha256").update(emailToken).digest("hex"),
        email: user.email,
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
      });

      // Send verification email
      await emailService.sendVerificationEmail(user.email, emailToken);

      return {
        success: true,
        message:
          "Registration successful. Please check your email to verify your account.",
        data: {
          userId: user.userId,
          email: user.email,
          emailVerificationRequired: true,
        },
      };
    } catch (error) {
      throw error;
    }
  }

  async login({ email, password, ipAddress, userAgent }) {
    try {
      // Check ip, email and global limits
      const ipLimit = await redisService.checkSlidingWindowRateLimit(
        `ratelimit:login:ip:${ipAddress}`,
        10,
        900
      );

      const emailLimit = await redisService.checkTokenBucketRateLimit(
        `ratelimit:login:email:${email}`,
        5,
        0.0055,
        900
      );

      const globalLimit = await redisService.checkRateLimit(
        `ratelimit:login:global`,
        10000,
        60
      );

      if (ipLimit.count > 5 || !ipLimit.allowed) {
        throw new Error("Invalid credentials or too many attempts.");
      }

      if (ipLimit.count > 3) {
        await new Promise((resolve) => setTimeout(resolve, 1000));
      }

      if (!emailLimit.allowed) {
        throw new Error("Invalid credentials or too many attempts.");
      }

      if (!globalLimit.allowed) {
        throw new Error("Invalid credentials or too many attempts.");
      }

      // Check if user exists
      const user = await authRepository.findByEmail(email);

      if (user) {
        // Check if account is locked
        const lockedTtl = await redisService.checkAccountLock(user.userId);
        if (lockedTtl) {
          const error = new Error(
            "Account is temporarily locked due to multiple failed login attempts."
          );
          error.code = "ACCOUNT_LOCKED";
          error.data = { retryAfter: lockedTtl };
          throw error;
        }

        if (user.lockUntil && user.lockUntil > Date.now()) {
          const remainingTime = Math.ceil((user.lockUntil - Date.now()) / 1000);

          await redisService.setAccountLocked(user.userId, remainingTime);

          const error = new Error(
            "Account is temporarily locked due to multiple failed login attempts."
          );
          error.code = "ACCOUNT_LOCKED";
          error.data = { retryAfter: remainingTime };
          throw error;
        }
      }

      const fakeHash =
        "$2b$12$C6UzMDM.H6dfI/f/IKcEeO6A6hZ6p9N1H8aCkT3P1l7KZ4p5J6N1K";

      // If user exist hash password if isn't hash fake string
      const passwordHash = user ? user.passwordHash : fakeHash;
      const isMatch = await bcrypt.compare(password, passwordHash);

      // If password didn't match set attempt limitter
      if (!isMatch) {
        if (user) {
          const attempts = await authRepository.incrementFailedLoginAttempts(
            user.userId
          );
          await authRepository.logLoginAttempt({
            identifier: email,
            identifierType: "email",
            ipAddress,
            userAgent,
            successful: false,
            geolocation: null,
          });

          if (attempts >= 5) {
            let lockDuration = 0;

            if (attempts === 5) lockDuration = 15 * 60 * 1000; // 15 mins
            else if (attempts === 6) lockDuration = 30 * 60 * 1000; // 30 mins
            else if (attempts === 7) lockDuration = 60 * 60 * 1000; // 1 hr
            else if (attempts === 8) lockDuration = 6 * 60 * 60 * 1000; // 6 hrs
            else lockDuration = 24 * 60 * 60 * 1000; // 24 hrs (9+)

            const lockUntil = new Date(Date.now() + lockDuration);
            await authRepository.lockAccount(user.userId, lockUntil);
            await redisService.setAccountLocked(
              user.userId,
              lockDuration / 1000
            );

            const error = new Error(
              "Account is temporarily locked due to multiple failed login attempts."
            );
            error.code = "ACCOUNT_LOCKED";
            error.data = { retryAfter: lockDuration / 1000 };
            throw error;
          }
        }

        throw new Error("Invalid credentials or too many attempts.");
      }

      // Reset login attemts when user login successfully
      if (user) {
        await authRepository.resetFailedLoginAttempts(user.userId);

        await authRepository.logLoginAttempt({
          identifier: email,
          identifierType: "email",
          ipAddress,
          userAgent,
          successful: true,
        });
      }

      // Check is user deleted
      if (user.accountStatus === "deleted") {
        throw new Error("Invalid credentials or too many attempts.");
      }

      // Check is user email verified if isn't send verification email
      if (!user.isEmailVerified) {
        const canResend = await redisService.checkResendLimit(user.userId, 300); // 5 mins

        let message = "Please verify your email address before logging in.";

        if (canResend) {
          await emailRepository.invalidateUserTokens(user.userId);

          const emailToken = crypto.randomBytes(32).toString("hex");
          await emailRepository.create({
            userId: user.userId,
            tokenType: "email_verification",
            tokenHash: crypto
              .createHash("sha256")
              .update(emailToken)
              .digest("hex"),
            email: user.email,
            expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
          });

          await emailService.sendVerificationEmail(user.email, emailToken);

          message =
            "Email not verified. A new verification email has been sent. Please check your inbox.";
        } else {
          message =
            "Email not verified. We recently sent you a verification email. Please check your inbox (including spam).";
        }

        return {
          error: "EMAIL_NOT_VERIFIED",
          message: message,
        };
      }

      // Generate access token and refresh token
      const accessTokenId = uuidv4();
      const familyId = uuidv4();
      const refreshTokenId = uuidv4();

      const accessToken = jwt.sign(
        {
          tokenId: accessTokenId,
          userId: user.userId,
          email: user.email,
          roles: user.roles,
          permissions: user.permissions,
          familyId,
        },
        process.env.JWT_SECRET,
        {
          expiresIn: "15m",
          issuer: "auth",
          audience: "users",
        }
      );

      const refreshTokenSecret = crypto.randomBytes(32).toString("hex");
      const refreshToken = `${refreshTokenId}.${refreshTokenSecret}`;
      const refreshTokenHash = crypto
        .createHash("sha256")
        .update(refreshTokenSecret)
        .digest("hex");

      await refreshRepository.create({
        tokenId: refreshTokenId,
        userId: user.userId,
        tokenHash: refreshTokenHash,
        familyId,
        deviceInfo: {
          userAgent,
          deviceType: parseDeviceType(userAgent),
          os: parseOS(userAgent),
          browser: parseBrowser(userAgent),
        },
        ipAddress,
        geolocation: null,
        expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
      });

      const issuedAt = Math.floor(Date.now() / 1000);
      const expiresAt = issuedAt + 900; // 15 mins

      const sessionData = {
        userId: user.userId,
        email: user.email,
        roles: user.roles,
        permissions: user.permissions,
        familyId: familyId,
        deviceInfo: {
          userAgent,
          deviceType: parseDeviceType(userAgent),
          os: parseOS(userAgent),
          browser: parseBrowser(userAgent),
        },
        ipAddress,
        issuedAt,
        expiresAt,
      };

      await redisService.setAccessToken(accessTokenId, sessionData);

      await authRepository.updateOne(user.userId, {
        lastLoginAt: new Date(),
        lastLoginIp: ipAddress,
        lastLoginDevice: parseDeviceType(userAgent),
        failedLoginAttempts: 0,
        lockUntil: null,
      });

      return {
        message: "Login successful",
        accessToken,
        refreshToken,
        tokenType: "Bearer",
        expiresAt,
        user: {
          userId: user.userId,
          email: user.email,
          roles: user.roles,
          permissions: user.permissions,
        },
      };
    } catch (error) {
      console.error(error);
      throw error;
    }
  }

  async refreshToken({ cmRefreshToken, ipAddress }) {
    try {
      // Split refresh token
      const [tokenId, tokenSecret] = cmRefreshToken.split(".");
      if (!tokenId || !tokenSecret) throw new Error("Invalid refresh token");

      // Check refresh token limit
      const refreshTokenLimit = await redisService.checkTokenBucketRateLimit(
        `ratelimit:refresh:${tokenId}`,
        10,
        0.1667,
        60
      );

      if (!refreshTokenLimit.allowed) throw new Error("Too many requests");

      // Make refresh token lock
      const lockId = uuidv4();
      const lockKey = `lock:refresh:${tokenId}`;
      const hasLock = await redisService.acquireLock(lockKey, lockId, 5);

      if (!hasLock) {
        const error = new Error("Too many requests");
        error.status = 429;
        throw error;
      }

      // Check if token is blacklisted
      const isBlacklisted = await redisService.getBlacklistData(tokenId);
      if (isBlacklisted) {
        if (blacklistData.reason === "rotation_attack") {
          await emailService.sendSecurityAlert(
            blacklistData.userId,
            "Rotation attack detected"
          );
        }
        await redisService.releaseLock(lockKey, lockId);
        const error = new Error("Token has been revoked");
        error.status = 401;
        throw error;
      }

      // Hash refresh token
      const tokenHash = crypto
        .createHash("sha256")
        .update(cmRefreshToken)
        .digest("hex");

      // Find refresh token
      const refreshTokenDoc = await refreshRepository.findToken(
        tokenHash,
        tokenId
      );

      if (!refreshTokenDoc) {
        await redisService.releaseLock(lockKey, lockId);
        const error = new Error("Invalid refresh token");
        error.status = 401;
        throw error;
      }

      // Check if token was used
      const wasTokenUsed = await refreshRepository.wasTokenUsed(tokenId);
      if (wasTokenUsed && Date.now() - wasTokenUsed.revokedAt < 60000) {
        const familyTokens = await refreshRepository.findTokensByFamilyId(
          refreshTokenDoc.familyId
        );
        await redisService.revokeAllFamily(refreshTokenDoc.familyId);
        for (const token of familyTokens) {
          await redisService.blacklistRefreshToken(token.tokenId, {
            reason: "rotation_attack",
            userId: token.userId,
            familyId: token.familyId,
          });
        }
        await redisService.blacklistAccessToken(refreshTokenDoc.familyId);
        await emailService.sendSecurityAlert(
          refreshTokenDoc.userId,
          "Suspicious activity detected. All sessions have been terminated"
        );
        await redisService.releaseLock(lockKey, lockId);
        const error = new Error(
          "Security violation detected. All sessions terminated"
        );
        error.status = 401;
        throw error;
      }

      // Generate access token and refresh token
      const accessTokenId = uuidv4();
      const familyId = refreshTokenDoc.familyId;
      const refreshTokenId = uuidv4();

      const accessToken = jwt.sign(
        {
          tokenId: accessTokenId,
          userId: refreshTokenDoc.userId,
          email: refreshTokenDoc.email,
          roles: refreshTokenDoc.roles,
          permissions: refreshTokenDoc.permissions,
          familyId,
        },
        process.env.JWT_SECRET,
        {
          expiresIn: "15m",
          issuer: "auth",
          audience: "users",
        }
      );

      const refreshTokenSecret = crypto.randomBytes(32).toString("hex");
      const newRefreshToken = `${refreshTokenId}.${refreshTokenSecret}`;
      const refreshTokenHash = crypto
        .createHash("sha256")
        .update(refreshTokenSecret)
        .digest("hex");

      await refreshRepository.revokeToken(tokenId, "rotation");
      await redisService.blacklistRefreshToken(tokenId, {
        reason: "rotation",
        userId: refreshTokenDoc.userId,
        familyId: refreshTokenDoc.familyId,
      });

      await refreshRepository.create({
        tokenId: refreshTokenId,
        userId: refreshTokenDoc.userId,
        tokenHash: refreshTokenHash,
        familyId: refreshTokenDoc.familyId,
        deviceInfo: refreshTokenDoc.deviceInfo,
        ipAddress,
        geolocation: null,
        lastUsedAt: new Date(),
        expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
      });

      const sessionData = {
        userId: refreshTokenDoc.userId,
        email: refreshTokenDoc.email,
        roles: refreshTokenDoc.roles,
        permissions: refreshTokenDoc.permissions,
        familyId: refreshTokenDoc.familyId,
        deviceInfo: refreshTokenDoc.deviceInfo,
        ipAddress,
        issuedAt,
        expiresAt,
      };

      await redisService.setAccessToken(accessTokenId, sessionData);
      await redisService.releaseLock(lockKey, lockId);
      return {
        message: "Refresh token successful",
        accessToken,
        refreshToken: newRefreshToken,
        tokenType: "Bearer",
        expiresAt,
        user: {
          userId: refreshTokenDoc.userId,
          email: refreshTokenDoc.email,
          roles: refreshTokenDoc.roles,
          permissions: refreshTokenDoc.permissions,
        },
      };
    } catch (error) {
      console.error(error);
      throw error;
    }
  }

  async logout({ accessTokenId, refreshTokenId }) {
    try {
      // Check access token
      const sessionData = await redisService.getAccessToken(accessTokenId);

      if (!sessionData) {
        throw new Error("Invalid access token");
      }

      // Revoke refresh token
      await refreshRepository.revokeToken(refreshTokenId, "user_logout");
      await redisService.blacklistRefreshToken(refreshTokenId, {
        reason: "user_logout",
        userId: sessionData.userId,
        familyId: sessionData.familyId,
      });

      // Revoke access token
      await redisService.revokeAccessToken(accessTokenId);
      return {
        message: "Logged out successfully",
      };
    } catch (error) {
      console.error(error);
      throw error;
    }
  }

  async logoutAll(userId) {
    try {
      // Revoke all refresh tokens
      const tokenIds = await refreshRepository.getRefreshTokensByUserId(userId);
      await refreshRepository.revokeAllTokens(userId);

      // Revoke all access tokens and blacklist refresh tokens
      await redisService.blacklistAllRefreshTokens(tokenIds, userId);
      await redisService.revokeAllUserSessions(userId);
      return {
        message: "Logged out successfully",
      };
    } catch (error) {
      console.error(error);
      throw error;
    }
  }

  async forgotPassword({ email, ipAddress }) {
    try {
      // Check ip and email limits
      const ipLimit = await redisService.checkSlidingWindowRateLimit(
        `ratelimit:forgotPass:ip:${ipAddress}`,
        10,
        3600 // 1 hour
      );
      if (!ipLimit.allowed)
        throw new Error(
          "Too many forgot password attempts from this IP. Please try again later."
        );

      const emailLimit = await redisService.checkRateLimit(
        `ratelimit:forgotPass:email:${email}`,
        3,
        3600 // 1 hour
      );
      if (!emailLimit.allowed)
        throw new Error(
          "Too many forgot password attempts for this email. Please try again tomorrow."
        );

      // Find user by email
      const user = await authRepository.findByEmail(email.toLowerCase());
      if (!user) throw new Error("User not found");

      // Invalidate all user password tokens
      await emailRepository.invalidateUserPasswordTokens(user.userId);

      // Generate token
      const tokenSecret = crypto.randomBytes(32).toString("hex");
      const tokenId = uuidv4();
      const tokenHash = crypto
        .createHash("sha256")
        .update(tokenSecret)
        .digest("hex");

      await emailRepository.create({
        userId: user.userId,
        tokenType: "password_reset",
        tokenHash: crypto
          .createHash("sha256")
          .update(tokenSecret)
          .digest("hex"),
        email: user.email,
        expiresAt: new Date(Date.now() + 60 * 60 * 1000), // 1 hour
      });
      await emailService.sendForgotPasswordEmail(user.email, tokenSecret);
      return {
        message: "Password reset email sent successfully",
      };
    } catch (error) {
      console.error(error);
      throw error;
    }
  }

  async resetPassword({ token, password, ipAddress }) {
    try {
      // Check ip limits
      const ipLimit = await redisService.checkSlidingWindowRateLimit(
        `ratelimit:resetPass:ip:${ipAddress}`,
        10,
        3600 // 1 hour
      );

      if (!ipLimit.allowed)
        throw new Error(
          "Too many reset password attempts from this IP. Please try again later."
        );

      // Compare token
      const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
      const tokensUser = await emailRepository.findUserWithPasswordResetToken(
        tokenHash
      );
      if (!tokensUser) throw new Error("Invalid token");

      // Check token expiration
      if (tokensUser.expiresAt < new Date()) throw new Error("Token expired");

      // Check user
      const user = await authRepository.findById(tokensUser.userId);
      if (!user || user.deletedAt !== null || user.accountStatus !== "active")
        throw new Error("User not found");

      // Update password
      const newPasswordHash = await bcrypt.hash(password, 12);
      await authRepository.updatePassword(user.userId, newPasswordHash);

      // Make token used
      await emailRepository.makeTokenUsed(tokensUser.tokenId);

      // Logout all sessions
      await this.logoutAll(user.userId);

      return {
        message: "Password reset successfully",
      };
    } catch (error) {
      console.error(error);
      throw error;
    }
  }

  async verifyEmail({ token }) {
    try {
      // Hash Token
      const tokenHash = crypto.createHash("sha256").update(token).digest("hex");

      // Find User
      const verificationToken =
        await emailRepository.findUserWithEmailVerificationToken(tokenHash);
      if (!verificationToken) throw new Error("Invalid token");

      // Check token expiration
      if (verificationToken.expiresAt < new Date())
        throw new Error("Token expired");

      // Check user
      const user = await authRepository.findById(verificationToken.userId);
      if (!user || user.deletedAt !== null) throw new Error("User not found");
      if (user.isEmailVerified) throw new Error("Email already verified");

      // Update email verification
      await authRepository.updateEmailVerification(user.userId);
      await emailRepository.makeTokenUsed(verificationToken.tokenId);

      // Invalidate user cache
      await redisService.invalidateUserCache(user.userId);
      return {
        message: "Email verified successfully",
      };
    } catch (error) {
      console.error(error);
      throw error;
    }
  }
}

module.exports = new AuthService();
