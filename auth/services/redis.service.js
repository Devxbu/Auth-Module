const redisClient = require("../../config/redisClient");

class RedisService {
  constructor() {
    this.EXPIRE_ACCESS_TOKEN = 900; // 15 mins
    this.EXPIRE_REFRESH_BLACKLIST = 604800; // 7 days
    this.EXPIRE_ACCESS_BLACKLIST = 900; // 15 min
    this.EXPIRE_USER_CACHE = 300; // 5 mins
    this.EXPIRE_RATE_LIMIT = 900; // 15 mins
    this.EXPIRE_LOCK = 5; // 5 seconds
  }

  // ==========================================
  // 1. Access Token Storage (Stateful JWT)
  // ==========================================

  async checkSlidingWindowRateLimit(key, limit, windowSeconds) {
    const now = Date.now();
    const windowStart = now - windowSeconds * 1000;

    await redisClient.zremrangebyscore(key, 0, windowStart);

    const count = await redisClient.zcard(key);

    if (count < limit) {
      const member = `${now}:${Math.random().toString(36).substr(2, 9)}`;

      const pipeline = redisClient.pipeline();
      pipeline.zadd(key, now, member);
      pipeline.expire(key, windowSeconds);
      await pipeline.exec();
      return { allowed: true, count: count + 1 };
    }

    return { allowed: false, count: count };
  }

  async setAccessToken(tokenId, userData) {
    const key = `auth:access:${tokenId}`;
    const pipeline = redisClient.pipeline();

    pipeline.set(key, JSON.stringify(userData), "EX", this.EXPIRE_ACCESS_TOKEN);

    const userSessionsKey = `auth:user:sessions:${userData.userId}`;
    pipeline.sadd(userSessionsKey, tokenId);
    pipeline.expire(userSessionsKey, this.EXPIRE_ACCESS_TOKEN);

    await pipeline.exec();
  }

  async getAccessToken(tokenId) {
    const data = await redisClient.get(`auth:access:${tokenId}`);
    return data ? JSON.parse(data) : null;
  }

  async revokeAccessToken(tokenId) {
    const data = await this.getAccessToken(tokenId);
    if (!data) return;

    const pipeline = redisClient.pipeline();
    pipeline.del(`auth:access:${tokenId}`);
    if (data.userId) {
      pipeline.srem(`auth:user:sessions:${data.userId}`, tokenId);
    }
    await pipeline.exec();
  }

  async revokeAllUserSessions(userId) {
    const userSessionsKey = `auth:user:sessions:${userId}`;
    const tokens = await redisClient.smembers(userSessionsKey);

    if (tokens.length === 0) return;

    const pipeline = redisClient.pipeline();
    tokens.forEach((tokenId) => {
      pipeline.del(`auth:access:${tokenId}`);
    });
    pipeline.del(`auth:user:${userId}`);
    pipeline.del(userSessionsKey);

    await pipeline.exec();
  }

  // ==========================================
  // 2. Refresh Token Blacklist
  // ==========================================

  async blacklistAllRefreshTokens(tokenIds, userId) {
    const pipeline = redisClient.pipeline();
    for (const tokenId of tokenIds) {
      pipeline.set(
        `auth:blacklist:refresh:${tokenId}`,
        JSON.stringify({
          userId: userId,
          revokedAt: Date.now(),
          reason: "logout_all_devices",
        }),
        "EX",
        this.EXPIRE_REFRESH_BLACKLIST
      );
    }
    await pipeline.exec();
  }

  async blacklistRefreshToken(tokenId, meta) {
    // meta: { reason, familyId, userId? }
    const key = `auth:blacklist:refresh:${tokenId}`;
    await redisClient.set(
      key,
      JSON.stringify(meta),
      "EX",
      this.EXPIRE_REFRESH_BLACKLIST
    );
  }
  async blacklistAccessToken(familyId) {
    const key = `auth:blacklist:access:${familyId}`;
    await redisClient.set(key, "1", "EX", this.EXPIRE_ACCESS_BLACKLIST);
  }

  async isRefreshTokenBlacklisted(tokenId) {
    const exists = await redisClient.exists(
      `auth:blacklist:refresh:${tokenId}`
    );
    return exists === 1;
  }

  async getBlacklistData(tokenId) {
    const data = await redisClient.get(`auth:blacklist:refresh:${tokenId}`);
    if (!data) return null;
    return JSON.parse(data);
  }

  // ==========================================
  // 3. Rate Limiting (Token Bucket / Sliding Window)
  // ==========================================
  async checkTokenBucketRateLimit(
    key,
    capacity,
    refillRate,
    windowSeconds = 900
  ) {
    const script = `
      local key = KEYS[1]
      local capacity = tonumber(ARGV[1])
      local refillRate = tonumber(ARGV[2])
      local now = tonumber(ARGV[3])
      local window = tonumber(ARGV[4])

      local data = redis.call('HMGET', key, 'tokens', 'lastRefill')
      local tokens = tonumber(data[1])
      local lastRefill = tonumber(data[2])

      if not tokens then
        tokens = capacity
        lastRefill = now
      end

      -- Refill
      local elapsed = (now - lastRefill) / 1000
      local added = elapsed * refillRate
      tokens = math.min(capacity, tokens + added)
      lastRefill = now

      local allowed = 0
      if tokens >= 1 then
        allowed = 1
        tokens = tokens - 1
      end

      redis.call('HMSET', key, 'tokens', tokens, 'lastRefill', lastRefill)
      redis.call('EXPIRE', key, window)
      
      return { allowed, tokens }
    `;

    const now = Date.now();
    const result = await redisClient.eval(
      script,
      1,
      key,
      capacity,
      refillRate,
      now,
      windowSeconds
    );

    return {
      allowed: result[0] === 1,
      remaining: parseFloat(result[1]),
    };
  }

  async checkRateLimit(key, limit, windowSeconds = 60) {
    const current = await redisClient.incr(key);
    if (current === 1) {
      await redisClient.expire(key, windowSeconds);
    }
    return { allowed: current <= limit, count: current };
  }

  async incrementLoginFailures(email, windowSeconds = 900) {
    const key = `failures:login:${email}`;
    const current = await redisClient.incr(key);
    if (current === 1) {
      await redisClient.expire(key, windowSeconds);
    }
    return current;
  }

  async resetLoginFailures(email) {
    const key = `failures:login:${email}`;
    await redisClient.del(key);
  }

  async setAccountLocked(userId, durationSeconds) {
    const key = `auth:locked:${userId}`;
    await redisClient.set(key, "1", "EX", durationSeconds);
  }

  async checkAccountLock(userId) {
    const key = `auth:locked:${userId}`;
    const ttl = await redisClient.ttl(key);
    return ttl > 0 ? ttl : null;
  }

  async checkResendLimit(userId, windowSeconds = 300) {
    const key = `ratelimit:resend:${userId}`;
    const result = await redisClient.set(key, "1", "NX", "EX", windowSeconds);
    return result === "OK";
  }

  // ==========================================
  // 4. Session State Cache (User Object)
  // ==========================================

  async cacheUser(userId, userData) {
    const key = `auth:user:${userId}`;
    await redisClient.set(
      key,
      JSON.stringify(userData),
      "EX",
      this.EXPIRE_USER_CACHE
    );
  }

  async getCachedUser(userId) {
    const data = await redisClient.get(`auth:user:${userId}`);
    return data ? JSON.parse(data) : null;
  }

  async invalidateUserCache(userId) {
    await redisClient.del(`auth:user:${userId}`);
  }

  // ==========================================
  // 5. Distributed Locks
  // ==========================================

  async acquireLock(lockKey, lockId, ttl = this.EXPIRE_LOCK) {
    const result = await redisClient.set(lockKey, lockId, "NX", "EX", ttl);
    return result === "OK";
  }

  async releaseLock(lockKey, lockId) {
    const script = `
      if redis.call("get", KEYS[1]) == ARGV[1] then
        return redis.call("del", KEYS[1])
      else
        return 0
      end
    `;
    await redisClient.eval(script, 1, lockKey, lockId);
  }
}

module.exports = new RedisService();
