const User = require("../models/user.model");

class AuthRepository {
  async createUser(data) {
    return await User.create(data);
  }

  async findByEmail(email) {
    return await User.findOne({ email, deletedAt: null });
  }

  async logLoginAttempt(data) {
    const LoginAttempt = require("../models/loginAttempt.model");
    return await LoginAttempt.create(data);
  }

  async hardDeleteUser(userId) {
    return await User.findOneAndDelete({ userId });
  }

  async lockAccount(userId, lockUntil) {
    return await User.updateOne(
      { userId },
      {
        $set: {
          lockUntil,
          // failedLoginAttempts: 0 // User requested NOT to reset here for progressive logic
        },
      }
    );
  }

  async incrementFailedLoginAttempts(userId) {
    const updated = await User.findOneAndUpdate(
      { userId },
      {
        $inc: { failedLoginAttempts: 1 },
        $set: { lastFailedLoginAt: new Date() },
      },
      { new: true }
    );
    return updated.failedLoginAttempts;
  }

  async resetFailedLoginAttempts(userId) {
    return await User.updateOne(
      { userId },
      {
        $set: {
          failedLoginAttempts: 0,
          lockUntil: null,
        },
      }
    );
  }

  async findById(id) {
    return await User.findOne({ userId: id });
  }

  async updateOne(userId, data) {
    return await User.updateOne({ userId }, data);
  }

  async updateEmailVerification(userId) {
    return await User.updateOne(
      { userId },
      { $set: { isEmailVerified: true } }
    );
  }

  async updatePassword(userId, hash) {
    return await User.findOneAndUpdate(
      { userId },
      {
        $set: {
          passwordHash: hash,
          passwordChangedAt: new Date(),
          failedLoginAttempts: 0,
          lockUntil: null,
        },
      }
    );
  }
}

module.exports = new AuthRepository();
