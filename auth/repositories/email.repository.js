const Email = require("../models/emailVerificationToken.model");

class EmailRepository {
  async create(data) {
    return await Email.create(data);
  }

  async invalidateUserTokens(userId) {
    return await Email.updateMany(
      { userId, tokenType: "email_verification", isUsed: false },
      { $set: { isUsed: true, usedAt: new Date() } }
    );
  }

  async findUserWithEmailVerificationToken(token) {
    return await Email.findOne({
      tokenHash: token,
      tokenType: "email_verification",
      isUsed: false,
      expiresAt: { $gt: new Date() },
    });
  }
  async findUserWithPasswordResetToken(token) {
    return await Email.findOne({
      tokenHash: token,
      tokenType: "password_reset",
      isUsed: false,
      expiresAt: { $gt: new Date() },
    });
  }

  async makeTokenUsed(tokenId) {
    return await Email.updateOne(
      { tokenId: tokenId },
      { $set: { isUsed: true, usedAt: new Date() } }
    );
  }

  async invalidateUserPasswordTokens(userId) {
    return await Email.updateMany(
      { userId, tokenType: "password_reset", isUsed: false },
      { $set: { isUsed: true, usedAt: new Date() } }
    );
  }
}

module.exports = new EmailRepository();
