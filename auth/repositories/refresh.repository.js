const RefreshToken = require("../models/refreshToken.model");

class RefreshRepository {
  async create(data) {
    return await RefreshToken.create(data);
  }
  async findToken(tokenHash, tokenId) {
    return await RefreshToken.findOne({
      tokenHash,
      tokenId,
      isRevoked: false,
      expiresAt: { $gt: new Date() },
    });
  }
  async wasTokenUsed(tokenId) {
    return await RefreshToken.findOne({
      tokenId,
      isRevoked: true,
      revokedReason: "rotation",
    });
  }
  async findTokensByFamilyId(familyId) {
    return await RefreshToken.find({ familyId });
  }
  async revokeAllFamily(familyId) {
    return await RefreshToken.updateMany(
      { familyId },
      {
        $set: {
          isRevoked: true,
          revokedReason: "rotation_attack",
          revokedAt: new Date(),
        },
      }
    );
  }
  async revokeToken(tokenId, reason) {
    return await RefreshToken.updateOne(
      { tokenId },
      {
        $set: {
          isRevoked: true,
          revokedReason: reason,
          revokedAt: new Date(),
        },
      }
    );
  }
  async revokeAllTokens(userId) {
    return await RefreshToken.updateMany(
      { userId, isRevoked: false, expiresAt: { $gt: new Date() } },
      {
        $set: {
          isRevoked: true,
          revokedReason: "logout_all_devices",
          revokedAt: new Date(),
        },
      }
    );
  }
  async getRefreshTokensByUserId(userId) {
    const refreshTokens = await RefreshToken.find({
      userId,
      isRevoked: false,
      expiresAt: { $gt: new Date() },
    });
    const tokenIds = refreshTokens.map((t) => t.tokenId);
    return tokenIds;
  }
}

module.exports = new RefreshRepository();
