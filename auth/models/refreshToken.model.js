const mongoose = require("mongoose");
const { v4: uuidv4 } = require("uuid");

const refreshTokenSchema = new mongoose.Schema(
  {
    tokenId: {
      type: String,
      default: uuidv4,
      unique: true,
      index: true,
    },
    userId: {
      type: String,
      required: true,
      index: true,
    },
    tokenHash: {
      type: String,
      required: true,
    },
    familyId: {
      type: String,
      required: true,
      index: true,
    },
    previousTokenId: {
      type: String,
      default: null,
    },
    isRevoked: {
      type: Boolean,
      default: false,
      index: true,
    },
    revokedAt: {
      type: Date,
      default: null,
    },
    revokeReason: {
      type: String,
      default: null,
    },
    deviceInfo: {
      userAgent: String,
      deviceType: {
        type: String,
        enum: ["mobile", "desktop", "tablet", "unknown"],
        default: "unknown",
      },
      os: String,
      browser: String,
    },
    ipAddress: {
      type: String,
    },
    geolocation: {
      country: String,
      city: String,
      coordinates: {
        type: { type: String, enum: ["Point"], default: "Point" },
        coordinates: { type: [Number], default: [0, 0] },
      },
    },
    expiresAt: {
      type: Date,
      required: true,
    },
    lastUsedAt: {
      type: Date,
      default: Date.now,
    },
  },
  {
    timestamps: true,
  }
);

refreshTokenSchema.index({ tokenId: 1, isRevoked: 1 });
refreshTokenSchema.index({ userId: 1, isRevoked: 1, expiresAt: 1 });
refreshTokenSchema.index({ familyId: 1, createdAt: 1 });
refreshTokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
refreshTokenSchema.index({ revokedAt: 1, revokeReason: 1 });
refreshTokenSchema.index({ tokenHash: 1, userId: 1 });

const RefreshToken = mongoose.model("RefreshToken", refreshTokenSchema);

module.exports = RefreshToken;
