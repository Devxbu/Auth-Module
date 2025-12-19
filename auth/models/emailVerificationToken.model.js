const mongoose = require("mongoose");
const { v4: uuidv4 } = require("uuid");

const emailVerificationTokenSchema = new mongoose.Schema(
  {
    tokenId: {
      type: String,
      default: uuidv4,
      unique: true,
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
    tokenType: {
      type: String,
      enum: ["email_verification", "password_reset"],
      required: true,
    },
    email: {
      type: String,
      required: true,
    },
    isUsed: {
      type: Boolean,
      default: false,
    },
    usedAt: {
      type: Date,
      default: null,
    },
    expiresAt: {
      type: Date,
      required: true,
    },
  },
  {
    timestamps: true,
  }
);

emailVerificationTokenSchema.index({ tokenId: 1, isUsed: 1, expiresAt: 1 });
emailVerificationTokenSchema.index({ userId: 1, tokenType: 1, isUsed: 1 });
emailVerificationTokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const EmailVerificationToken = mongoose.model(
  "EmailVerificationToken",
  emailVerificationTokenSchema
);

module.exports = EmailVerificationToken;
