const mongoose = require("mongoose");

const loginAttemptSchema = new mongoose.Schema({
  identifier: {
    type: String, // email or IP or both
    required: true,
    index: true,
  },
  identifierType: {
    type: String,
    enum: ["email", "ip", "email_ip"],
    required: true,
  },
  ipAddress: {
    type: String,
    required: true,
    index: true,
  },
  successful: {
    type: Boolean,
    required: true,
    index: true,
  },
  attemptedAt: {
    type: Date,
    default: Date.now,
  },
  userAgent: {
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
});

loginAttemptSchema.index({ identifier: 1, attemptedAt: -1 });
loginAttemptSchema.index({ ipAddress: 1, attemptedAt: -1 });
loginAttemptSchema.index({ attemptedAt: 1 }, { expireAfterSeconds: 3600 });
loginAttemptSchema.index({ successful: 1, attemptedAt: -1 });

const LoginAttempt = mongoose.model("LoginAttempt", loginAttemptSchema);

module.exports = LoginAttempt;
