const dotenv = require("dotenv");
dotenv.config();

const env = {
  port: process.env.PORT,
  mongoUri: process.env.MONGODB_URI,
  redisUrl: process.env.REDIS_URL,
  redisHost: process.env.REDIS_HOST || "localhost",
  redisPort: process.env.REDIS_PORT || 6379,
  redisPassword: process.env.REDIS_PASSWORD,
  emailUser: process.env.EMAIL_USER,
  emailPass: process.env.EMAIL_PASS,
  frontendUrl: process.env.FRONTEND_URL,
  frontendVerifyEmailUrl: process.env.FRONTEND_VERIFY_EMAIL_URL,
  frontendForgotPassUrl: process.env.FRONTEND_FORGOT_PASS_URL,
  jwtSecret: process.env.JWT_SECRET,
};

module.exports = env;
