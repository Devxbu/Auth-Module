const authService = require("./services/auth.service");

module.exports.register = async (req, res) => {
  try {
    const { email, password } = req.body;
    const ipAddress =
      req.ip || req.headers["x-forwarded-for"] || req.connection.remoteAddress;

    const result = await authService.register({ email, password, ipAddress });
    return res.status(201).json(result);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: error.message });
  }
};

module.exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const ipAddress =
      req.ip || req.headers["x-forwarded-for"] || req.connection.remoteAddress;
    const userAgent = req.headers["user-agent"];
    const result = await authService.login({
      email,
      password,
      ipAddress,
      userAgent,
    });

    if (result.refreshToken) {
      res.cookie("refreshToken", result.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
      });
      delete result.refreshToken;
    }

    if (result && result.error === "EMAIL_NOT_VERIFIED") {
      return res.status(403).json({
        error: "EMAIL_NOT_VERIFIED",
        message: result.message,
      });
    }

    return res.status(200).json(result);
  } catch (error) {
    console.error(error);
    if (error.code === "ACCOUNT_LOCKED") {
      return res.status(423).json({
        error: "ACCOUNT_LOCKED",
        message: error.message,
        retryAfter: error.data.retryAfter,
      });
    }
    return res.status(500).json({ message: error.message });
  }
};

module.exports.logout = async (req, res) => {
  try {
    const accessTokenId = req.user.tokenId;
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) {
      return res.status(401).json({ message: "Missing refresh token" });
    }
    const [refreshTokenId] = refreshToken.split(".") || [];
    const result = await authService.logout({ accessTokenId, refreshTokenId });
    return res.status(200).json({ message: "Logged out successfully" });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: error.message });
  }
};

module.exports.logoutAll = async (req, res) => {
  try {
    const { userId } = req.user;
    await authService.logoutAll({ userId });
    return res.status(200).json({ message: "Logged out from all devices" });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: error.message });
  }
};

module.exports.refreshToken = async (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken;
    const ipAddress =
      req.ip || req.headers["x-forwarded-for"] || req.connection.remoteAddress;

    const result = await authService.refreshToken({
      cmRefreshToken: refreshToken,
      ipAddress,
    });

    if (result.refreshToken) {
      res.cookie("refreshToken", result.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
      });
      delete result.refreshToken;
    }
    return res.status(200).json(result);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: error.message });
  }
};

module.exports.verifyEmail = async (req, res) => {
  try {
    const { token } = req.query;

    if (!token)
      return res.status(400).json({ message: "Missing verification token" });

    if (!/^[a-f0-9]{64}$/i.test(token))
      return res.status(400).json({ message: "Invalid token format" });

    const result = await authService.verifyEmail({ token });
    return res.status(200).json(result);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: error.message });
  }
};

module.exports.forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;
    const ipAddress =
      req.ip || req.headers["x-forwarded-for"] || req.connection.remoteAddress;

    const result = await authService.forgotPassword({ email, ipAddress });
    return res.status(200).json(result);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: error.message });
  }
};

module.exports.resetPassword = async (req, res) => {
  try {
    const { token, password } = req.body;
    const ipAddress =
      req.ip || req.headers["x-forwarded-for"] || req.connection.remoteAddress;

    const result = await authService.resetPassword({
      token,
      password,
      ipAddress,
    });
    return res.status(200).json(result);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: error.message });
  }
};
