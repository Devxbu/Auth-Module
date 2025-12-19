const jwt = require("jsonwebtoken");

const extractToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res
      .status(401)
      .json({ message: "Missing or invalid authorization header" });
  }
  const accessToken = authHeader.split(" ")[1];

  const decoded = jwt.decode(accessToken);
  req.user = decoded;
  next();
};

module.exports = extractToken;
