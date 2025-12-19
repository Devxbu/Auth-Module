const express = require("express");
const router = express.Router();
const extractToken = require("../middleware/extractToken");
const authController = require("./auth.controller");

router.post("/register", authController.register);
router.post("/login", authController.login);
router.post("/refresh", authController.refreshToken);
router.post("/logout", extractToken, authController.logout);
router.post("/logout-all", extractToken, authController.logoutAll);
router.post("/forgot-password", authController.forgotPassword);
router.post("/reset-password", authController.resetPassword);

module.exports = router;
