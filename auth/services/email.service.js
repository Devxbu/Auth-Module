const nodemailer = require("nodemailer");
const env = require("../../config/env");
const authRepository = require("../repositories/auth.repository");

class EmailService {
  constructor() {
    this.transporter = nodemailer.createTransport({
      service: "Gmail",
      auth: {
        user: env.emailUser,
        pass: env.emailPass,
      },
    });
  }

  async sendVerificationEmail(to, token) {
    const subject = "Verify your email address";
    const verifyUrl = `${env.frontendVerifyEmailUrl}?token=${token}`;

    const text = `Welcome! Please verify your email by clicking the following link: ${verifyUrl}`;

    const html = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #eee; border-radius: 5px; }
          .header { text-align: center; margin-bottom: 20px; }
          .button { display: inline-block; padding: 12px 24px; background-color: #007bff; color: white; text-decoration: none; border-radius: 4px; font-weight: bold; }
          .footer { margin-top: 30px; font-size: 12px; color: #999; text-align: center; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h2>Verify your email address</h2>
          </div>
          <p>Hello,</p>
          <p>Thank you for registering. To complete your account setup and ensure the security of your account, please verify your email address by clicking the button below:</p>
          <p style="text-align: center; margin: 30px 0;">
            <a href="${verifyUrl}" class="button">Verify Email</a>
          </p>
          <p>If you didn't create an account, you can safely ignore this email.</p>
          
          <div class="footer">
            <p>If the button doesn't work, copy and paste this link into your browser:</p>
            <p><a href="${verifyUrl}">${verifyUrl}</a></p>
            <p>&copy; ${new Date().getFullYear()} Your Company Name. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `;

    try {
      const info = await this.transporter.sendMail({
        from: `"Auth Service" <${env.emailUser}>`,
        to,
        subject,
        text,
        html,
      });
      console.log("Message sent: %s", info.messageId);
      return info;
    } catch (error) {
      console.error("Error sending email:", error);
      throw new Error("Failed to send verification email");
    }
  }
  async sendForgotPasswordEmail(to, token) {
    const subject = "Change your password";
    const verifyUrl = `${env.frontendForgotPassUrl}?token=${token}`;

    const text = `Welcome! Please change your password by clicking the following link: ${verifyUrl}`;

    const html = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #eee; border-radius: 5px; }
          .header { text-align: center; margin-bottom: 20px; }
          .button { display: inline-block; padding: 12px 24px; background-color: #007bff; color: white; text-decoration: none; border-radius: 4px; font-weight: bold; }
          .footer { margin-top: 30px; font-size: 12px; color: #999; text-align: center; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h2>Change your password</h2>
          </div>
          <p>Hello,</p>
          <p>Please change your password by clicking the button below:</p>
          <p style="text-align: center; margin: 30px 0;">
            <a href="${verifyUrl}" class="button">Change Password</a>
          </p>
          <p>If you didn't create an account, you can safely ignore this email.</p>
          
          <div class="footer">
            <p>If the button doesn't work, copy and paste this link into your browser:</p>
            <p><a href="${verifyUrl}">${verifyUrl}</a></p>
            <p>&copy; ${new Date().getFullYear()} Your Company Name. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `;

    try {
      const info = await this.transporter.sendMail({
        from: `"Auth Service" <${env.emailUser}>`,
        to,
        subject,
        text,
        html,
      });
      console.log("Message sent: %s", info.messageId);
      return info;
    } catch (error) {
      console.error("Error sending email:", error);
      throw new Error("Failed to send forgot password email");
    }
  }

  async sendSecurityAlert(to, reason) {
    const user = await authRepository.findById(to);
    const email = user.email;
    const subject = "Security Alert: Suspicious Activity Detected";
    const html = `
        <div style="font-family: sans-serif; padding: 20px;">
          <h2>Security Alert</h2>
          <p>We detected suspicious activity on your account.</p>
          <p>Reason: <strong>${reason}</strong></p>
          <p>If this wasn't you, please reset your password immediately.</p>
        </div>
      `;

    try {
      await this.transporter.sendMail({
        from: `"Auth Service" <${env.emailUser}>`,
        to: email,
        subject,
        html,
      });
      console.log(`Security alert sent to ${email}`);
    } catch (error) {
      console.error("Failed to send security alert:", error);
    }
  }
}

module.exports = new EmailService();
