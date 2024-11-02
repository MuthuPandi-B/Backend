import User from "../Models/userModel.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import nodemailer from "nodemailer";
import crypto from "crypto";

dotenv.config();

// Register User
export const registerUser = async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    const hashPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ name, email, password: hashPassword, role });
    await newUser.save();
    res.status(200).json({ message: "User Registered Successfully", data: newUser });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// Login User
export const loginUser = async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User Not Found" });

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) return res.status(400).json({ message: "Invalid Password" });

    const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });
    res.status(200).json({ message: "User Logged In Successfully", token });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// Forgot Password
export const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User Not Found" });

    // Generate a random reset token
    const resetToken = crypto.randomBytes(32).toString("hex");
    const hashedToken = await bcrypt.hash(resetToken, 10);

    user.resetPasswordToken = hashedToken; // Save the hashed token in DB
    user.resetPasswordExpires = Date.now() + 3600000; // 1 hour expiration
    await user.save();

    // Send reset link with the plain reset token in the URL
    const resetLink = `https://passwordreset.netlify.app/reset-password/${resetToken}`;
    const transporter = nodemailer.createTransport({
      service: "Gmail",
      auth: {
        user: process.env.PASS_MAIL,
        pass: process.env.PASS_KEY,
      },
    });
    const mailOptions = {
      from: process.env.PASS_MAIL,
      to: user.email,
      subject: "Password Reset Link",
      text: `You are receiving this because you have requested the reset of the password for your account. Please click the following link or paste it into your browser to complete the process: ${resetLink}`,
    };
    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.log(error);
        return res.status(500).json({ message: "Internal server error in sending the mail" });
      }
      res.status(200).json({ message: "Email Sent Successfully" });
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};



// Reset Password
export const resetPassword = async (req, res) => {
  const { resetToken } = req.params; // This is your plain token from the URL
  const { password } = req.body;

  try {
      // Find the user with the reset token and ensure it hasn’t expired
      const user = await User.findOne({
          resetPasswordToken: { $exists: true }, // Check if token exists
          resetPasswordExpires: { $gt: Date.now() }, // Check if token hasn't expired
      });

      console.log("User retrieved:", user);

      if (!user) {
          return res.status(400).json({ message: "Invalid or expired token" });
      }

      // Compare the plain reset token with the hashed one
      const isTokenValid = await bcrypt.compare(resetToken, user.resetPasswordToken);
      console.log("Is token valid?", isTokenValid);

      if (!isTokenValid) {
          return res.status(400).json({ message: "Invalid or expired token" });
      }

      // Hash the new password and save it
      const hashedPassword = await bcrypt.hash(password, 10);
      user.password = hashedPassword;
      user.resetPasswordToken = undefined; // Clear token
      user.resetPasswordExpires = undefined; // Clear expiration

      await user.save();
      res.status(200).json({ message: "Password reset successful" });

  } catch (error) {
      console.error("Error:", error);
      res.status(500).json({ message: "Server error" });
  }
};
