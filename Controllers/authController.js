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
    res
      .status(200)
      .json({ message: "User Registered Successfully", data: newUser });
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
    if (!passwordMatch)
      return res.status(400).json({ message: "Invalid Password" });

    const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });
    res.status(200).json({ message: "User Logged In Successfully", token });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

export const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User Not Found" });
    }
    const resetToken = crypto.randomBytes(20).toString("hex");
    const hashedResetToken = await bcrypt.hash(resetToken, 10);

    user.resetPasswordToken = hashedResetToken;
    user.resetPasswordExpires = Date.now() + 3600000; // 1 hour from now
    await user.save();

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
      text: `Dear ${user.name}
          We received a request to reset your password for your account. 
             Please click the link below to set a new password. 
            This link is only valid for the next hour:
      https://passwordreset.netlify.app/reset-password/${resetToken}
      If you didn’t request this, you can ignore this email. Your password will remain unchanged.

    Thank you,
    The Password Reset Team`,
    };
    transporter.sendMail(mailOptions, function (error, info) {
      if (error) {
        console.log(error);
        res
          .status(500)
          .json({ message: "Internal server error in sending the mail" });
      } else {
        res.status(200).json({ message: "Email Sent Successfully" });
      }
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

export const resetPassword = async (req, res) => {
  const { resetToken } = req.params;
  const { password } = req.body;

  try {
    const user = await User.findOne({
      resetPasswordToken: { $exists: true },
      resetPasswordExpires: { $gt: Date.now() },
    });
    if (!user)
      return res.status(400).json({ message: "Invalid or expired token" });

    const isMatch = await bcrypt.compare(resetToken, user.resetPasswordToken);
    if (!isMatch) return res.status(400).json({ message: "Invalid Token" });

    // Update password and clear reset token
    user.password = await bcrypt.hash(password, 10);
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    res.status(200).json({ message: "Password updated successfully" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};
