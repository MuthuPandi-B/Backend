import User from "../Models/userModel.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import nodemailer from "nodemailer";
dotenv.config();

export const registerUser = async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    const hashPassword = await bcrypt.hash(password, 10);
    //console.log(hashPassword);
    const newUser = new User({ name, email, password: hashPassword, role });
    await newUser.save();
    res
      .status(200)
      .json({ message: "User Registered Successfully", data: newUser });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

//login user || signin
export const loginUser = async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User Not Found" });
    }
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(400).json({ message: "Invalid Password" });
    }

    const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });
    user.token = token;
    await user.save();
    res
      .status(200)
      .json({ message: "User Logged In Successfully", token: token });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// forgot password
import crypto from "crypto";


export const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User Not Found" });
    }

    // Generate a random token
    const resetToken = crypto.randomBytes(32).toString("hex");

    // Set the reset token and expiration in the user document
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = Date.now() + 3600000; // 1 hour expiration
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
      text: `You are receiving this because you have requested the reset of the password for your account.
      Please click the following link or paste it into your browser to complete the process:
      https://passwordreset.netlify.app/reset-password/${resetToken}`,
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

// reset password



export const resetPassword = async (req, res) => {
  const { id, token } = req.params;
  const { password } = req.body;

  try {
    // Step 1: Verify the token using the secret key
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    console.log("Token decoded successfully:", decoded);

    // Step 2: Check if the user exists in the database with the specified id and token
    const user = await User.findOne({
      _id: id,
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() }
    });

    // Log the user data if found or error if not found
    if (!user) {
      console.log("No matching user found or token expired");
      return res.status(400).json({ message: "Invalid or expired token" });
    }
    console.log("User found:", user);

    // Step 3: Hash the new password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Step 4: Update the user's password and clear reset token fields
    user.password = hashedPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;

    // Save the updated user data
    await user.save();
    console.log("Password reset successfully");

    // Send success response
    res.status(200).json({ message: "Password reset successful" });

  } catch (error) {
    // Log specific error for debugging
    console.error("Error during reset:", error);
    
    if (error.name === "JsonWebTokenError" || error.name === "TokenExpiredError") {
      return res.status(400).json({ message: "Invalid or expired token" });
    }
    res.status(500).json({ message: "Server error" });
  }
};

