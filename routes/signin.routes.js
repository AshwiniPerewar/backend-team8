const { Router } = require("express");
const authController = Router();
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const { userModel } = require("../models/User.model");
const {
  mailOtp,
  generateToken,
  validateEmail
} = require("../util/emailotp");
const otpModel = require("../models/Otp.model");
const customEmailMessage = "sign in with masai portal.";
const customEmailMessage2 = "reset your old password";
const rateLimit = require("express-rate-limit");

const apiLimiter = rateLimit({
  windowMs: 360 * 60 * 1000, //1 hour
  max: 10, // Limit each IP to 10 requests per `window` (here, per 60 minutes)
  message: "Too many requests. Try again after some time.",
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
});

authController.use("/signin", apiLimiter);

// APT for sign in
authController.post("/signin", async (req, res) => {
  const { email, password } = req.body;
  const emailValidation = validateEmail(email);
  if (emailValidation) {
    const user = await userModel.findOne({ email });
    if (user && password) {
      const hash = user.password;
      if (user && password) {
        const verification = await bcrypt.compare(password, hash);
        if (verification) {
          res.send(
            generateToken({
              email: user.email,
              fullName: user.fullName,
              mobile: user.mobile,
            })
          );
        } else if (user && !verification)
          res.status(401).send({ msg: "Please enter a valid password." });
      }
    } else if (user) {
      mailOtp(email, customEmailMessage, user?.fullName);
      res.status(200).send({
        msg: "OTP sent successfully, Please check your email for OTP.",
      });
    } else
      res.status(401).send({
        msg: "The account you mentioned does not exist. Please try with correct email address.",
      });
  } else res.status(401).send({ msg: "Please enter a valid email address." });
});

// API to verify otp sent on email
authController.post("/verifyotp", async (req, res) => {
  const { email, otp } = req.body;
  const user = await otpModel.findOne({ email });
  if (user && user.otp == otp) {
    const userDetails = await userModel.findOne({ email });
    if (userDetails)
      res.send(
        generateToken({
          email: userDetails.email,
          full_name: userDetails.full_name,
          mobile: userDetails.mobile,
        })
      );
  } else res.status(401).send({ msg: "Please enter a valid 6 digit OTP." });
});

authController.post("/forget", async (req, res) => {
  let { email } = req.body;
  const user = await userModel.findOne({ email });
  if (user) {
    try {
      sendmail(email, customEmailMessage2, user?.fullName);
      res.status(200).send({ msg: "your otp for reset password is sended" });
    } catch (err) {
      console.log(err);
      res.status(401).send("something went wrong! try again");
    }
  } else {
    res.status(404).send({ msg: "user not found" });
  }
});

authController.post("/reset", async (req, res) => {
  let { otp, password } = req.body;
  let isValidOtp = await otpModel.findOne({ otp });
  if (isValidOtp) {
    let { email } = isValidOtp;
    bcrypt.hash(password, 5, async function (err, hash) {
      if (err) {
        res.status(400).send({ msg: "something went wrong! try again" });
      } else {
        let isUpdate = await userModel.findOneAndUpdate(
          { email },
          { password: hash }
        );
        if (isUpdate) {
          res.status(200).send("password updated");
        }
      }
    });
  } else {
    res.status(401).send("Invalid otp");
  }
});

module.exports = { authController };
