const { Router } = require("express");
const authController = Router();
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const { UserModel } = require("../models/User.model");
const {
  sendMailOtp,
  generateToken,
  validateEmail,
} = require("../util/emailotp");
const OtpModel = require("../models/Otp.model");
const customEmailMessage = "sign in with masai portal.";
const customEmailMessage2 = "reset your old password";
const rateLimit = require("express-rate-limit");

// <----------------------  Function to limit the 10 requests per 60 minutes   -------------->

const apiLimiter = rateLimit({
  windowMs: 360 * 60 * 1000, //1 hour
  max: 10, // Limit each IP to 10 requests per `window` (here, per 60 minutes)
  message: "Too many requests. Try again after some time.",
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
});

authController.use("/signin", apiLimiter);

//<-------------------------------   APT for sign in   ------------------------------->

authController.post("/signin", async (req, res) => {
  const { email, password, mobile } = req.body;
  if (email) {
    const validEmail = validateEmail(email);
    if (validEmail) {
      const userDetails = await UserModel.findOne({ email });
      if (userDetails && password) {
        const hash = userDetails.password;
        if (userDetails && hash) {
          const verification = await bcrypt.compare(password, hash);
          if (verification) {
            res.status(200).send({
              msg: "Signed in successfully",
              token: generateToken({
                email: userDetails.email,
                fullName: userDetails.fullName,
                mobile: userDetails.mob,
              }),
            });
          } else if (userDetails && !verification)
            res.status(401).send({ msg: "Please enter a valid password." });
        }
      } else if (userDetails && !userDetails.password) {
        res.status(200).send({
          msg: "Password is not associated with your email address, Please try with OTP.",
        });
      } else if (userDetails) {
        sendMailOtp(email, customEmailMessage, userDetails?.fullName);
        res.status(200).send({
          msg: "OTP sent successfully, Please check your email for OTP.",
        });
      } else
        res.status(401).send({
          msg: "The account you mentioned does not exist. Please try with correct email address.",
        });
    } else res.status(401).send({ msg: "Please enter a valid email address." });
  } else if (mobile) {
    if (mobile.length != 10 || mobile[0] == 0)
      res
        .status(401)
        .send({ msg: "Please Enter 10 digit valid mobile number" });
    else {
      const userDetails = await UserModel.findOne({ mob: mobile });
      if (userDetails && password && !userDetails.password) {
        res.status(401).send({
          msg: "Password is not associated with your mobile number, Please try with OTP.",
        });
      } else if (!userDetails) {
        res
          .status(401)
          .send({
            msg: "There is no account associated with this mobile number",
          });
      } else
        res.status(200).send({
          msg: "Signed in successfully",
          token: generateToken({
            email: userDetails.email,
            fullName: userDetails.fullName,
            mobile: userDetails.mob,
          }),
        });
    }
  }
});

//<--------------------    API to verify otp sent on email ----------------------->
authController.post("/verifyotp", async (req, res) => {
  const { email, otp } = req.body;
  const user = await OtpModel.findOne({ email });
  if (user && user.otp == otp) {
    const userDetails = await UserModel.findOne({ email });
    if (userDetails)
      res.status(200).send({
        msg: "Signed in successfully",
        token: generateToken({
          email: userDetails.email,
          fullName: userDetails.fullName,
          mobile: userDetails.mob,
        }),
      });
  } else res.status(401).send({ msg: "Please enter a valid 6 digit OTP." });
});

authController.post("/forget", async (req, res) => {
  let { email } = req.body;
  const user = await UserModel.findOne({ email });
  if (user) {
    try {
      sendMailOtp(email, customEmailMessage2, user?.fullName);
      res.status(200).send({ msg: "your otp for reset password is sended" });
    } catch (err) {
      res.status(401).send("something went wrong! try again");
    }
  } else {
    res.status(404).send({ msg: "user not found" });
  }
});

authController.post("/reset", async (req, res) => {
  let { otp, password } = req.body;
  let isValidOtp = await OtpModel.findOne({ otp });
  if (isValidOtp) {
    let { email } = isValidOtp;
    bcrypt.hash(password, 5, async function (err, hash) {
      if (err) {
        res.status(400).send({ msg: "something went wrong! try again" });
      } else {
        let isUpdate = await UserModel.findOneAndUpdate(
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

module.exports = authController;
