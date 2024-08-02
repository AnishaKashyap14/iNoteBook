const express = require("express");
const User = require("../models/User");
const router = express.Router();
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
var jwt = require('jsonwebtoken');
var fetchUser=require('../middleware/fetchUser')

const JWT_SECRET = "harryisagood$boy";

//ROUTE 1:create a user using:POST "/api/auth/createuser".No login required
router.post('/createuser', [
  body('name', 'Enter a name').isLength({ min: 3 }),
  body('email', 'Enter a valid email').isEmail(),
  body('password', 'Password must be atleast 5 characters').isLength({ min: 5 }),
], async (req, res) => {
  let  success=false;
  //if there are errors,return bad request and the errors
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({success, errors: errors.array() });
  }
  //check whether the user with this email exist already
  try {


    let user = await User.findOne({ email: req.body.email });

    if (user) {
      return res.status(400).json({ success,error: "sorry a user with this email already exists" })
    }
    const salt = await bcrypt.genSalt(10);
    const secpass = await bcrypt.hash(req.body.password, salt)
    user = await User.create({
      name: req.body.name,
      password: secpass,
      email: req.body.email,
    });
    const data = {
      user: {
        id: user.id
      }
    }
    const authtoken = jwt.sign(data, JWT_SECRET);

    // res.json(user)
    success=true;
    res.json({success, authtoken })
  }
  catch (error) {
    console.log(error.message);
    res.status(400).send("Internal server error");
  }

})
//ROUTE 2:Authenticate a user using:POST "/api/auth/login".No login required
router.post('/login', [
  body('email', 'Enter a valid email').isEmail(),
  body('password', 'Enter a valid password(cannot be blank)').exists(),
], async (req, res) => {
  let  success=false;
  //if there are errors,return bad request and the errors
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  const { email, password } = req.body;
  try {
    let user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ success, error: "Please try to login with correct credentials" });
    }
    const passwordcompare = await bcrypt.compare(password, user.password);
    if (!passwordcompare) {
      success=false
      return res.status(400).json({  success,error: "Please try to login with correct credentials" });
    }
    const data = {
      user: {
        id: user.id
      }
    }
    const authtoken = jwt.sign(data, JWT_SECRET);
    success=true;
    res.json({ success,authtoken })
  } catch (error) {
    console.log(error.message);
    res.status(400).send("Internal server error");
  }
})

//ROUTE 3:Get loggedin user credentials using:POST "/api/auth/getuser".login required
router.post('/getuser',fetchUser, async (req, res) => {
  try {
    userId = req.user.id;
    const user = await User.findById(userId).select("-password");
    res.send(user)
  } catch (error) {
    console.log(error.message);
    res.status(400).send("Internal server error");
  }
})
module.exports = router