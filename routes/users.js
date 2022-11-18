var express = require("express");
var router = express.Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
var { uuid } = require("uuidv4");
const { db } = require("../mongo");

let user = {};

/* GET users listing. */
router.get("/", function (req, res, next) {
  res.json({
    success: true,
  });
});

router.post("/register", async function (req, res, next) {
  const email = req.body.email;
  const password = req.body.password;

  const saltRounds = 5;
  const salt = await bcrypt.genSalt(saltRounds);
  const hash = await bcrypt.hash(password, salt);

  user = {
    email,
    password: hash,
    id: uuid(),
  };

  console.log(salt);
  console.log(hash);

  console.log(user);

  const addUser = await db().collection("users").insertOne(user);

  res.json({
    success: true,
    user,
  });
});

router.post("/login", async function (req, res, next) {
  const email = req.body.email;
  const password = req.body.password;

  const retrieveUser = await db().collection("users").findOne({
    email: email,
  });

  const passwordMatch = await bcrypt.compare(password, retrieveUser.password);

  console.log(passwordMatch);
  if (retrieveUser === null) {
    res.json({
      success: false,
    });
    return;
  }
  if (passwordMatch === true) {
    let scope = retrieveUser.email.includes("codeimmersives.com")
      ? "admin"
      : "user";
    console.log(scope);
    const userData = {
      email: retrieveUser.email,
      date: new Date(),
      userId: retrieveUser.id,
      scope,
      
    };

    const payload = {
      userData,
      exp: Math.floor(Date.now() / 1000) + 60 * 60,
    };

    const secretKey = process.env.JWT_SECRET_KEY;
    const token = jwt.sign(payload, secretKey);

    res.json({
      success: true,
      token: token,
      email: retrieveUser.email,
    });
    return;
  }

  if (passwordMatch === false) {
    res.json({
      success: false,
      message: "your password is incorrect",
    });
  }
});

router.get('/message', async function (req, res, next){
  try {
     const tokenToAuth = req.header(process.env.TOKEN_HEADER_KEY)
  const secretKey = process.env.JWT_SECRET_KEY

  const verified = jwt.verify(tokenToAuth, secretKey)
 
  
  console.log(verified)

 
    let userScope = ""
  
 
  if(verified.userData.scope === "user"){
    userScope = "user"
  }
  if(verified.userData.scope === "admin"){
    userScope = "admin"
  }

  return res.json({
    success: true,
    verified: verified,
    message: "You are verified",
    user: userScope
  })
  } catch (error) {
    return res.json({
      success: false,
      message: error.toString()
    })
  }
 
  
})

module.exports = router;
