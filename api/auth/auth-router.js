const router = require("express").Router();
const bcrypt = require("bcryptjs");
const User = require("../users/users-model");
const { checkUsernameExists, validateRoleName } = require("./auth-middleware");
const { JWT_SECRET } = require("../secrets"); // use this secret!
const jwt = require("jsonwebtoken");

router.post("/register", validateRoleName, async (req, res, next) => {
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
  try {
    const { username, password, role_name } = req.body;
    const user = await User.findBy({ username });
    if (user) {
      console.log(user);
      return res.status(409).json({ message: "Username is already taken" });
    } else {
      next();
    }

    const registerUser = await User.add({
      username,
      role_name,
      password: await bcrypt.hash(password, parseInt(process.env.ROUNDS)),
    });
    res.status(201).json(registerUser);
  } catch (err) {
    next(err);
  }
});

router.post("/login", checkUsernameExists, async (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */

  try {
    const { username, password } = req.body;
    const user = await User.findBy({ username }).first();
    if (!user) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const passwordValid = await bcrypt.compare(password, user.password);
    if (!passwordValid) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign(
      {
        userID: user.id,
        username: user.username,
        role_name: user.role_name,
      },
      JWT_SECRET
    );

    res.json({
      message: `${user.username} is back!`,
      token: token,
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
