const router = require("express").Router();
const { check, validationResult } = require("express-validator");
const bcrypt = require("bcrypt");
const JWT = require("jsonwebtoken");
const { users } = require("../database");

require("dotenv").config();

// Sign up
router.post(
  "/signup",
  [
    check("email", "Invalid email").isEmail(),
    check("password", "Password must be at least 6 chars long").isLength({
      min: 6,
    }),
  ],
  async (req, res) => {
    const { email, password } = req.body;

    // Validate user input
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      return res.status(400).json({
        errors: errors.array(),
      });
    }

    // Validate if user already exists
    let user = users.find((user) => {
      return user.email === email;
    });

    if (user) {
      // 422 Unprocessable Entity: server understands the content type of the request entity
      // 200 Ok: Gmail, Facebook, Amazon, Twitter are returning 200 for user already exists
      return res.status(200).json({
        errors: [
          {
            email: user.email,
            msg: "The user already exists",
          },
        ],
      });
    }

    // Hash password before saving to database
    const salt = await bcrypt.genSalt(10);
    console.log("salt:", salt);
    const hashedPassword = await bcrypt.hash(password, salt);
    console.log("hashed password:", hashedPassword);

    // Save email and password to database/array
    users.push({
      email,
      password: hashedPassword,
    });

    // Do not include sensitive information in JWT
    const accessToken = await JWT.sign(
      { email },
      process.env.ACCESS_TOKEN_SECRET,
      {
        expiresIn: "10s",
      }
    );

    res.json({
      accessToken,
    });
  }
);

// Error status code
// 401 Unauthorized: it’s for authentication, not authorization. Server says "you're not authenticated".
// 403 Forbidden: it's for authorization. Server says "I know who you are,
//                but you just don’t have permission to access this resource".

///////////////////////////

// Get all users
router.get("/users", (req, res) => {
  res.json(users);
});

// Log in
router.post("/login", async (req, res) => {
  const { email, password } = req.body;

  // Look for user email in the database
  let user = users.find((user) => {
    return user.email === email;
  });

  // If user not found, send error message
  if (!user) {
    return res.status(400).json({
      errors: [
        {
          msg: "Invalid credentials",
        },
      ],
    });
  }

  // Compare hased password with user password to see if they are valid
  let isMatch = await bcrypt.compare(password, user.password);

  if (!isMatch) {
    return res.status(401).json({
      errors: [
        {
          msg: "Email or password is invalid",
        },
      ],
    });
  }

  // Send JWT
  const accessToken = await JWT.sign(
    { email },
    process.env.ACCESS_TOKEN_SECRET,
    {
      expiresIn: "10s",
    }
  );

  res.json({
    accessToken,
  });
});

module.exports = router;
