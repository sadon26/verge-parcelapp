const express = require("express");
const router = express.Router();
const pool = require("../query");
const bcrypt = require("bcryptjs");
var jwt = require("jsonwebtoken");
const dotenv = require("dotenv");

dotenv.config({ path: "../config/config.env" });

//Create a user
router.post("/signup", async (req, res) => {
  const { role_id, email, password, first_name, last_name, state } = req.body;

  let errors = [];

  var salt = bcrypt.genSaltSync(10);
  let hashedPassword = await bcrypt.hash(password, salt);

  if (!role_id || !email || !password || !first_name || !last_name || !state) {
    errors.push({
      message: "Please enter all fields",
    });
  }

  const roleQueryObj = {
    text: "SELECT * FROM Roles WHERE id = $1",
    values: [role_id],
  };

  // check for role
  pool.query(roleQueryObj, (err, results) => {
    if (err) {
      throw err;
    }
    if (results.rowCount == 0) {
      res.status(400).json({
        message: "Role not found",
      });
    }
  });

  if (password.length < 6) {
    errors.push({
      message: "Password should be at least 6 characters",
    });
  }

  const queryObj = {
    text: "SELECT * FROM Users WHERE email = $1",
    values: [email],
  };

  const queryObjTwo = {
    text:
      "INSERT INTO Users (role_id, email, password, first_name, last_name, state) VALUES($1, $2, $3, $4, $5, $6) RETURNING *",
    values: [role_id, email, hashedPassword, first_name, last_name, state],
  };

  pool.query(queryObj, (err, results) => {
    if (err) {
      res.json({
        message: err,
      });
    }

    if (!results) {
      res.status(400).json({
        message: "Something went wrong with the registration. Try again!",
      });
    }

    if (results.rowCount > 0) {
      res.status(401).json({
        message: "Email already exists",
      });
    } else if (results.rowCount == 0) {
      pool.query(queryObjTwo, (err, response) => {
        if (err) {
          res.json({
            message: err,
          });
        }
        res.json({
          message: "User created successfully",
        });
        console.log(response);
      });
    }
  });

  if (errors.length > 0) {
    res.json({
      errors,
    });
  }
});

//User login
router.post("/login", (req, res) => {
  const { email } = req.body;
  pool.query(
    "SELECT * FROM Users WHERE email = $1",
    [email],
    (err, results) => {
      if (results.rowCount == 0) {
        res.json({
          message: "Email is not found",
        });
      }
      if (err) {
        throw err;
      }
      if (results.rowCount == 1) {
        const user = results.rows[0];
        const { password } = req.body;
        pool.query(
          "SELECT * FROM Users WHERE password = $1",
          [password],
          (err, results) => {
            bcrypt.compare(password, user.password, (err, isMatch) => {
              if (err) {
                throw err;
              }
              if (isMatch) {
                const token = jwt.sign(
                  {
                    _id: user.id,
                  },
                  "secret"
                );
                res.header("auth-token", token).json(token);
              }
              if (!isMatch) {
                res.json({
                  message: "Please make sure your password is correct",
                });
              }
            });
          }
        );
      }
    }
  );
});

module.exports = router;
