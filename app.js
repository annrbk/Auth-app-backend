const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const crypto = require("crypto");
const dotenv = require("dotenv");
const jwt = require("jsonwebtoken");
const { createLogger } = require("winston");

const logger = createLogger();

dotenv.config();

const PORT = 5000;

const app = express();
app.use(express.json());

const corsOptions = {
  origin: process.env.CORS_LINK,
  optionsSuccessStatus: 200,
};

app.use(cors(corsOptions));

const db = mysql.createPool({
  host: process.env.DB_HOST, 
  user: process.env.DB_USERNAME, 
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 5,
  queueLimit: 0
});

db.getConnection((error) => {
  if (error) {
    logger.info("Error:", error);
    return;
  }
  logger.info("Connected to MySQL database");
});

db.promise()

const hashPassword = (password) => {
  return crypto.createHash("sha3-256").update(password).digest("hex");
};

const generateToken = (userId) => {
  return jwt.sign({ id: userId }, process.env.SECRET_KEY, { expiresIn: "24h" });
};

const authenticateToken = (req, res, next) => {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

app.get("/ping", (req, res) => {
  return res
          .status(201)
          .json({ message: "Pong!" });
})

app.post("/register", cors(corsOptions), (req, res) => {
  logger.info("I'm in register")
  const { username, email, password } = req.body;
  const hashedPassword = hashPassword(password);
  const isBlocked = false;
  const registrationDate = new Date()
    .toISOString()
    .replace("T", " ")
    .substring(0, 19);
  const lastLogin = null;

  logger.info("I'm before db query")

  const checkUniqueEmail = "SELECT * FROM users WHERE email = ?";
  db.query(checkUniqueEmail, [email], (checkErr, checkRes) => {
    if (checkErr) {
      return res.status(500).json({ message: "Error checking email" });
    }
    if (checkRes.length > 0) {
      return res.status(400).json({ message: "Email already in use" });
    }

    logger.info("I'm in db query and after validation")

    const query =
      "INSERT INTO users(username, email, password, is_blocked, registration_date, last_login) VALUES (?, ?, ?, ?, ?, ?)";
    db.query(
      query,
      [username, email, hashedPassword, isBlocked, registrationDate, lastLogin],
      (err, result) => {
        if (err) {
          logger.error("Error to insert user", err.message)
          return res.status(500).json({ message: err.message});
        }
        return res
          .status(201)
          .json({ message: "User registered successfully" });
      }
    );
  });
});

app.post("/login", cors(corsOptions), (req, res) => {
  const { email, password } = req.body;
  const hashedPassword = hashPassword(password);

  const query =
    "SELECT * FROM users WHERE email = ? AND password = ? AND is_blocked = false";
  db.query(query, [email, hashedPassword], (err, result) => {
    if (err) {
      return res.status(500).json({ message: "Server error" });
    }
    if (result && result.length > 0) {
      const user = result[0];
      const userId = user.id;

      const updateQuery = "UPDATE users SET last_login = NOW() WHERE id = ?";
      db.query(updateQuery, [userId], (updateErr) => {
        if (updateErr) {
          return res
            .status(500)
            .json({ message: "Failed to update last login" });
        }
      });

      const token = generateToken(userId);
      res.status(200).json({ message: "Login successfully", token, userId });
    } else {
      res.status(401).json({ message: "Login failed" });
    }
  });
});

app.get("/api/validateToken", [authenticateToken, cors(corsOptions)], (req, res) => {
  res.status(200).json({ message: "Token is valid" });
});

app.get("/users", [authenticateToken, cors(corsOptions)], (req, res) => {
  const query = "SELECT * FROM users";
  db.query(query, (err, result) => {
    if (err) {
      return res.status(500).json({ message: "Failed to fetch users" });
    }
    res.json(result);
  });
});

app.put("/api/users/block/:id", [authenticateToken, cors(corsOptions)], (req, res) => {
  const userId = req.params.id;
  const query = "UPDATE users SET is_blocked = true WHERE id = ?";

  db.query(query, [userId], (err, result) => {
    if (err) {
      return res.status(500).json({ message: "Failed to block user" });
    }
    res.status(200).json({ message: "User blocked successfully" });
  });
});

app.put("/api/users/unblock/:id", [authenticateToken, cors(corsOptions)], (req, res) => {
  const userId = req.params.id;
  const query = "UPDATE users SET is_blocked = false WHERE id = ?";

  db.query(query, [userId], (err, result) => {
    if (err) {
      return res.status(500).json({ message: "Failed to unblock user" });
    }
    res.status(200).json({ message: "User unblocked successfully" });
  });
});

app.delete("/api/users/delete/:id", [authenticateToken, cors(corsOptions)], (req, res) => {
  const userId = req.params.id;
  const query = "DELETE FROM users WHERE id = ?";

  db.query(query, [userId], (err, result) => {
    if (err) {
      return res.status(500).json({ message: "Failed to delete user" });
    }
    res.status(200).json({ message: "User deleted successfully" });
  });
});

app.listen(PORT, () => {
  logger.info(`Application listening on port ${PORT}!`);
});
