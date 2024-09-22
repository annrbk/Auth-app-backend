const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");

const PORT = 5000;

const app = express();
app.use(express.json());
app.use(cors());

const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  database: "user_management",
  password: "new_password",
});

db.connect((error) => {
  if (error) {
    console.log("Error:", error);
    return;
  }
  console.log("Connected to MySQL database");
});

let users = [];

app.post("/register", (req, res) => {
  const userData = req.body;
  const status = "active";
  const registrationDate = new Date().toISOString();
  const lastLogin = null;
  users.push(userData);
  res.status(201).json({ message: "User registered successfully", userData });
});

app.get("/users", (req, res) => {
  res.json(users);
});

app.listen(PORT, () => {
  console.log(`Application listening on port ${PORT}!`);
});
