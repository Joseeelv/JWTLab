require("dotenv").config();

const express = require("express");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const app = express();

const PORT = 3000;
const FRONTEND_ORIGIN = "http://localhost:8000";

app.use(
  cors({
    origin: FRONTEND_ORIGIN,
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  })
);

app.use(bodyParser.json());
app.use(cookieParser());

const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret_key_here";
console.log("JWT_SECRET:", JWT_SECRET);

// In-memory "database"
const users = [];
users.push({ user: "admin", password: "admin" });
console.log(users);

// Vulnerability flags
const FLAGS = {
  ALG_NONE: "FLAG{alg_none_bypass}",
  ALG_CONFUSION: "FLAG{algorithm_confusion}",
  KID_INJECTION: "FLAG{kid_injection}",
  PAYLOAD_TAMPERING: "FLAG{payload_tampering}",
};

// Registration endpoint
app.post("/register", (req, res) => {
  const { user, password } = req.body;

  if (!user || !password) {
    return res.status(400).json({ error: "Username and password required" });
  }

  if (users.find((u) => u.user === user)) {
    return res.status(409).json({ error: "User already exists" });
  }

  users.push({ user, password });
  res.json({ message: "User registered successfully" });
});

// Login endpoint
app.post("/login", (req, res) => {
  const { user, password } = req.body;
  console.log("Cookies on login:", req.cookies);
  if (!user || !password) {
    return res.status(400).json({ error: "Username and password required" });
  }

  const userFound = users.find((u) => u.user === user);
  if (!userFound) return res.status(401).json({ error: "User not found" });

  if (userFound.password !== password) {
    return res.status(401).json({ error: "Invalid password" });
  }

  // Signing token with HS256 and including isAdmin boolean
  const token = jwt.sign(
    { user, isAdmin: userFound.user === "admin" },
    JWT_SECRET,
    { algorithm: "HS256" }
  );

  res.cookie("token", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production" ? true : false,
    sameSite: "lax",
    maxAge: 3600000,
  });

  res.json({
    message: "Login successful",
    isAdmin: userFound.user === "admin",
  });
});

// Profile endpoint: vulnerable to all JWT attacks
app.get("/profile", (req, res) => {
  console.log("Cookies received:", req.cookies);
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: "Token required" });

  try {
    // Decode JWT header
    const header = JSON.parse(
      Buffer.from(token.split(".")[0], "base64").toString()
    );

    // Vulnerability: alg:none bypass
    if (header.alg === "none") {
      const payload = JSON.parse(
        Buffer.from(token.split(".")[1], "base64").toString()
      );
      return res.json({
        message: `Hi ${payload.user}! Welcome to the vulnerable lab.`,
        isAdmin: true,
        flag: FLAGS.ALG_NONE,
        redirectToAdmin: true,
      });
    }

    // Vulnerability: kid injection simulation
    if (header.kid && header.kid.includes("' OR 1=1 --")) {
      const decoded = jwt.verify(token, JWT_SECRET, {
        algorithms: ["HS256", "none"],
      });
      return res.json({
        user: decoded.user,
        isAdmin: true,
        flag: FLAGS.KID_INJECTION,
        redirectToAdmin: true,
      });
    }

    // Vulnerability: algorithm confusion forced by query param
    if (req.query.forceConfusion) {
      const decoded = jwt.verify(token, JWT_SECRET, {
        algorithms: ["HS256", "none"],
      });
      return res.json({
        user: decoded.user,
        isAdmin: true,
        flag: FLAGS.ALG_CONFUSION,
        redirectToAdmin: true,
      });
    }

    // Normal token verification
    const decoded = jwt.verify(token, JWT_SECRET, {
      algorithms: ["HS256", "none"],
    });

    // Payload tampering: if isAdmin true but user is not admin
    if (decoded.isAdmin && decoded.user !== "admin") {
      return res.json({
        user: decoded.user,
        isAdmin: true,
        flag: FLAGS.PAYLOAD_TAMPERING,
        redirectToAdmin: true,
      });
    }

    // Default response
    res.json({
      message: `Hi ${decoded.user}! Welcome to the vulnerable lab.`,
    });
  } catch (e) {
    console.error("Error validating token:", e.message);
    res.status(401).json({ error: "Invalid token" });
  }
});

// Admin endpoint: vulnerable to all JWT attacks
app.get("/admin", (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: "Token required" });

  try {
    const header = JSON.parse(
      Buffer.from(token.split(".")[0], "base64").toString()
    );

    if (header.alg === "none") {
      const payload = JSON.parse(
        Buffer.from(token.split(".")[1], "base64").toString()
      );
      if (payload.isAdmin) {
        return res.json({
          message: "Welcome, admin!",
          isAdmin: true,
          flag: FLAGS.ALG_NONE,
        });
      } else {
        return res.status(403).json({ error: "No admin privileges" });
      }
    }

    if (header.kid && header.kid.includes("' OR 1=1 --")) {
      const decoded = jwt.verify(token, JWT_SECRET, {
        algorithms: ["HS256", "none"],
      });
      if (decoded.isAdmin) {
        return res.json({
          message: "Welcome, admin!",
          isAdmin: true,
          flag: FLAGS.KID_INJECTION,
        });
      } else {
        return res.status(403).json({ error: "No admin privileges" });
      }
    }

    if (req.query.forceConfusion) {
      const decoded = jwt.verify(token, JWT_SECRET, {
        algorithms: ["HS256", "none"],
      });
      if (decoded.isAdmin) {
        return res.json({
          message: "Welcome, admin!",
          isAdmin: true,
          flag: FLAGS.ALG_CONFUSION,
        });
      } else {
        return res.status(403).json({ error: "No admin privileges" });
      }
    }

    const decoded = jwt.verify(token, JWT_SECRET, {
      algorithms: ["HS256", "none"],
    });

    if (decoded.isAdmin && decoded.user !== "admin") {
      return res.json({
        message: "Welcome, admin!",
        isAdmin: true,
        flag: FLAGS.PAYLOAD_TAMPERING,
      });
    }

    if (decoded.isAdmin) {
      return res.json({ message: "Welcome, admin!", isAdmin: true });
    } else {
      return res.status(403).json({ error: "No admin privileges" });
    }
  } catch (e) {
    res.status(401).json({ error: "Invalid token" });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Vulnerable JWT Lab running on http://localhost:${PORT}`);
});
