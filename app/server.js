const dotenv = require("dotenv");
dotenv.config();

const express = require("express");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const fs = require("fs");
const path = require("path");

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

// Vulnerable flags
const FLAGS = {
  ALG_NONE: "FLAG{alg_none_bypass}",
  ALG_CONFUSION: "FLAG{algorithm_confusion}",
  KID_INJECTION: "FLAG{kid_injection}",
  PAYLOAD_TAMPERING: "FLAG{payload_tampering}",
};

// Fake key store simulating insecure key management
const fakeKeyStore = {
  "default-key": Buffer.from(JWT_SECRET),
  "malicious-key": Buffer.from("fake-key-for-exploit"),
  ed2Nf8sb: Buffer.from("claveSegura123"),
  "dev-null": Buffer.from(""),
};

// Custom JWT header
const CUSTOM_HEADER = {
  alg: "HS256",
  typ: "JWT",
  kid: "ed2Nf8sb",
};

// Path to /app/etc/passwd.txt
const passwdDir = "/app/etc";
const passwdPath = path.join(passwdDir, "passwd.txt");

// Create directory if it does not exist
if (!fs.existsSync(passwdDir)) {
  fs.mkdirSync(passwdDir, { recursive: true });
}

// Validate user by reading passwd.txt
function isValidUser(user, password) {
  try {
    if (!fs.existsSync(passwdPath)) return false;

    const lines = fs.readFileSync(passwdPath, "utf8").split("\n");

    for (const line of lines) {
      const [u, p] = line.trim().split(":");
      if (u === user && p === password) {
        return true;
      }
    }

    return false;
  } catch (err) {
    console.error("Error reading /app/etc/passwd.txt:", err);
    return false;
  }
}

// User registration
app.post("/register", (req, res) => {
  const { user, password } = req.body;

  if (
    typeof user !== "string" ||
    typeof password !== "string" ||
    !user ||
    !password
  ) {
    return res.status(400).json({ error: "User and password are required" });
  }

  console.log(`[REGISTER] User: ${user}, Password: ${password}`); // <-- Here

  const entry = `${user}:${password}\n`;

  try {
    fs.appendFileSync(passwdPath, entry, "utf8");
    res.json({ message: "User registered" });
  } catch (err) {
    console.error("Error writing to /app/etc/passwd.txt", err);
    res.status(500).json({ error: "Failed to register" });
  }
});
// Login with JWT
app.post("/login", (req, res) => {
  const { user, password } = req.body;

  if (
    typeof user !== "string" ||
    typeof password !== "string" ||
    !user ||
    !password
  ) {
    return res.status(400).json({ error: "Missing credentials" });
  }

  console.log(`[LOGIN] User: ${user}, Password: ${password}`); // <-- Here

  const valid = isValidUser(user, password);

  if (!valid) {
    return res.status(401).json({ error: "Invalid login" });
  }

  const token = jwt.sign({ user, isAdmin: user === "admin" }, JWT_SECRET, {
    algorithm: "HS256",
    header: CUSTOM_HEADER,
  });

  res.cookie("token", token, {
    httpOnly: true,
    secure: false,
    sameSite: "lax",
    maxAge: 3600000,
  });

  res.json({ message: "Login successful", isAdmin: user === "admin" });
});

app.get("/profile", (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: "Token missing" });

  try {
    // Decode header without verifying
    const header = JSON.parse(
      Buffer.from(token.split(".")[0], "base64").toString()
    );
    const keyId = header.kid || "default-key";

    if (keyId.includes("../") || keyId.includes("/") || keyId.includes("\\")) {
      try {
        // Try to read the file indicated in kid
        const fileContent = fs.readFileSync(keyId, "utf8");
        return res.json({
          message: "Kid injection successful via path traversal",
          isAdmin: true,
          flag: FLAGS.KID_INJECTION
        });
      } catch (err) {
        console.error("Error reading file from kid:", err);
        return res
          .status(400)
          .json({ error: "Cannot read file from kid: " + err.message });
      }
    }

    // If not path traversal, verify JWT normally
    const verificationKey = fakeKeyStore[keyId] || JWT_SECRET;

    const decoded = jwt.verify(token, verificationKey, {
      algorithms: ["HS256", "RS256", "none"],
      ignoreExpiration: true,
    });

    // Further checks
    if (decoded.isAdmin && decoded.user !== "admin") {
      return res.json({
        message: "Payload tampering detected",
        user: decoded.user,
        isAdmin: true,
        flag: FLAGS.PAYLOAD_TAMPERING,
      });
    }

    res.json({ message: `Hello ${decoded.user}`, isAdmin: decoded.isAdmin });
  } catch (err) {
    console.error("Token validation error:", err.message);
    res.status(401).json({ error: "Invalid token" });
  }
});

// Admin route
app.get("/admin", (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: "Token required" });

  try {
    const header = JSON.parse(
      Buffer.from(token.split(".")[0], "base64").toString()
    );
    const keyId = header.kid || "default-key";
    const verificationKey = fakeKeyStore[keyId] || JWT_SECRET;

    const decoded = jwt.verify(token, verificationKey, {
      algorithms: ["HS256", "RS256", "none"],
      ignoreExpiration: true,
    });

    if (decoded.isAdmin) {
      return res.json({ message: "Welcome, admin!", isAdmin: true });
    }

    res.status(403).json({ error: "Not an admin" });
  } catch (err) {
    res.status(401).json({ error: "Invalid token" });
  }
});

app.listen(PORT, () => {
  console.log(`Vulnerable JWT Lab running on http://localhost:${PORT}`);
});
