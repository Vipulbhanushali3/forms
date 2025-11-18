import express from "express";
import bodyParser from "body-parser";
import fs from "fs";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cors from "cors";

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Simulated database file
const USERS_FILE = "./users.json";

// Secret key for JWT
const JWT_SECRET = "your_secret_key";

// Helper: Load users from file
function loadUsers() {
  if (!fs.existsSync(USERS_FILE)) return [];
  const data = fs.readFileSync(USERS_FILE);
  return JSON.parse(data);
}

// Helper: Save users to file
function saveUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

// -------------------- SIGNUP API --------------------
app.post("/api/signup", async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password)
    return res.status(400).json({ message: "All fields are required" });

  const users = loadUsers();

  if (users.find((u) => u.email === email)) {
    return res.status(400).json({ message: "Email already registered" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const newUser = { id: Date.now(), name, email, password: hashedPassword };
  users.push(newUser);
  saveUsers(users);

  // ⭐ GENERATE TOKEN HERE
  const token = jwt.sign(
      { id: newUser.id, name: newUser.name, email: newUser.email },
      JWT_SECRET,
      { expiresIn: "1h" }
  );

  res.json({
    message: "Signup successful",
    token,       // send token
  });
});


// -------------------- LOGIN API --------------------
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res.status(400).json({ message: "Email and password required" });

  const users = loadUsers();
  const user = users.find((u) => u.email === email);
  if (!user) return res.status(401).json({ message: "Invalid credentials" });

  // Compare password
  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).json({ message: "Invalid credentials" });

  // Create JWT token
  const token = jwt.sign(
      { id: user.id, name: user.name, email: user.email },
      JWT_SECRET,
      { expiresIn: "1h" }
  );

  res.json({ message: "Login successful", token });
});

// -------------------- PROTECTED ROUTE EXAMPLE --------------------
app.get("/api/profile", (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ message: "No token provided" });

  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    res.json({ message: "Profile data", user: decoded });
  } catch (err) {
    res.status(401).json({ message: "Invalid or expired token" });
  }
});

app.listen(3000, () => console.log("✅ Server running on http://localhost:3000"));
