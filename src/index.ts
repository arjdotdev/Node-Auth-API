import express, { Request, Response } from "express";
import { body, validationResult } from "express-validator";
import bcrypt from "bcrypt";
import { v4 as uuidv4 } from "uuid";
import { NextFunction } from "express-serve-static-core";
import jwt from "jsonwebtoken";
import { JwtPayload } from "jsonwebtoken";

// ——— Tell TS that Express.Request has a `user` property ———
declare global {
  namespace Express {
    interface Request {
      user?: {
        userId: string;
        email: string;
        iat: number;
        exp: number;
      };
    }
  }
}

const app = express();
const PORT = process.env.PORT || 3000;
const BCRYPT_SALT_ROUNDS = 10;

// In-memory user store
interface User {
  id: string;
  email: string;
  passwordHash: string;
  createdAt: string;
}
const users: User[] = [];

// JWT secret (in production, set via env var)
const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key";
const JWT_EXPIRES_IN = "1h";

// In‐memory blacklist for “logged out” tokens
const tokenBlacklist: string[] = [];

// JSON body parsing middleware, changing JSON to JS object
app.use(express.json());

app.get("/", (req: Request, res: Response) => {
  res.json("User Auth API server is up and running!");
});

app.post("/echo", (req: Request, res: Response) => {
  res.json({ received: req.body }); //req.body is whatever we send on the payload
});

//Register Endpoint
app.post(
  "/register",
  // a) Validation middleware
  [
    body("email").isEmail().withMessage("Must be a valid email"),
    body("password")
      .isLength({ min: 6 })
      .withMessage("Password must be at least 6 characters"),
  ],
  async (req: Request, res: Response, next: NextFunction) => {
    // b) Check validation result
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    try {
      const { email, password } = req.body;

      // c) Hash the password
      const passwordHash = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);

      // d) Create and store user
      const newUser: User = {
        id: uuidv4(),
        email,
        passwordHash,
        createdAt: new Date().toISOString(),
      };
      users.push(newUser);

      // e) Return success (never return the hash!)
      res.status(201).json({ id: newUser.id, email: newUser.email });
    } catch (err) {
      next(err);
    }
  }
);

// ─── LOGIN ────────────────────────────────────
app.post(
  "/login",
  [
    body("email").isEmail().withMessage("Must be a valid email"),
    body("password").notEmpty().withMessage("Password is required"),
  ],
  async (req: Request, res: Response, next: NextFunction) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    try {
      const { email, password } = req.body;
      const user = users.find((u) => u.email === email);
      if (!user) {
        return res.status(401).json({ error: "Invalid credentials" });
      }

      const isMatch = await bcrypt.compare(password, user.passwordHash);
      if (!isMatch) {
        return res.status(401).json({ error: "Invalid credentials" });
      }

      // Sign a JWT and return it
      const token = jwt.sign(
        { userId: user.id, email: user.email },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRES_IN }
      );
      res.json({ token });
    } catch (err) {
      next(err);
    }
  }
);

// ─── LOGOUT ───────────────────────────────────
app.post("/logout", (req: Request, res: Response) => {
  const auth = req.headers.authorization;
  if (auth && auth.startsWith("Bearer ")) {
    const token = auth.split(" ")[1];
    tokenBlacklist.push(token);
  }
  res.json({ message: "Logged out" });
});

// 1️⃣ Auth middleware
function authenticateJWT(req: Request, res: Response, next: NextFunction) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Missing token" });
  }

  const token = auth.split(" ")[1];

  // 1a) Check blacklist
  if (tokenBlacklist.includes(token)) {
    return res.status(401).json({ error: "Token has been logged out" });
  }

  try {
    // 1b) Verify & decode
    const payload = jwt.verify(token, JWT_SECRET) as JwtPayload & {
      userId: string;
      email: string;
    };
    // 1c) Attach user info to req
    req.user = {
      userId: payload.userId,
      email: payload.email,
      iat: payload.iat!,
      exp: payload.exp!,
    };
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

// 2️⃣ Protected route example
app.get("/protected", authenticateJWT, (req: Request, res: Response) => {
  // req.user is now available
  res.json({
    message: "You accessed a protected endpoint!",
    user: req.user,
  });
});

// Global error handler (if you haven’t already)
app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
  console.error(err);
  res.status(500).json({ error: err.message || "Server error" });
});

//starts server on the port
app.listen(PORT, () => {
  console.log(`🚀 Server listening on http://localhost:${PORT}`);
});
