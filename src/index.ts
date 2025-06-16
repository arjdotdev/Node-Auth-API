import express, { Request, Response } from "express";
import { body, validationResult } from "express-validator";
import bcrypt from "bcrypt";
import { v4 as uuidv4 } from "uuid";
import { NextFunction } from "express-serve-static-core";

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

// Global error handler (if you haven’t already)
app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
  console.error(err);
  res.status(500).json({ error: err.message || "Server error" });
});

//starts server on the port
app.listen(PORT, () => {
  console.log(`🚀 Server listening on http://localhost:${PORT}`);
});
