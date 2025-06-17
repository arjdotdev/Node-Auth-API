# 🛡️ Authentication and API Notes (Node.js + Express)

---

## 🔄 `_req` vs `req`

- `_req`: Underscore prefix means the parameter is unused.
- `req`: Actively used in the function body (accesses data like body, params, headers).

---

## 📨 `res.send` vs `res.json`

- `res.send`: Sends a response body as a string, buffer, or object.
- `res.json`: Sends a JSON response. Automatically stringifies the object and sets Content-Type.

---

## 📦 Installed Packages

```bash
npm install express-validator bcrypt jsonwebtoken uuid
npm install --save-dev @types/bcrypt @types/jsonwebtoken @types/uuid
```

---

## 📚 Package Purpose

### ✅ express-validator

- Provides middleware to validate/sanitize user input (e.g., form data, request bodies).
- Examples:
  - Check if an email is valid
  - Check if a password is long enough

### ✅ bcrypt

- Hashes passwords securely
- Stores hashed passwords so even if the DB is breached, actual passwords aren’t exposed

### ✅ JSONWEBTOKEN (JWT)

- Creates and verifies JWT tokens
- Used for authentication — sends signed tokens to users to prove identity

### ✅ UUID

- Generates unique identifiers (UUIDs)
- Useful for users, posts, files, etc.

---

## ⚙️ Express Middleware Setup

```ts
app.use(express.json());
```

- Parses any request with `Content-Type: application/json`
- Populates `req.body` with the parsed object

---

## 📝 `/register` Route Example

```ts
app.post(
  "/register",
  [
    body("email").isEmail().withMessage("Must be a valid email"),
    body("password")
      .isLength({ min: 6 })
      .withMessage("Password must be at least 6 characters"),
  ],
  async (req, res, next) => {
    // …
  }
);
```

### 1. Validation Middleware Array

- `body("email").isEmail()` → checks `req.body.email` is valid email format
- `body("password").isLength({ min: 6 })` → ensures password is ≥ 6 chars
- On failure, a custom message is recorded

---

### 2. Handler Logic

```ts
async (req: Request, res: Response, next: NextFunction) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { email, password } = req.body;

    const passwordHash = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);

    const newUser: User = {
      id: uuidv4(),
      email,
      passwordHash,
      createdAt: new Date().toISOString(),
    };
    users.push(newUser);

    res.status(201).json({ id: newUser.id, email: newUser.email });
  } catch (err) {
    next(err);
  }
};
```

- `validationResult(req)`: Collects validation errors
- `bcrypt.hash`: Salts and hashes password securely
- Returns `201` with `id` and `email` (never send hashed password!)

---

## 🧯 Global Error Handler

```ts
app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: err.message || "Server error" });
});
```

- Catches all exceptions from async route handlers
- Logs full error to console
- Returns a safe 500 JSON error message

---

## 🔐 Auth Middleware + Protected Route

```ts
function authenticateJWT(req: Request, res: Response, next: NextFunction) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Missing token" });
  }

  const token = auth.split(" ")[1];

  if (tokenBlacklist.includes(token)) {
    return res.status(401).json({ error: "Token has been logged out" });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET) as JwtPayload & {
      userId: string;
      email: string;
    };

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
```

### Protected Route

```ts
app.get("/protected", authenticateJWT, (req: Request, res: Response) => {
  res.json({
    message: "You accessed a protected endpoint!",
    user: req.user,
  });
});
```

---

## 🔍 How `authenticateJWT` Works

- Checks for `Authorization: Bearer <token>` header
- Rejects missing or malformed token with `401 Unauthorized`
- Checks token against `tokenBlacklist`
- If token is valid:
  - Verifies using `jwt.verify()`
  - Attaches `req.user = { userId, email, iat, exp }`
  - Calls `next()`
- If invalid or expired: returns 401

---

## 🔁 How It All Connects

### `/register`

Registers new user  
**Test:** POST request with `email` and `password` → returns `id` and `email` as JSON

### `/login`

Logs user in  
**Test:** POST request with user `email` and `password`

### `/logout`

Logs user out  
**Test:** POST request with header `Authorization: Bearer <Token>`

### `authenticateJWT`

Middleware to protect routes

### `/protected`

Accessible **only if user is authenticated**  
**Test:** GET request with header `Authorization: Bearer <Token>`

---

## 🧪 Sample Token

```

```
