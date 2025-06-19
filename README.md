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

# New Notes

# 🛡️ Authentication Workflow in Express (with JWT, bcrypt, express-validator)

---

## 🔽 Imports

- Import `body`, `validationResult` from `express-validator`
- Import `bcrypt` from `bcrypt`
- Import `v4 as uuidv4` from `uuid`
- Import `jwt` from `jsonwebtoken`
- Import type `NextFunction`
- Import type `JwtPayload`

---

## 📝 Register Route: Saves user info to database

- **POST** request with 3 arguments:  
  `route`, `middleware`, and `handler function`

### ✅ Middleware

- Checks if inputs are valid

### 🔧 Handler

- Async (since bcrypt is async), so use `try-catch` block
- Checks error from middleware — if yes, return response with status and json

### ✅ Try Block

- Get input field values using `req.body`
- Hash password using `await bcrypt`
- Create an object with `id`, `email`, `hashedPW`, `createdAt`
- Store it to DB or file
- Give back response with status and JSON

### ❌ Catch Block

- Catches and handles any error

#### ❓ What does the `next` function do in `catch`?

- Passes error to global error handler middleware for centralized handling

---

## 🔐 Login Route: Verifies credentials → returns JWT token

- **POST** request with 3 arguments: route, middleware, handler

### ✅ Middleware

- Checks if input is valid

### 🔧 Handler

- Async function with `try-catch`

### ✅ Error Check

- If validation errors are present, return `res` with status and json

### ✅ Try Block

- Get `email` and `password` from `req.body`
- Get user object that has the same email

  - **Problem**: Check if email exists in user array
  - If not found, return response with status and json

- Compare request password with stored hash using `bcrypt.compare`

  - If `matched` is false, return status and json

- Else: **sign a JWT** and return it

---

## 🧾 How JWT Sign Works

```ts
jwt.sign(payload, secretOrPrivateKey, [options]);
```

### 🔸 Payload:

- `{ userId, email }`

### 🔸 Secret (`JWT_SECRET`)

- Used to cryptographically sign and verify the token
- Should be kept in `.env`

### 🔸 Options

- `{ expiresIn: "1h" }`
- Sets the token's expiration (e.g., "1h", "30m")

```ts
const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key";
```

### 🔙 Returns

```ts
res.json({ token });
```

- Token should be stored in `localStorage`
- Sent in future requests as:
  ```http
  Authorization: Bearer <token>
  ```

---

## 🔓 Logout Route: Invalidates JWT by saving token to `blacklist`

- **POST** request with `Authorization` header
  - Value is `Bearer <token>` from `localStorage`

### ✅ Logic

- Get value from `req.headers.authorization`
- If it starts with "Bearer", extract token and store it in a `blacklist`
- Send back a response with JSON

---

## 🔐 AuthenticateJWT Middleware: Validates token before protected routes

- Used to protect any route after login

### ✅ Steps

1. Get `auth` from `req.headers.authorization`  
   (value from localStorage or client-side)

2. If `auth` is empty or doesn’t start with "Bearer", return `401 Unauthorized`

3. Extract token:

```ts
const token = auth.split(" ")[1]; // "Bearer <token>" → "<token>"
```

4. If token is in `tokenBlacklist`, return status and json

5. Use `try-catch`

```ts
const payload = jwt.verify(token, JWT_SECRET)
  as JwtPayload & { userId: string; email: string };
```

6. Attach user info to `req.user`:

```ts
req.user = {
  userId: payload.userId,
  email: payload.email,
  iat: payload.iat!,
  exp: payload.exp!,
};
```

7. Call `next()` to proceed

8. If token is invalid or expired, return `401 Unauthorized`

---

## 🧪 Protected Route: Can only be accessed with a valid token

```ts
app.get("/protected", authenticateJWT, (req, res) => {
  res.json({
    message: "You accessed a protected endpoint!",
    user: req.user,
  });
});
```

- `authenticateJWT` runs first
- If `next()` is called, it means token was valid and not blacklisted
- `req.user` now contains `{ userId, email, iat, exp }`

---

## 🔐 JWT Token Structure

A JSON Web Token has **3 parts** separated by dots:

```text
header.payload.signature
```

### 🔹 Header

- Describes the token type and algorithm

### 🔹 Payload

- Contains claims like:
  - `iat` (issued at)
  - `exp` (expiration)
- Does **not include** sensitive data like password

### 🔹 Signature

- HMAC signature of header + payload

---
