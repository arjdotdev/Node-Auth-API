\_req vs req

res.send vs res.json

npm install express-validator bcrypt jsonwebtoken uuid
npm install --save-dev @types/bcrypt @types/jsonwebtoken @types/uuid

express-validator: Provides middleware that Validates and sanitizes user input (like form data or API request bodies).
e.g., checking if an email is valid or if a password is long enough

bcrypt: hashes passwords securely
Stores hashed versions of passwords so even if a database is breached, the actual passwords aren’t exposed.

JSONWEBTOKEN aka JWT
creates and verifies JsonWebToken
Handles authentication by sending signed tokens to users, which they use to prove their identity on future requests.

UUID
Generates unique identifiers (UUIDs).
Useful for creating unique IDs for users, posts, files, etc.

app.use(express.json())
Parses any incoming request with a JSON Content-Type header
Populates req.body with the parsed object

/register Route
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

1. Validation middleware array
   body("email").isEmail() checks req.body.email is a valid email format.

body("password").isLength({ min: 6 }) ensures req.body.password is ≥6 chars.

If any check fails, an error gets recorded with your custom message.

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

validationResult(req)
Immediately after validation, you call this to collect any errors.

If non-empty, you return a 400 Bad Request with an errors array detailing which checks failed.

const passwordHash = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);
bcrypt.hash salts and hashes the plain password asynchronously.

app.use((err, \_req, res, \_next) => {
console.error(err);
res.status(500).json({ error: err.message || "Server error" });
});
Catches any exceptions thrown in your async route handlers.

Logs the full error to your console.

Sends back a JSON 500 with a safe error message

Auth Middleware + A Sample Protected Route

import { JwtPayload } from "jsonwebtoken";

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
const payload = jwt.verify(token, JWT_SECRET) as JwtPayload & { userId: string; email: string };
// 1c) Attach user info to req
req.user = { userId: payload.userId, email: payload.email, iat: payload.iat!, exp: payload.exp! };
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
user: req.user
});
});

"authenticateJWT" Middleware
This function runs before any "protected route"

const auth = req.headers.authorization;
if (!auth?.startsWith("Bearer ")) {
return res.status(401).json({ error: "Missing token" });
}
Ensures a header like Authorization: Bearer <token> is present.
If not, immediately returns 401 Unauthorized.

const token = auth.split(" ")[1]; //extract raw token

if (tokenBlacklist.includes(token)) {
return res.status(401).json({ error: "Token has been logged out" });
}
Any token pushed into tokenBlacklist (via your /logout route) is now considered invalid.

const payload = jwt.verify(token, JWT_SECRET)
as JwtPayload & { userId: string; email: string };
jwt.verify checks the signature and expiration against JWT_SECRET
If valid, it returns the decoded payload, which we cast to include our custom claims.

req.user = {
userId: payload.userId,
email: payload.email,
iat: payload.iat!,
exp: payload.exp!
};
next();
Now downstream handlers can read req.user to know who’s calling.

If verify throws (bad signature or expired), we catch it and return 401.

app.get("/protected", authenticateJWT, (req, res) => {
res.json({
message: "You accessed a protected endpoint!",
user: req.user
});
});
authenticateJWT runs first.
If it calls next(), we know the token was valid and not blacklisted.
Inside the handler, req.user holds { userId, email, iat, exp }.

How does this work?
/register route => registers new user

/login route => helps user login

/logout route => helps user logout

authenticateJWT function => helps authenticate user for protected routes

/protected route => allows user in only the user is authenticated
