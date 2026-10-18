const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const Database = require("better-sqlite3");
const express = require("express");
const {
  hashPassword,
  validatePassword,
  validateUsername,
  verifyPassword,
} = require("./security");

const app = express();
const PORT = Number(process.env.PORT || 10000);
const sessionCookie = "calculator_portal_session";
const sessionLifetimeMs = 8 * 60 * 60 * 1000;
const secureCookies = process.env.COOKIE_SECURE === "true"
  || process.env.NODE_ENV === "production";
const trustProxy = process.env.TRUST_PROXY === "1" || process.env.RENDER === "true"
  ? 1
  : false;
const dataDirectory = path.join(__dirname, "App_Data");
const publicDirectory = path.join(__dirname, "public");
const databasePath = process.env.DATABASE_PATH
  ? path.resolve(process.env.DATABASE_PATH)
  : path.join(dataDirectory, "portal.sqlite");

fs.mkdirSync(path.dirname(databasePath), { recursive: true });
const database = new Database(databasePath);
database.pragma("journal_mode = WAL");
database.pragma("foreign_keys = ON");
database.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL COLLATE NOCASE UNIQUE,
    password_hash TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0,
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS login_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    username TEXT NOT NULL,
    succeeded INTEGER NOT NULL,
    occurred_at TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);
  CREATE INDEX IF NOT EXISTS login_events_time ON login_events(id DESC);
`);
database.prepare("DELETE FROM sessions WHERE expires_at <= ?").run(Date.now());

const statements = {
  findUserByName: database.prepare("SELECT * FROM users WHERE username = ?"),
  findUserById: database.prepare("SELECT * FROM users WHERE id = ?"),
  userCount: database.prepare("SELECT COUNT(*) AS count FROM users"),
  activeAdminCount: database.prepare(
    "SELECT COUNT(*) AS count FROM users WHERE is_admin = 1 AND active = 1",
  ),
  addLoginEvent: database.prepare(`
    INSERT INTO login_events (user_id, username, succeeded, occurred_at)
    VALUES (?, ?, ?, ?)
  `),
};

let bootstrapToken = statements.userCount.get().count === 0
  ? crypto.randomBytes(32).toString("base64url")
  : null;

if (bootstrapToken) {
  console.info("First-run admin setup token (enter this in the portal):");
  console.info(bootstrapToken);
}

const loginAttempts = new Map();
const dummySalt = crypto.randomBytes(16);
const dummyHash = crypto.scryptSync(
  "not-a-real-account-password",
  dummySalt,
  64,
  { N: 32768, r: 8, p: 1, maxmem: 128 * 1024 * 1024 },
);
const dummyPasswordHash = `${dummySalt.toString("base64url")}.${dummyHash.toString("base64url")}`;

app.disable("x-powered-by");
app.set("trust proxy", trustProxy);
app.use(express.json({ limit: "16kb" }));
app.use((request, response, next) => {
  response.set({
    "Cache-Control": "no-store",
    "Content-Security-Policy": [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com",
      "style-src 'self' 'unsafe-inline'",
      "worker-src 'self' blob: https://cdnjs.cloudflare.com",
      "frame-src 'self'",
      "frame-ancestors 'self'",
      "object-src 'none'",
      "base-uri 'self'",
      "form-action 'self'",
    ].join("; "),
    "Referrer-Policy": "same-origin",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "SAMEORIGIN",
  });
  next();
});

function getCookie(request, name) {
  const cookieHeader = request.headers.cookie || "";
  for (const item of cookieHeader.split(";")) {
    const separator = item.indexOf("=");
    if (separator < 0) continue;
    if (item.slice(0, separator).trim() === name) {
      try {
        return decodeURIComponent(item.slice(separator + 1).trim());
      } catch {
        return null;
      }
    }
  }
  return null;
}

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function publicUser(user) {
  return {
    id: user.id,
    username: user.username,
    isAdmin: Boolean(user.is_admin),
  };
}

function clearCookie(response) {
  response.clearCookie(sessionCookie, {
    httpOnly: true,
    sameSite: "strict",
    secure: secureCookies,
    path: "/",
  });
}

function createSession(request, response, userId) {
  const existingToken = getCookie(request, sessionCookie);
  if (existingToken && existingToken.length <= 128) {
    database.prepare("DELETE FROM sessions WHERE token_hash = ?").run(hashToken(existingToken));
  }
  const token = crypto.randomBytes(32).toString("base64url");
  const expiresAt = Date.now() + sessionLifetimeMs;
  database.prepare(
    "INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
  ).run(hashToken(token), userId, expiresAt);

  response.cookie(sessionCookie, token, {
    httpOnly: true,
    sameSite: "strict",
    secure: secureCookies,
    maxAge: sessionLifetimeMs,
    path: "/",
  });
}

function resolveSession(request) {
  const token = getCookie(request, sessionCookie);
  if (!token || token.length > 128) return null;

  const tokenHash = hashToken(token);
  const session = database.prepare(`
    SELECT users.*, sessions.expires_at
    FROM sessions
    JOIN users ON users.id = sessions.user_id
    WHERE sessions.token_hash = ?
  `).get(tokenHash);

  if (!session) return null;
  if (session.expires_at <= Date.now() || !session.active) {
    database.prepare("DELETE FROM sessions WHERE token_hash = ?").run(tokenHash);
    return null;
  }
  return { tokenHash, user: session };
}

function requireAuth(request, response, next) {
  const session = resolveSession(request);
  if (!session) {
    clearCookie(response);
    response.status(401).json({ error: "Sign in to continue." });
    return;
  }
  request.portalUser = session.user;
  request.sessionTokenHash = session.tokenHash;
  next();
}

function requireAdmin(request, response, next) {
  if (!request.portalUser || !request.portalUser.is_admin) {
    response.status(403).json({ error: "Administrator access is required." });
    return;
  }
  next();
}

function requireSameOrigin(request, response, next) {
  const origin = request.get("origin");
  const expectedOrigin = `${request.protocol}://${request.get("host")}`;
  if (origin !== expectedOrigin) {
    response.status(403).json({ error: "Request origin was not allowed." });
    return;
  }
  next();
}

function recordLogin(userId, username, succeeded) {
  statements.addLoginEvent.run(
    userId || null,
    username,
    succeeded ? 1 : 0,
    new Date().toISOString(),
  );
}

function loginIsBlocked(ipAddress) {
  const attempt = loginAttempts.get(ipAddress);
  if (!attempt) return false;
  if (Date.now() - attempt.startedAt >= 15 * 60 * 1000) {
    loginAttempts.delete(ipAddress);
    return false;
  }
  return attempt.count >= 10;
}

function recordFailedAttempt(ipAddress) {
  const current = loginAttempts.get(ipAddress);
  if (!current || Date.now() - current.startedAt >= 15 * 60 * 1000) {
    loginAttempts.set(ipAddress, { startedAt: Date.now(), count: 1 });
  } else {
    current.count += 1;
  }
}

function clearFailedAttempts(ipAddress) {
  loginAttempts.delete(ipAddress);
}

function asyncRoute(handler) {
  return (request, response, next) => {
    Promise.resolve(handler(request, response, next)).catch(next);
  };
}

app.get("/", (request, response) => {
  response.sendFile(path.join(publicDirectory, "index.html"));
});

app.get("/healthz", (request, response) => {
  response.status(200).json({ status: "ok" });
});

app.get("/calculators/standee", requireAuth, (request, response) => {
  response.sendFile(path.join(publicDirectory, "calculators", "standee.html"));
});

app.get("/calculators/additional-bars", requireAuth, (request, response) => {
  response.sendFile(path.join(publicDirectory, "calculators", "additional-bars.html"));
});

app.get("/api/session", (request, response) => {
  const session = resolveSession(request);
  if (session) {
    response.json({ setupRequired: false, user: publicUser(session.user) });
    return;
  }
  response.json({
    setupRequired: statements.userCount.get().count === 0,
    user: null,
  });
});

app.post("/api/setup", requireSameOrigin, asyncRoute(async (request, response) => {
  if (!bootstrapToken || statements.userCount.get().count !== 0) {
    response.status(403).json({ error: "First-time setup is no longer available." });
    return;
  }

  const { token, username, password } = request.body || {};
  if (typeof token !== "string" || token.length > 128
    || Buffer.byteLength(token) !== Buffer.byteLength(bootstrapToken)
    || !crypto.timingSafeEqual(Buffer.from(token), Buffer.from(bootstrapToken))) {
    response.status(403).json({ error: "The setup token is invalid." });
    return;
  }
  if (!validateUsername(username) || !validatePassword(password)) {
    response.status(400).json({
      error: "Use a 3–40 character username and a password of at least 4 characters.",
    });
    return;
  }

  const passwordHash = await hashPassword(password);
  let user;
  try {
    const createAdmin = database.transaction(() => {
      if (statements.userCount.get().count !== 0) {
        throw new Error("setup-already-complete");
      }
      const result = database.prepare(`
        INSERT INTO users (username, password_hash, is_admin, active, created_at)
        VALUES (?, ?, 1, 1, ?)
      `).run(username, passwordHash, new Date().toISOString());
      return statements.findUserById.get(result.lastInsertRowid);
    });
    user = createAdmin();
  } catch (error) {
    if (error.message === "setup-already-complete") {
      response.status(403).json({ error: "First-time setup is no longer available." });
      return;
    }
    if (error.code === "SQLITE_CONSTRAINT_UNIQUE") {
      response.status(409).json({ error: "That username is already in use." });
      return;
    }
    throw error;
  }

  bootstrapToken = null;
  recordLogin(user.id, user.username, true);
  createSession(request, response, user.id);
  response.status(201).json({ user: publicUser(user) });
}));

app.post("/api/login", requireSameOrigin, asyncRoute(async (request, response) => {
  const ipAddress = request.ip;
  if (loginIsBlocked(ipAddress)) {
    response.status(429).json({ error: "Too many attempts. Try again in 15 minutes." });
    return;
  }

  const { username, password } = request.body || {};
  const normalizedUsername = typeof username === "string"
    ? username.trim().slice(0, 40)
    : "";
  const account = normalizedUsername
    ? statements.findUserByName.get(normalizedUsername)
    : null;
  const passwordHash = account ? account.password_hash : dummyPasswordHash;
  const passwordMatches = typeof password === "string"
    && await verifyPassword(password, passwordHash);

  if (!account || !account.active || !passwordMatches) {
    recordLogin(account && account.active ? account.id : null, normalizedUsername || "(empty)", false);
    recordFailedAttempt(ipAddress);
    response.status(401).json({ error: "Username or password is incorrect." });
    return;
  }

  clearFailedAttempts(ipAddress);
  recordLogin(account.id, account.username, true);
  createSession(request, response, account.id);
  response.json({ user: publicUser(account) });
}));

app.post("/api/logout", requireSameOrigin, (request, response) => {
  const token = getCookie(request, sessionCookie);
  if (token && token.length <= 128) {
    database.prepare("DELETE FROM sessions WHERE token_hash = ?").run(hashToken(token));
  }
  clearCookie(response);
  response.status(204).end();
});

app.get("/api/admin/users", requireAuth, requireAdmin, (request, response) => {
  const users = database.prepare(`
    SELECT id, username, is_admin, active, created_at
    FROM users
    ORDER BY username COLLATE NOCASE
  `).all().map((user) => ({
    id: user.id,
    username: user.username,
    isAdmin: Boolean(user.is_admin),
    active: Boolean(user.active),
    createdAt: user.created_at,
  }));
  response.json({ users });
});

app.post("/api/admin/users", requireSameOrigin, requireAuth, requireAdmin, asyncRoute(async (request, response) => {
  const { username, password, isAdmin } = request.body || {};
  if (!validateUsername(username) || !validatePassword(password)
    || typeof isAdmin !== "boolean") {
    response.status(400).json({
      error: "Enter a 3–40 character username, a password of at least 4 characters, and an account role.",
    });
    return;
  }

  const passwordHash = await hashPassword(password);
  try {
    const result = database.prepare(`
      INSERT INTO users (username, password_hash, is_admin, active, created_at)
      VALUES (?, ?, ?, 1, ?)
    `).run(username, passwordHash, isAdmin ? 1 : 0, new Date().toISOString());
    const user = statements.findUserById.get(result.lastInsertRowid);
    response.status(201).json({ user: publicUser(user) });
  } catch (error) {
    if (error.code === "SQLITE_CONSTRAINT_UNIQUE") {
      response.status(409).json({ error: "That username is already in use." });
      return;
    }
    throw error;
  }
}));

app.patch("/api/admin/users/:id/active", requireSameOrigin, requireAuth, requireAdmin, (request, response) => {
  const userId = Number(request.params.id);
  const { active } = request.body || {};
  if (!Number.isSafeInteger(userId) || typeof active !== "boolean") {
    response.status(400).json({ error: "A valid account and active status are required." });
    return;
  }

  const target = statements.findUserById.get(userId);
  if (!target) {
    response.status(404).json({ error: "Account not found." });
    return;
  }
  if (target.id === request.portalUser.id) {
    response.status(400).json({ error: "You cannot deactivate your own account." });
    return;
  }
  if (!active && target.is_admin && statements.activeAdminCount.get().count <= 1) {
    response.status(400).json({ error: "The last active administrator cannot be deactivated." });
    return;
  }

  const update = database.transaction(() => {
    database.prepare("UPDATE users SET active = ? WHERE id = ?").run(active ? 1 : 0, userId);
    if (!active) {
      database.prepare("DELETE FROM sessions WHERE user_id = ?").run(userId);
    }
  });
  update();
  response.json({ active });
});

app.get("/api/admin/login-history", requireAuth, requireAdmin, (request, response) => {
  const events = database.prepare(`
    SELECT username, succeeded, occurred_at
    FROM login_events
    ORDER BY id DESC
    LIMIT 200
  `).all().map((event) => ({
    username: event.username,
    succeeded: Boolean(event.succeeded),
    occurredAt: event.occurred_at,
  }));
  response.json({ events });
});

app.use((request, response) => {
  response.status(404).json({ error: "Not found." });
});

app.use((error, request, response, next) => {
  if (error.status === 400) {
    response.status(400).json({ error: "The request body is invalid." });
    return;
  }
  console.error("Request failed:", error);
  if (response.headersSent) {
    next(error);
    return;
  }
  response.status(500).json({ error: "An unexpected server error occurred." });
});

const server = app.listen(PORT, "0.0.0.0", () => {
  console.info(`Server running on port ${PORT}`);
  if (!secureCookies) {
    console.warn("Network binding is enabled without secure cookies. Use HTTPS before exposing this server.");
  }
});

function shutdown() {
  server.close(() => {
    database.close();
    process.exit(0);
  });
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
