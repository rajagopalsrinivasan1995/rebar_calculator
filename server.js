const crypto = require("node:crypto");
const path = require("node:path");
const express = require("express");
const { Pool } = require("pg");
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
const publicDirectory = path.join(__dirname, "public");
if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL must be set to the Supabase PostgreSQL connection string.");
}
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
pool.on("error", (error) => {
  console.error("Unexpected PostgreSQL pool error:", error);
});

const statements = {
  findUserByName: "SELECT * FROM users WHERE lower(username) = lower($1)",
  findUserById: "SELECT * FROM users WHERE id = $1",
  userCount: "SELECT COUNT(*) AS count FROM users",
  activeAdminCount: `
    SELECT COUNT(*) AS count FROM users WHERE is_admin = true AND active = true
  `,
};
let bootstrapToken = null;

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

async function createSession(request, response, userId) {
  const existingToken = getCookie(request, sessionCookie);
  if (existingToken && existingToken.length <= 128) {
    await pool.query("DELETE FROM sessions WHERE token_hash = $1", [hashToken(existingToken)]);
  }
  const token = crypto.randomBytes(32).toString("base64url");
  const expiresAt = new Date(Date.now() + sessionLifetimeMs);
  await pool.query(
    "INSERT INTO sessions (token_hash, user_id, expires_at) VALUES ($1, $2, $3)",
    [hashToken(token), userId, expiresAt],
  );

  response.cookie(sessionCookie, token, {
    httpOnly: true,
    sameSite: "strict",
    secure: secureCookies,
    maxAge: sessionLifetimeMs,
    path: "/",
  });
}

async function resolveSession(request) {
  const token = getCookie(request, sessionCookie);
  if (!token || token.length > 128) return null;

  const tokenHash = hashToken(token);
  const result = await pool.query(`
    SELECT users.*, sessions.expires_at
    FROM sessions
    JOIN users ON users.id = sessions.user_id
    WHERE sessions.token_hash = $1
  `, [tokenHash]);
  const session = result.rows[0];

  if (!session) return null;
  if (session.expires_at.getTime() <= Date.now() || !session.active) {
    await pool.query("DELETE FROM sessions WHERE token_hash = $1", [tokenHash]);
    return null;
  }
  return { tokenHash, user: session };
}

const requireAuth = asyncRoute(async (request, response, next) => {
  const session = await resolveSession(request);
  if (!session) {
    clearCookie(response);
    response.status(401).json({ error: "Sign in to continue." });
    return;
  }
  request.portalUser = session.user;
  request.sessionTokenHash = session.tokenHash;
  next();
});

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

async function recordLogin(userId, username, succeeded) {
  await pool.query(`
    INSERT INTO login_events (user_id, username, succeeded, occurred_at)
    VALUES ($1, $2, $3, $4)
  `, [
    userId || null,
    username,
    succeeded,
    new Date(),
  ]);
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

app.get("/api/session", asyncRoute(async (request, response) => {
  const session = await resolveSession(request);
  if (session) {
    response.json({ setupRequired: false, user: publicUser(session.user) });
    return;
  }
  const userCount = await pool.query(statements.userCount);
  response.json({
    setupRequired: Number(userCount.rows[0].count) === 0,
    user: null,
  });
}));

app.post("/api/setup", requireSameOrigin, asyncRoute(async (request, response) => {
  const userCount = await pool.query(statements.userCount);
  if (!bootstrapToken || Number(userCount.rows[0].count) !== 0) {
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
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT pg_advisory_xact_lock(861734921)");
    const count = await client.query(statements.userCount);
    if (Number(count.rows[0].count) !== 0) {
      await client.query("ROLLBACK");
      response.status(403).json({ error: "First-time setup is no longer available." });
      return;
    }
    const result = await client.query(`
      INSERT INTO users (username, password_hash, is_admin, active, created_at)
      VALUES ($1, $2, true, true, $3)
      RETURNING *
    `, [username, passwordHash, new Date()]);
    user = result.rows[0];
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    if (error.code === "23505") {
      response.status(409).json({ error: "That username is already in use." });
      return;
    }
    throw error;
  } finally {
    client.release();
  }

  bootstrapToken = null;
  await recordLogin(user.id, user.username, true);
  await createSession(request, response, user.id);
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
  const accountResult = normalizedUsername
    ? await pool.query(statements.findUserByName, [normalizedUsername])
    : null;
  const account = accountResult && accountResult.rows[0];
  const passwordHash = account ? account.password_hash : dummyPasswordHash;
  const passwordMatches = typeof password === "string"
    && await verifyPassword(password, passwordHash);

  if (!account || !account.active || !passwordMatches) {
    await recordLogin(account && account.active ? account.id : null, normalizedUsername || "(empty)", false);
    recordFailedAttempt(ipAddress);
    response.status(401).json({ error: "Username or password is incorrect." });
    return;
  }

  clearFailedAttempts(ipAddress);
  await recordLogin(account.id, account.username, true);
  await createSession(request, response, account.id);
  response.json({ user: publicUser(account) });
}));

app.post("/api/logout", requireSameOrigin, asyncRoute(async (request, response) => {
  const token = getCookie(request, sessionCookie);
  if (token && token.length <= 128) {
    await pool.query("DELETE FROM sessions WHERE token_hash = $1", [hashToken(token)]);
  }
  clearCookie(response);
  response.status(204).end();
}));

app.get("/api/admin/users", requireAuth, requireAdmin, asyncRoute(async (request, response) => {
  const result = await pool.query(`
    SELECT id, username, is_admin, active, created_at
    FROM users
    ORDER BY lower(username)
  `);
  const users = result.rows.map((user) => ({
    id: user.id,
    username: user.username,
    isAdmin: user.is_admin,
    active: user.active,
    createdAt: user.created_at,
  }));
  response.json({ users });
}));

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
    const result = await pool.query(`
      INSERT INTO users (username, password_hash, is_admin, active, created_at)
      VALUES ($1, $2, $3, true, $4)
      RETURNING *
    `, [username, passwordHash, isAdmin, new Date()]);
    const user = result.rows[0];
    response.status(201).json({ user: publicUser(user) });
  } catch (error) {
    if (error.code === "23505") {
      response.status(409).json({ error: "That username is already in use." });
      return;
    }
    throw error;
  }
}));

app.patch("/api/admin/users/:id/active", requireSameOrigin, requireAuth, requireAdmin, asyncRoute(async (request, response) => {
  const userId = Number(request.params.id);
  const { active } = request.body || {};
  if (!Number.isSafeInteger(userId) || typeof active !== "boolean") {
    response.status(400).json({ error: "A valid account and active status are required." });
    return;
  }

  const targetResult = await pool.query(statements.findUserById, [userId]);
  const target = targetResult.rows[0];
  if (!target) {
    response.status(404).json({ error: "Account not found." });
    return;
  }
  if (target.id === request.portalUser.id) {
    response.status(400).json({ error: "You cannot deactivate your own account." });
    return;
  }
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT pg_advisory_xact_lock(861734921)");
    if (!active && target.is_admin) {
      const adminCount = await client.query(statements.activeAdminCount);
      if (Number(adminCount.rows[0].count) <= 1) {
        await client.query("ROLLBACK");
        response.status(400).json({ error: "The last active administrator cannot be deactivated." });
        return;
      }
    }
    await client.query("UPDATE users SET active = $1 WHERE id = $2", [active, userId]);
    if (!active) {
      await client.query("DELETE FROM sessions WHERE user_id = $1", [userId]);
    }
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
  response.json({ active });
}));

app.get("/api/admin/login-history", requireAuth, requireAdmin, asyncRoute(async (request, response) => {
  const result = await pool.query(`
    SELECT username, succeeded, occurred_at
    FROM login_events
    ORDER BY id DESC
    LIMIT 200
  `);
  const events = result.rows.map((event) => ({
    username: event.username,
    succeeded: event.succeeded,
    occurredAt: event.occurred_at,
  }));
  response.json({ events });
}));

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

let server;

async function start() {
  await pool.query("DELETE FROM sessions WHERE expires_at <= NOW()");
  const result = await pool.query(statements.userCount);
  if (Number(result.rows[0].count) === 0) {
    bootstrapToken = crypto.randomBytes(32).toString("base64url");
    console.info("First-run admin setup token (enter this in the portal):");
    console.info(bootstrapToken);
  }
  server = app.listen(PORT, "0.0.0.0", () => {
    console.info(`Server running on port ${PORT}`);
    if (!secureCookies) {
      console.warn("Network binding is enabled without secure cookies. Use HTTPS before exposing this server.");
    }
  });
}

start().catch((error) => {
  console.error("Failed to initialize Supabase PostgreSQL:", error);
  pool.end().finally(() => {
    process.exitCode = 1;
  });
});

function shutdown() {
  if (!server) {
    pool.end().catch((error) => {
      console.error("Failed to close PostgreSQL pool:", error);
      process.exitCode = 1;
    });
    return;
  }
  server.close(() => {
    pool.end().then(() => process.exit(0)).catch((error) => {
      console.error("Failed to close PostgreSQL pool:", error);
      process.exitCode = 1;
    });
  });
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
