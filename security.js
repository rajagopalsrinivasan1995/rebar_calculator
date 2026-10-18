const {
  randomBytes,
  scrypt,
  timingSafeEqual,
} = require("node:crypto");

const PASSWORD_BYTES = 64;
const SCRYPT_OPTIONS = {
  N: 32768,
  r: 8,
  p: 1,
  maxmem: 128 * 1024 * 1024,
};

function validateUsername(username) {
  return typeof username === "string"
    && username.length >= 3
    && username.length <= 40
    && /^[a-zA-Z0-9_.-]+$/.test(username);
}

function validatePassword(password) {
  return typeof password === "string"
    && password.length >= 4
    && password.length <= 256;
}

function deriveKey(password, salt) {
  return new Promise((resolve, reject) => {
    scrypt(password, salt, PASSWORD_BYTES, SCRYPT_OPTIONS, (error, key) => {
      if (error) {
        reject(error);
        return;
      }
      resolve(key);
    });
  });
}

async function hashPassword(password) {
  const salt = randomBytes(16);
  const key = await deriveKey(password, salt);
  return `${salt.toString("base64url")}.${key.toString("base64url")}`;
}

async function verifyPassword(password, encoded) {
  if (typeof encoded !== "string") {
    return false;
  }

  const [saltText, keyText, extra] = encoded.split(".");
  if (!saltText || !keyText || extra !== undefined) {
    return false;
  }

  let salt;
  let expected;
  try {
    salt = Buffer.from(saltText, "base64url");
    expected = Buffer.from(keyText, "base64url");
  } catch {
    return false;
  }

  if (salt.length !== 16 || expected.length !== PASSWORD_BYTES) {
    return false;
  }

  const actual = await deriveKey(password, salt);
  return timingSafeEqual(actual, expected);
}

module.exports = {
  hashPassword,
  validatePassword,
  validateUsername,
  verifyPassword,
};
