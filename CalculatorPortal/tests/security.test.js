const test = require("node:test");
const assert = require("node:assert/strict");
const {
  hashPassword,
  validatePassword,
  validateUsername,
  verifyPassword,
} = require("../security");

test("accepts usernames with the supported length and characters", () => {
  assert.equal(validateUsername("rajagopal"), true);
  assert.equal(validateUsername("user.name-1"), true);
  assert.equal(validateUsername("ab"), false);
  assert.equal(validateUsername("user name"), false);
});

test("requires a password with at least 4 characters", () => {
  assert.equal(validatePassword("long-password"), true);
  assert.equal(validatePassword("short"), false);
  assert.equal(validatePassword("x".repeat(257)), false);
});

test("stores password hashes and verifies only the matching password", async () => {
  const password = "a-private-test-password";
  const firstHash = await hashPassword(password);
  const secondHash = await hashPassword(password);

  assert.notEqual(firstHash, secondHash);
  assert.equal(await verifyPassword(password, firstHash), true);
  assert.equal(await verifyPassword("another-password", firstHash), false);
  assert.equal(await verifyPassword(password, "invalid-hash"), false);
});
