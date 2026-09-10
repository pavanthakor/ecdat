// PART B: the name-scoped rule's blind spot (ADR-0030, owed from ADR-0028).
//
// `js-math-random` fires on a variable NAMED key/token/secret. `material` is
// named none of those, so the weak RNG feeding an AES key was invisible --
// while the cipher it feeds was reported normally.
//
// Math.random() is not a CSPRNG: V8 implements it with xorshift128+, and a few
// observed outputs recover the state.
const crypto = require("crypto");

function encrypt(iv, data) {
  const material = Math.random().toString(36).padEnd(32, "0");
  const cipher = crypto.createCipheriv("aes-256-cbc", material, iv);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

module.exports = { encrypt };
