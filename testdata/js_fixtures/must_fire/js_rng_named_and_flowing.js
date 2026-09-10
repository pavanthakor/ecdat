// BOTH rules see this one: the variable IS named, AND the value flows.
//
// They agree on algorithm, primitive, usage and params, so they carry ONE
// identity and the normaliser folds them into a single component -- the
// ADR-0026 pattern, re-made for JS. Asserted rather than assumed, which is why
// both can ship instead of one being switched off.
const crypto = require("crypto");

function encrypt(iv, data) {
  const sessionKey = Math.random().toString(36).padEnd(32, "0");
  const cipher = crypto.createCipheriv("aes-256-cbc", sessionKey, iv);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

module.exports = { encrypt };
