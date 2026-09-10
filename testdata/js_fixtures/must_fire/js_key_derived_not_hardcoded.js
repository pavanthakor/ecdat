// must_fire: js-createcipheriv ONLY (ADR-0034). A literal reaches each cipher
// here without BEING the key, so the cipher is reported and no hard-coded-key
// finding may be. Both are false positives a plain taint rule produced in
// ADR-0034's STEP 0.
const crypto = require("crypto");

// A KDF's output is not its salt. `taint_assume_safe_functions` stops the salt
// literal flowing through scryptSync into the key.
function keyFromPassword(password, iv) {
  const key = crypto.scryptSync(password, "JSNEARMISSstaticSaltValue", 32);
  return crypto.createCipheriv("aes-256-cbc", key, iv);
}

// A key ASSEMBLED from a constant and a runtime value: the literal is a part,
// not the key. Concatenation is a sanitizer in every hard-coded-key rule.
function tenantCipher(tenantSecret, iv) {
  return crypto.createCipheriv("aes-256-cbc", "JSNEARMISSprefix" + tenantSecret, iv);
}

module.exports = { keyFromPassword, tenantCipher };
