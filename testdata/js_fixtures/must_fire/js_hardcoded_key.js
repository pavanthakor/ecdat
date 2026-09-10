const crypto = require("crypto");

// A hard-coded key and IV. The sentinels must reach NO Finding.
const staticKey = "JSSECRETSENTINEL0123456789abcdef";
const staticIv = "JSNOTAREALKEY123";

function encrypt(plaintext) {
  const cipher = crypto.createCipheriv("aes-256-cbc", staticKey, staticIv);
  return Buffer.concat([cipher.update(plaintext), cipher.final()]);
}

module.exports = { encrypt };
