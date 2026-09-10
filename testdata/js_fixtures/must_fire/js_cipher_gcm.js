const crypto = require("crypto");

function encryptGcm(key, iv, plaintext) {
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  return Buffer.concat([cipher.update(plaintext), cipher.final()]);
}

module.exports = { encryptGcm };
