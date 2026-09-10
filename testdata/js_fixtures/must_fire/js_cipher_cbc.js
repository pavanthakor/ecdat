const crypto = require("crypto");

function encryptCbc(key, iv, plaintext) {
  const cipher = crypto.createCipheriv("aes-128-cbc", key, iv);
  return Buffer.concat([cipher.update(plaintext), cipher.final()]);
}

module.exports = { encryptCbc };
