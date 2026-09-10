const crypto = require("crypto");

function fingerprint(data) {
  return crypto.createHash("md5").update(data).digest("hex");
}

module.exports = { fingerprint };
