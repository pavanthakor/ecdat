const crypto = require("crypto");

function legacyDigest(data) {
  return crypto.createHash("sha1").update(data).digest("hex");
}

module.exports = { legacyDigest };
