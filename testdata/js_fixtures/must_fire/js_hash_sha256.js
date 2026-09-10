const crypto = require("crypto");

// A control: coverage needs the correct choices inventoried too.
function contentHash(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

module.exports = { contentHash };
