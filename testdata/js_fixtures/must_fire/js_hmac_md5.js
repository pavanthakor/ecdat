const crypto = require("crypto");

function sign(key, data) {
  return crypto.createHmac("md5", key).update(data).digest("hex");
}

module.exports = { sign };
