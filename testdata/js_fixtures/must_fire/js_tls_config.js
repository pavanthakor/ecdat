const https = require("https");

function legacyAgent() {
  return new https.Agent({
    minVersion: "TLSv1",
    ciphers: "DES-CBC3-SHA:AES128-SHA",
  });
}

module.exports = { legacyAgent };
