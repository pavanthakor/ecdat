const jwt = require("jsonwebtoken");

function issue(claims, key) {
  return jwt.sign(claims, key, { algorithm: "RS256" });
}

module.exports = { issue };
