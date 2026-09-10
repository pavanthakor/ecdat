const jwt = require("jsonwebtoken");

// alg=none disables verification entirely: anyone can mint a token.
function issueUnsigned(claims) {
  return jwt.sign(claims, "", { algorithm: "none" });
}

module.exports = { issueUnsigned };
