// THE AUTH-BYPASS CLOSE (ADR-0028). `alg` is a variable, so the four
// `js-jwt-*` rules' metavariable-regex saw the source text `alg` and every one
// of these was invisible -- including `none`, which RFC 8725 s3.1 requires to
// be rejected outright. A service that selects its signing algorithm from
// config was reported as having no JWT signing at all.
const jwt = require("jsonwebtoken");

const CONFIGURED_ALG = "RS256";

function issueUnsigned(claims) {
  const alg = "none";
  return jwt.sign(claims, "", { algorithm: alg });
}

function issueRsa(claims, key) {
  return jwt.sign(claims, key, { algorithm: CONFIGURED_ALG });
}

function issueEcdsa(claims, key) {
  const alg = "ES256";
  return jwt.sign(claims, key, { algorithm: alg });
}

function issueHmac(claims, secret) {
  const alg = "HS256";
  return jwt.sign(claims, secret, { algorithm: alg });
}

module.exports = { issueUnsigned, issueRsa, issueEcdsa, issueHmac };
