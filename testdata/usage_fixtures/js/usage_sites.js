// JavaScript call sites whose API names the usage (ADR-0030).
const crypto = require("crypto");
const jwt = require("jsonwebtoken");

function issueToken(claims, key) {
  return jwt.sign(claims, key, { algorithm: "RS256" });
}

function checkToken(token, key) {
  // VERIFIES. Reported as `sign` before ADR-0030.
  return jwt.verify(token, key, { algorithms: ["RS256"] });
}

function wrapSessionKey(publicKey, sessionKey) {
  // RSA as a cipher is key transport.
  return crypto.publicEncrypt(publicKey, sessionKey);
}

function agree(privateKey, peerKey) {
  const ecdh = crypto.createECDH("prime256v1");
  ecdh.setPrivateKey(privateKey);
  return ecdh.computeSecret(peerKey);
}

module.exports = { issueToken, checkToken, wrapSessionKey, agree };
