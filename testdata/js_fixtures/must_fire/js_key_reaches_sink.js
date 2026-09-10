// must_fire: js-hardcoded-key (ADR-0034) -- a literal that REACHES a key
// parameter is key material, whatever its variable is called. Three shapes of
// the same fact. The sentinels must reach no Finding.
const crypto = require("crypto");
const jwt = require("jsonwebtoken");

// High-entropy, key-ish AND reaching a sink. js-hardcoded-key-candidate
// matches this declaration too; the scanner folds that candidate into the
// sink finding (same holder, same file), so this key is reported ONCE, at
// high confidence -- never as a confirmed finding plus a candidate.
const webhookKey = "e624c0021fe5c93132c217102105033b";

function macOf(data) {
  return crypto.createHmac("sha256", webhookKey).update(data).digest("hex");
}

// Inline at the sink: no variable holds it.
function issueToken(claims) {
  return jwt.sign(claims, "JSSINKSENTINELinlineJwtSigningKey");
}

// Through an encoding wrapper assigned to a second variable.
function encryptRecord(iv, record) {
  const rawKey = "JSSINKSENTINELwrappedAes256Key01";
  const keyBytes = Buffer.from(rawKey, "utf8");
  const cipher = crypto.createCipheriv("aes-256-cbc", keyBytes, iv);
  return Buffer.concat([cipher.update(record), cipher.final()]);
}

module.exports = { macOf, issueToken, encryptRecord };
