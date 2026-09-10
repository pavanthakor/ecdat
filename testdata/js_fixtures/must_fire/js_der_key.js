// must_fire: js-hardcoded-key-der (ADR-0034) -- a base64 DER structure is key
// material by its SHAPE alone. `MII` is a DER SEQUENCE with a two-byte length
// (X.690 s8.1.3), the header of every RSA key and every X.509 certificate
// (RFC 8017, RFC 5280). The body is filler; the sentinel must reach no Finding.
const crypto = require("crypto");

const partnerKeyDer =
  "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAJSDERSENTINELnotARealKeyJustFillerForTheShapeOnly0123456789";

// It reaches a key parameter too. The DER rule owns a shaped literal, so this
// is still ONE finding -- not a DER finding plus a sink finding.
function partnerSecret() {
  return crypto.createSecretKey(Buffer.from(partnerKeyDer, "base64"));
}

module.exports = { partnerSecret };
