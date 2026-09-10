// must_fire: js-hardcoded-key-candidate (ADR-0034) -- a key-ish name holding a
// high-entropy 32- or 64-character hex literal, with no sink anywhere. That is
// not proof of key material -- it may be an API token, a test vector, a digest
// someone misnamed -- so it is reported as a CANDIDATE at low confidence for an
// analyst to confirm, never asserted. The literals are random filler.
const backupEncryptionKey = "e551cb2cae989987974ced702fb08c21";
const webhookSigningSecret = "6949b268dc2426f55af2f8aa1016c20a5dcd1cfb685b5cd5eacabea16e92605b";

module.exports = { backupEncryptionKey, webhookSigningSecret };
