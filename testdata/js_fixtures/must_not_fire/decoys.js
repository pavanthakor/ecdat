// JavaScript that MUST NOT produce a single Finding.
//
// Every entry is a plausible false positive: prose naming an algorithm, an
// identifier that reads like a digest, a name-scoped RNG rule's non-key use,
// and a non-crypto import whose name looks cryptographic.

// A package whose name looks cryptographic but is a string helper.
const slugify = require("crypto-random-words-that-do-not-exist-shim");

// MD5 and RC4 are named in this comment, and crypto.createHash('md5') appears
// here too. A comment is documentation, not a call site.
const documentation = "we migrated off MD5 and RC4 in 2019";

// Identifiers that read like crypto but hold nothing secret.
const md5Column = "legacy_md5_column";
const cipherName = "display-name";
const sha1Migration = "completed";

// A name-scoped RNG rule must NOT fire here: jitter is not a key, token,
// secret or nonce.
function backoffJitter(attempt) {
  const jitter = Math.random() * 100;
  return attempt * 1000 + jitter;
}

// Shuffling a display list is not key generation either.
function shuffleForDisplay(items) {
  return items.sort(() => Math.random() - 0.5);
}

module.exports = {
  slugify,
  documentation,
  md5Column,
  cipherName,
  sha1Migration,
  backoffJitter,
  shuffleForDisplay,
};
