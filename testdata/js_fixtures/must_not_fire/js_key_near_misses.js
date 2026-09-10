// must_not_fire (ADR-0034): near misses. Each fails exactly ONE of the
// candidate rule's gates -- name, length, entropy -- and must not fire.

// Right name, right length, no entropy: a repeating pattern.
const repeatingKey = "deadbeefdeadbeefdeadbeefdeadbeef";

// Right name, random, but 31 characters: under the 32-character bar.
const shortHexKey = "0740faadefa87633211e940ab35c5c2";

// Random and 64 characters, but nothing in the NAME says key: a digest.
const releaseChecksum = "bdeb974bc737c16b892f8bfb97ae901197858c956f8bf7c33a421d3ad3a14c38";

// An address held in a name that says "token" -- the Juice Shop faucet shape.
// `token` is deliberately not a key-ish word for the candidate rule.
const beeTokenAddress = "0x17dc32dd06e3dad096b26cfefd6eea1a5fb8a08a";

module.exports = { repeatingKey, shortHexKey, releaseChecksum, beeTokenAddress };
