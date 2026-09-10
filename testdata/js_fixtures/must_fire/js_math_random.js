// Math.random() is not a CSPRNG. Using it for a token is a key-recovery bug.
function newSessionToken() {
  const token = Math.random().toString(36).slice(2);
  return token;
}

module.exports = { newSessionToken };
