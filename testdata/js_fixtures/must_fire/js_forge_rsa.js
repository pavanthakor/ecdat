const forge = require("node-forge");

function newForgeKey() {
  return forge.pki.rsa.generateKeyPair({ bits: 2048 });
}

module.exports = { newForgeKey };
