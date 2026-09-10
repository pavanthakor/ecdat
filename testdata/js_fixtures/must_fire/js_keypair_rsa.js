const crypto = require("crypto");

function newTransportKey(cb) {
  crypto.generateKeyPair("rsa", { modulusLength: 2048 }, cb);
}

module.exports = { newTransportKey };
