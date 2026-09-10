const CryptoJS = require("crypto-js");

function legacyId(value) {
  return CryptoJS.MD5(value).toString();
}

module.exports = { legacyId };
