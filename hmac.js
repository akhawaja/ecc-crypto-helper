(function() {
  var crypto, hmac;

  crypto = require("crypto");

  hmac = (digest, text, secret) => {
    return new Promise((resolve, reject) => {
      return resolve(crypto.createHmac(digest, secret).update(text).digest());
    });
  };

  module.exports = {
    /**
     * Compute an HMAC using SHA-256 of a given string.
     *
     * @param {string} text - The text to calculate into a hash.
     * @param {string} secret - The shared secret.
     * @returns {Buffer}
     */
    hmac256: (text, secret) => {
      return Promise.resolve(hmac("sha256", text, secret));
    },
    /**
     * Compute an HMAC using SHA-384 of a given string.
     *
     * @param {string} text - The text to calculate into a hash.
     * @param {string} secret - The shared secret.
     * @returns {Buffer}
     */
    hmac384: (text, secret) => {
      return Promise.resolve(hmac("sha384", text, secret));
    },
    /**
     * Compute an HMAC using SHA-512 of a given string.
     *
     * @param {string} text - The text to calculate into a hash.
     * @param {string} secret - The shared secret.
     * @returns {Buffer}
     */
    hmac512: (text, secret) => {
      return Promise.resolve(hmac("sha512", text, secret));
    }
  };

}).call(this);

//# sourceMappingURL=hmac.js.map
