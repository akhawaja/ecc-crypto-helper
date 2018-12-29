(function() {
  var crypto;

  crypto = require("crypto");

  module.exports = {
    /**
     * Compute a SHA-256 hash of a given string.
     *
     * @param {string} text - The text to calculate into a hash.
     * @returns {Buffer}
     */
    sha256: (text) => {
      return new Promise((resolve, reject) => {
        var hash;
        hash = crypto.createHash("sha256");
        return resolve(hash.update(text).digest());
      });
    },
    /**
     * Compute a SHA-384 hash of a given string.
     *
     * @param {string} text - The text to calculate into a hash.
     * @returns {Buffer}
     */
    sha384: (text) => {
      return new Promise((resolve, reject) => {
        var hash;
        hash = crypto.createHash("sha384");
        return resolve(hash.update(text).digest());
      });
    },
    /**
     * Compute a SHA-512 hash of a given string.
     *
     * @param {string} text - The text to calculate into a hash.
     * @returns {Buffer}
     */
    sha512: (text) => {
      return new Promise((resolve, reject) => {
        var hash;
        hash = crypto.createHash("sha512");
        return resolve(hash.update(text).digest());
      });
    }
  };

}).call(this);

//# sourceMappingURL=hash.js.map
