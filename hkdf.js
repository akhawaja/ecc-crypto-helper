(function() {
  var common;

  common = require("./common");

  module.exports = {
    /**
     * Derive a cryptographically strong set of values using the contraction and
     * expansion method of HKDF.
     *
     * @param {string} ikm - The initial key material. A shared secret or some
     *                       other random value you know about.
     * @param {number} size - The number of bytes to derive.
     * @param {string} salt - Additional entropy.
     * @param {string} info - Additional entropy to bind the bytes derived to a
     *                        specific entity.
     * @returns {Buffer}
     */
    derive: (ikm, size, salt = null, info = null) => {
      var hkdf;
      hkdf = require("futoin-hkdf");
      return new Promise(async(resolve, reject) => {
        var err;
        if (salt === null || salt === void 0) {
          salt = (await common.randomString(32));
        }
        try {
          return resolve(hkdf(ikm, size, salt, info, "SHA-512"));
        } catch (error) {
          err = error;
          return reject(err);
        }
      });
    }
  };

}).call(this);

//# sourceMappingURL=hkdf.js.map
