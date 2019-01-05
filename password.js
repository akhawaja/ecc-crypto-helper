(function() {

  /**
   * Hash the password using the Scrypt algorithm.
   *
   * @param {string} plainPassword - The password to hash.
   * @param {string} salt - Additional entropy to use when hashing the password.
   * @returns {Buffer}
   */
  var KEY_LENGTH, SALT_SIZE, common, crypto, hkdf, scryptPassword;

  crypto = require("crypto");

  common = require("./common");

  hkdf = require("./hkdf");

  SALT_SIZE = 64;

  KEY_LENGTH = 64;

  scryptPassword = (plainPassword, salt = null) => {
    return new Promise(async(resolve, reject) => {
      if (salt === null) {
        salt = (await common.random(SALT_SIZE));
      }
      return crypto.scrypt(plainPassword, salt, KEY_LENGTH, async(err, derivedKey) => {
        var expandedKey;
        if (err != null) {
          return reject(err);
        }
        expandedKey = (await hkdf.derive(derivedKey, KEY_LENGTH, salt));
        return resolve(Buffer.concat([salt, expandedKey]));
      });
    });
  };

  module.exports = {
    /**
     * Hash the password using a combination of Scrypt and HKDF.
     *
     * @param {string} plainPassword - The password to hash.
     * @returns {Buffer} The hashed password.
     */
    hash: (plainPassword) => {
      return Promise.resolve(scryptPassword(plainPassword));
    },
    /**
     * Verify that the plain password and derivedPassword match.
     *
     * @param {string} plainPassword - The plain password.
     * @param {string|Buffer} derivedPassword - The previously hashed password.
     * @returns {boolean} true if the password is correct; false otherwise.
     */
    match: (plainPassword, derivedPassword) => {
      return new Promise(async(resolve, reject) => {
        var derivedBuffer, hash, salt;
        if (Buffer.isBuffer(derivedPassword)) {
          derivedBuffer = derivedPassword; // We assume the string is hex encoded
        } else {
          derivedBuffer = Buffer.from(derivedPassword, "hex");
        }
        salt = derivedBuffer.slice(0, SALT_SIZE);
        hash = (await scryptPassword(plainPassword, salt));
        return resolve(hash.compare(derivedBuffer) === 0);
      });
    }
  };

}).call(this);

//# sourceMappingURL=password.js.map
