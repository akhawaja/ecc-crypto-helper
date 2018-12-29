crypto = require "crypto"

module.exports =
  ###*
   * Compute a SHA-256 hash of a given string.
   *
   * @param {string} text - The text to calculate into a hash.
   * @returns {Buffer}
  ###
  sha256: (text) =>
    new Promise (resolve, reject) =>
      hash = crypto.createHash("sha256")
      resolve hash.update(text).digest()

  ###*
   * Compute a SHA-384 hash of a given string.
   *
   * @param {string} text - The text to calculate into a hash.
   * @returns {Buffer}
  ###
  sha384: (text) =>
    new Promise (resolve, reject) =>
      hash = crypto.createHash("sha384")
      resolve hash.update(text).digest()

  ###*
   * Compute a SHA-512 hash of a given string.
   *
   * @param {string} text - The text to calculate into a hash.
   * @returns {Buffer}
  ###
  sha512: (text) =>
    new Promise (resolve, reject) =>
      hash = crypto.createHash("sha512")
      resolve hash.update(text).digest()
