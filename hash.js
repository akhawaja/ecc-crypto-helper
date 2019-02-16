const crypto = require('crypto')

module.exports = {
  /**
   * Compute a SHA-256 hash of a given string.
   *
   * @param {string} text - The text to calculate into a hash.
   * @returns {Promise}
   */
  sha256: (text) => {
    return new Promise((resolve, reject) => {
      let hash = crypto.createHash('sha256')

      return resolve(hash.update(text).digest())
    })
  },

  /**
   * Compute a SHA-384 hash of a given string.
   *
   * @param {string} text - The text to calculate into a hash.
   * @returns {Promise}
   */
  sha384: (text) => {
    return new Promise((resolve, reject) => {
      let hash = crypto.createHash('sha384')

      return resolve(hash.update(text).digest())
    })
  },

  /**
   * Compute a SHA-512 hash of a given string.
   *
   * @param {string} text - The text to calculate into a hash.
   * @returns {Promise}
   */
  sha512: (text) => {
    return new Promise((resolve, reject) => {
      let hash = crypto.createHash('sha512')

      return resolve(hash.update(text).digest())
    })
  }
}
