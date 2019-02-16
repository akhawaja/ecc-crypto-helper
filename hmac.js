const crypto = require('crypto')

/**
 *
 * @param digest
 * @param text
 * @param secret
 * @returns {Promise<any>}
 */
const hmac = (digest, text, secret) => {
  return new Promise((resolve, reject) => {
    return resolve(crypto.createHmac(digest, secret).update(text).digest())
  })
}

module.exports = {
  /**
   * Compute an HMAC using SHA-256 of a given string.
   *
   * @param {string} text - The text to calculate into a hash.
   * @param {string} secret - The shared secret.
   * @returns {Promise}
   */
  hmac256: (text, secret) => {
    return hmac('sha256', text, secret)
  },

  /**
   * Compute an HMAC using SHA-384 of a given string.
   *
   * @param {string} text - The text to calculate into a hash.
   * @param {string} secret - The shared secret.
   * @returns {Promise}
   */
  hmac384: (text, secret) => {
    return hmac('sha384', text, secret)
  },

  /**
   * Compute an HMAC using SHA-512 of a given string.
   *
   * @param {string} text - The text to calculate into a hash.
   * @param {string} secret - The shared secret.
   * @returns {Promise}
   */
  hmac512: (text, secret) => {
    return hmac('sha512', text, secret)
  }
}
