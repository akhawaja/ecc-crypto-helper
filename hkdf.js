const common = require('./common')

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
   * @returns {Promise}
   */
  derive: (ikm, size, salt = null, info = null) => {
    const hkdf = require('futoin-hkdf')

    return new Promise(async (resolve, reject) => {
      if (salt === null || salt === void 0) {
        salt = await common.random(32)
      }

      try {
        return resolve(hkdf(ikm, size, salt, info, 'SHA-512'))
      } catch (err) {
        return reject(err)
      }
    })
  }
}
