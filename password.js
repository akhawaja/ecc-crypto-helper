const crypto = require('crypto')
const common = require('./common')
const hkdf = require('./hkdf')
const SALT_SIZE = 64
const KEY_LENGTH = 64

/**
 * Hash the password using the Scrypt algorithm.
 *
 * @param {string} plainPassword - The password to hash.
 * @param {string} salt - Additional entropy to use when hashing the password.
 * @returns {Promise}
 */
const scryptPassword = (plainPassword, salt = '') => {
  return new Promise(async (resolve, reject) => {
    if (salt === '') {
      salt = await common.random(SALT_SIZE)
    }

    return crypto.scrypt(plainPassword, salt, KEY_LENGTH,
      async (err, derivedKey) => {
        if (err != null) {
          return reject(err)
        }

        const expandedKey = await hkdf.derive(derivedKey, KEY_LENGTH, salt)

        return resolve(Buffer.concat([salt, expandedKey]))
      })
  })
}

module.exports = {
  /**
   * Hash the password using a combination of Scrypt and HKDF.
   *
   * @param {string} plainPassword - The password to hash.
   * @returns {Promise} The hashed password.
   */
  hash: (plainPassword) => {
    return scryptPassword(plainPassword)
  },

  /**
   * Verify that the plain password and derivedPassword match.
   *
   * @param {string} plainPassword - The plain password.
   * @param {string|Buffer} derivedPassword - The previously hashed password.
   * @returns {Promise} true if the password is correct; false otherwise.
   */
  match: (plainPassword, derivedPassword) => {
    return new Promise(async (resolve, reject) => {
      let derivedBuffer

      if (Buffer.isBuffer(derivedPassword)) {
        derivedBuffer = derivedPassword // We assume the string is hex encoded
      } else {
        derivedBuffer = Buffer.from(derivedPassword, 'hex')
      }

      const salt = derivedBuffer.slice(0, SALT_SIZE)
      const hash = (await scryptPassword(plainPassword, salt))

      return resolve(hash.compare(derivedBuffer) === 0)
    })
  }
}
