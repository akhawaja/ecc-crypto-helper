const crypto = require('crypto')
const common = require('./common')
const hkdf = require('./hkdf')
const ITERATIONS = 10000
const KEY_LENGTH = 32 // AES-GCM-256 requires a 32-bytes key length
const DIGEST = 'sha512'
const CIPHER = 'aes-256-gcm'
const SALT_SIZE = 64
const AUTH_TAG_SIZE = 16
const IV_SIZE = 12 // A 12-bytes (96-bit initialization vector) is recommended for AES-GCM-256

module.exports = {
  /**
   * Encrypt a string using a secret.
   *
   * @param {string} text - The text to encrypt.
   * @param {string|Buffer} secret - The secret to use for decryption.
   * @returns {Promise} The cipher text.
   */
  encrypt: (text, secret) => {
    return new Promise(async (resolve, reject) => {
      let masterKey = null

      if (typeof text !== 'string') {
        reject(new Error('text to encrypt must be a string.'))
      }

      // We will presume that the secret is cryptographically strong
      if (Buffer.isBuffer(secret)) {
        masterKey = secret
      } else if (typeof secret === 'string') {
        masterKey = Buffer.from(secret)
      } else {
        return reject(new Error(
          `secret should be either a String or Buffer. Found '${typeof secret}'.`))
      }
      let salt = await common.random(SALT_SIZE)
      let iv = await common.random(IV_SIZE)
      return crypto.pbkdf2(masterKey, salt, ITERATIONS, KEY_LENGTH, DIGEST,
        async (err, derivedKey) => {
          let authTag, cipher, cipherText, expandedKey

          if (err != null) {
            return reject(err)
          }

          expandedKey = await hkdf.derive(derivedKey, KEY_LENGTH, salt)
          cipher = crypto.createCipheriv(CIPHER, expandedKey, iv)
          cipherText = Buffer.concat(
            [cipher.update(text, 'utf8'), cipher.final()])
          authTag = cipher.getAuthTag()

          return resolve(Buffer.concat([salt, iv, authTag, cipherText]))
        })
    })
  },

  /**
   * Decrypt a previously encrypted text.
   *
   * @param {string|Buffer} cipherText - The encrypted text.
   * @param {string|Buffer} secret - The secret to use for decryption.
   * @returns {Promise} The decrypted text.
   */
  decrypt: (cipherText, secret) => {
    return new Promise((resolve, reject) => {
      let authTag, cipherTextBuffer, iv, masterKey, salt
      masterKey = null
      cipherTextBuffer = null

      if (typeof cipherText === 'string') {
        cipherTextBuffer = Buffer.from(cipherText)
      }

      if (Buffer.isBuffer(cipherText)) {
        cipherTextBuffer = cipherText
      } else {
        return reject(new TypeError(
          `cipherText should be a Buffer or string. Found '${typeof cipherTextBuffer}'.`))
      }

      if (Buffer.isBuffer(secret)) {
        masterKey = secret
      } else if (typeof secret === 'string') {
        masterKey = Buffer.from(secret)
      } else {
        return reject(new TypeError(
          `secret should be either a String or Buffer. Found '${typeof secret}'.`))
      }

      salt = cipherTextBuffer.slice(0, SALT_SIZE)
      iv = cipherTextBuffer.slice(SALT_SIZE, SALT_SIZE + IV_SIZE)
      authTag = cipherTextBuffer.slice(SALT_SIZE + IV_SIZE,
        SALT_SIZE + IV_SIZE + AUTH_TAG_SIZE)
      cipherText = cipherTextBuffer.slice(SALT_SIZE + IV_SIZE + AUTH_TAG_SIZE)

      return crypto.pbkdf2(masterKey, salt, ITERATIONS, KEY_LENGTH, DIGEST,
        async (err, derivedKey) => {
          if (err) {
            throw err
          }

          let expandedKey = (await hkdf.derive(derivedKey, KEY_LENGTH, salt))
          let cipher = crypto.createDecipheriv(CIPHER, expandedKey, iv)
          cipher.setAuthTag(authTag)
          let text = cipher.update(cipherText, 'binary', 'utf8') + cipher.final(
            'utf8')
          return resolve(text)
        })
    })
  }
}
