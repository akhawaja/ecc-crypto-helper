const commonAesGcm = require('./common-aes-gcm')
const CIPHER = 'aes-128-gcm'

module.exports = {
  /**
   * Encrypt a string using a secret.
   *
   * @param {string} text - The text to encrypt.
   * @param {string|Buffer} secret - The secret to use for decryption.
   * @param {string} [aad] - Additional authenticated data.
   * @returns {Promise<Object>} The cipher text.
   */
  encrypt: (text, secret, aad = Buffer.from('')) => {
    return commonAesGcm.encrypt(text, secret, CIPHER, aad)
  },

  /**
   * Decrypt a previously encrypted text.
   *
   * @param {string|Buffer} cipherText - The encrypted text.
   * @param {string|Buffer} secret - The secret to use for decryption.
   * @param {Buffer} iv - Initialization vector.
   * @param {Buffer} authTag - Authentication tag.
   * @param {string} [aad] - Additional authenticated data.
   * @returns {Promise<string>} The decrypted text.
   */
  decrypt: (cipherText, secret, iv, authTag, aad = Buffer.from('')) => {
    return commonAesGcm.decrypt(cipherText, secret, CIPHER, iv, authTag, aad)
  }
}
