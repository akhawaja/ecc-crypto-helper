const commonAesCbc = require('./common-aes-cbc')
const CIPHER = 'aes-256-cbc'

module.exports = {
  /**
   * Encrypt a string using a secret.
   *
   * @param {string} text - The text to encrypt.
   * @param {string|Buffer} secret - The secret to use for decryption.
   * @returns {Promise<Buffer>} The cipher text.
   */
  encrypt: (text, secret) => {
    return commonAesCbc.encrypt(text, secret, CIPHER)
  },

  /**
   * Decrypt a previously encrypted text.
   *
   * @param {string|Buffer} cipherText - The encrypted text.
   * @param {string|Buffer} secret - The secret to use for decryption.
   * @param {Buffer} iv - Initialization vector.
   * @returns {Promise<string>} The decrypted text.
   */
  decrypt: (cipherText, secret, iv) => {
    return commonAesCbc.decrypt(cipherText, secret, CIPHER, iv)
  }
}
