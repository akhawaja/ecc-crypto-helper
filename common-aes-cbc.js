const crypto = require('crypto')
const common = require('./common')
const supportedCiphers = ['aes-128-cbc', 'aes-192-cbc', 'aes-256-cbc']
const IV_LENGTH = 16

const isCipherSupported = (scheme) => {
  return supportedCiphers.indexOf(scheme.toLowerCase()) >= 0
}

const calculateKeyLength = (cipher) => {
  switch (cipher.toLowerCase()) {
    case 'aes-128-cbc':
      return 16

    case 'aes-192-cbc':
      return 24

    case 'aes-256-cbc':
      return 32
  }
}

/**
 * Encrypt a string using a secret.
 *
 * @param {string} text - The text to encrypt.
 * @param {string|Buffer} secret - The secret to use for decryption.
 * @param {string} cipher - The encryption scheme to use.
 * @returns {Promise<Object>} The cipher text.
 */
const encrypt = (text, secret, cipher) => {
  return new Promise(async (resolve, reject) => {
    if (!isCipherSupported(cipher)) {
      return reject(
        new Error(`cipher ${cipher} must be one of ${supportedCiphers}`))
    }

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

    let keyLength = calculateKeyLength(cipher)
    let iv = await common.random(IV_LENGTH)

    return crypto.scrypt(masterKey, iv, keyLength,
      async (err, derivedKey) => {
        let cryptoCipher, cipherText

        if (err != null) {
          return reject(err)
        }

        cryptoCipher = crypto.createCipheriv(cipher, derivedKey, iv)
        cipherText = Buffer.concat(
          [cryptoCipher.update(text, 'utf8'), cryptoCipher.final()])

        let payload = {
          encrypted: cipherText,
          iv
        }

        return resolve(payload)
      })
  })
}

/**
 * Decrypt a previously encrypted text.
 *
 * @param {string|Buffer} cipherText - The encrypted text.
 * @param {string|Buffer} secret - The secret to use for decryption.
 * @param {string} cipher - The encryption scheme to use.
 * @param {Buffer} iv - Initialization vector.
 * @returns {Promise<string>} The decrypted text.
 */
const decrypt = (cipherText, secret, cipher, iv) => {
  return new Promise((resolve, reject) => {
    if (!isCipherSupported(cipher)) {
      return reject(
        new Error(`cipher ${cipher} must be one of ${supportedCiphers}`))
    }

    let cipherTextBuffer, masterKey
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

    let keyLength = calculateKeyLength(cipher)

    return crypto.scrypt(masterKey, iv, keyLength,
      async (err, derivedKey) => {
        if (err) {
          throw err
        }

        let cryptoCipher = crypto.createDecipheriv(cipher, derivedKey, iv)
        let text = cryptoCipher.update(cipherTextBuffer, 'binary', 'utf8') +
          cryptoCipher.final('utf8')

        return resolve(text)
      })
  })
}

module.exports = {
  encrypt,
  decrypt
}
