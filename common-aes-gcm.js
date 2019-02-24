const crypto = require('crypto')
const common = require('./common')
const IV_LENGTH = 16
const supportedCiphers = ['aes-128-gcm', 'aes-192-gcm', 'aes-256-gcm']

const isCipherSupported = (scheme) => {
  return supportedCiphers.indexOf(scheme.toLowerCase()) >= 0
}

const calculateKeyLength = (cipher) => {
  switch (cipher.toLowerCase()) {
    case 'aes-128-gcm':
      return 16

    case 'aes-192-gcm':
      return 24

    case 'aes-256-gcm':
      return 32
  }
}

/**
 * Encrypt a payload.
 *
 * @param {string} text - The text to encrypt.
 * @param {string} secret - The shared secret.
 * @param {string} cipher - The encryption scheme to use.
 * @param {Buffer} [aad] - Additional authenticated data.
 * @returns {Promise<Object>}
 */
const encrypt = (text, secret, cipher, aad = Buffer.from('')) => {
  return new Promise(async (resolve, reject) => {
    if (!isCipherSupported(cipher)) {
      return reject(
        new Error(`cipher ${cipher} is not one from ${supportedCiphers}`))
    }

    let keyLength = calculateKeyLength(cipher)
    let masterKey = null

    if (typeof text !== 'string') {
      return reject(new Error('text to encrypt must be a string.'))
    }

    if (!Buffer.isBuffer(aad)) {
      return reject(new TypeError(`aad must be a Buffer; found ${typeof aad}`))
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

    const IV = await common.random(IV_LENGTH)

    return crypto.scrypt(masterKey, IV, keyLength,
      async (err, derivedKey) => {
        let authTag, cryptoCipher, cipherText

        if (err != null) {
          return reject(err)
        }

        cryptoCipher = crypto.createCipheriv(cipher, derivedKey, IV)

        if (Buffer.isBuffer(aad) && aad.length > 0) {
          cryptoCipher.setAAD(aad)
        }

        cipherText = Buffer.concat(
          [cryptoCipher.update(text, 'utf8'), cryptoCipher.final()])
        authTag = cryptoCipher.getAuthTag()

        let payload = {
          encrypted: cipherText,
          iv: IV,
          authTag
        }

        return resolve(payload)
      })
  })
}

/**
 * Decrypt a cipher text.
 *
 * @param {string|Buffer} cipherText - The cipher text.
 * @param {string} secret - The shared secret.
 * @param {string} cipher - The decryption scheme to use.
 * @param {Buffer} iv - The initialization vector.
 * @param {Buffer} authTag - The authentication tag.
 * @param {Buffer} [aad] - Additional authenticated data.
 * @returns {Promise<Buffer>}
 */
const decrypt = (cipherText, secret, cipher, iv, authTag,
  aad = Buffer.from('')) => {
  return new Promise(async (resolve, reject) => {
    if (!isCipherSupported(cipher)) {
      return reject(
        new Error(`cipher ${cipher} is not one from ${supportedCiphers}`))
    }

    let keyLength = calculateKeyLength(cipher)
    let masterKey = null
    let cipherTextBuffer = null

    if (typeof cipherText === 'string') {
      cipherTextBuffer = Buffer.from(cipherText)
    }

    if (Buffer.isBuffer(cipherText)) {
      cipherTextBuffer = cipherText
    } else {
      return reject(new TypeError(
        `cipherText should be a Buffer or string. Found '${typeof cipherTextBuffer}'.`))
    }

    if (!Buffer.isBuffer(iv)) {
      return reject(new TypeError(
        `iv should be a buffer. Found '${typeof iv}'.`))
    }

    if (Buffer.isBuffer(secret)) {
      masterKey = secret
    } else if (typeof secret === 'string') {
      masterKey = Buffer.from(secret)
    } else {
      return reject(new TypeError(
        `secret should be either a String or Buffer. Found '${typeof secret}'.`))
    }

    if (!Buffer.isBuffer(aad)) {
      return reject(new Error(`aad must be a Buffer. Found ${typeof aad}`))
    }

    return crypto.scrypt(masterKey, iv, keyLength,
      async (err, derivedKey) => {
        if (err) {
          throw err
        }

        let cryptoCipher = crypto.createDecipheriv(cipher, derivedKey, iv)

        if (Buffer.isBuffer(aad) && aad.length > 0) {
          cryptoCipher.setAAD(aad)
        }

        cryptoCipher.setAuthTag(authTag)

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
