const crypto = require('crypto')
const permittedModulusLengths = [1024, 2048, 4096]
const permittedHashForSignatures = ['SHA256', 'SHA512']
const MIN_PASSPHRASE_LENGTH = 8

/**
 * Create a new RSA key pair.
 *
 * @param {int} modulusLength - The RSA modulus length.
 * @param {string} passphrase - The passphrase to use to protect the private key.
 * @returns {Promise}
 */
const createKeyPair = (modulusLength, passphrase = '') => {
  return new Promise(async (resolve, reject) => {
    if (permittedModulusLengths.indexOf(modulusLength) < 0) {
      return reject(
        new Error(`modulusLength must be one of ${permittedModulusLengths}`))
    }

    let options = {
      modulusLength: modulusLength,
      publicExponent: 65537,
      publicKeyEncoding: {
        type: 'pkcs1',
        format: 'pem'
      },
      privateKeyEncoding: {
        type: 'pkcs1',
        format: 'pem'
      }
    }

    if (passphrase !== '') {
      if (passphrase.length < MIN_PASSPHRASE_LENGTH) {
        return reject(new Error('passphrase too short.'))
      }

      options.privateKeyEncoding.cipher = 'aes-256-cbc'
      options.privateKeyEncoding.passphrase = passphrase
    }

    crypto.generateKeyPair('rsa', options, (err, publicKey, privateKey) => {
      if (err) {
        return reject(err)
      }

      console.log()
      return resolve({ privateKey, publicKey })
    })
  })
}

/**
 * Check if the hash type supplied is one that is acceptable.
 *
 * @param {string} hash - The SHA2 hash type.
 * @returns {number}
 */
const isHashPermitted = (hash) => {
  return permittedHashForSignatures.indexOf(hash.toUpperCase())
}

/**
 * Sign a payload
 *
 * @param {string} payload - The payload to sign.
 * @param {string} privateKey - The private key in PEM format.
 * @param {string} passphrase - The passphrase protecting the private key.
 * @param {string} hash - The SHA2 hash to use.
 * @returns {Promise<Buffer>}
 */
const signPayload = async (payload, privateKey, passphrase = '',
  hash = 'SHA256') => {
  return new Promise(async (resolve, reject) => {
    try {
      if (isHashPermitted(hash) < 0) {
        return reject(
          new Error(`hash must be one of ${permittedHashForSignatures}`))
      }

      const signer = crypto.createSign(hash)
      signer.update(payload)
      signer.end()

      let keyOptions = {
        key: privateKey
      }

      if (passphrase !== '') {
        keyOptions.passphrase = passphrase
      }

      const key = crypto.createPrivateKey(keyOptions)

      return resolve(signer.sign(key))
    } catch (e) {
      return reject(e)
    }
  })
}

/**
 * Verify a payload signed using a RSA private key.
 *
 * @param {string} payload - The payload over which the signature was created.
 * @param {Buffer} signature - The signature of the payload.
 * @param {string} publicKey - PEM encoded RSA public certificate.
 * @param {string} hash - The SHA2 hash to use.
 * @returns {Promise<boolean>}
 */
const verifyPayloadSignature = (payload, signature, publicKey,
  hash = 'SHA256') => {
  return new Promise(async (resolve, reject) => {
    try {
      if (isHashPermitted(hash) < 0) {
        return reject(
          new Error(`hash must be one of ${permittedHashForSignatures}`))
      }

      const verifier = crypto.createVerify(hash)
      verifier.update(payload)
      verifier.end()

      return resolve(verifier.verify(publicKey, signature))
    } catch (e) {
      return reject(e)
    }
  })
}

/**
 * Encrypt a payload with a RSA public key. Defaults to using
 * RSA_PKCS1_OAEP_PADDING.
 *
 * @param {string} publicKey - The RSA public key in PEM format.
 * @param {string|Buffer} payload - The payload to encrypt.
 * @returns {Promise}
 */
const encryptWithPublicKey = (publicKey, payload) => {
  return new Promise((resolve, reject) => {
    const key = crypto.createPublicKey(publicKey)
    const buffer = Buffer.isBuffer(payload) ? payload : Buffer.from(payload)

    try {
      return resolve(crypto.publicEncrypt(key, buffer))
    } catch (e) {
      return reject(e)
    }
  })
}

/**
 * Decrypt a payload encrypted with a RSA private key. Defaults to using
 * RSA_PKCS1_OAEP_PADDING.
 *
 * @param {string} privateKey - The RSA private key in PEM format.
 * @param {string|Buffer} payload - The paylad to decrypt.
 * @param {string} passphrase = The passphrase used to protect the private key.
 * @returns {Promise}
 */
const decryptWithPrivateKey = (privateKey, payload, passphrase = '') => {
  return new Promise((resolve, reject) => {
    let keyOptions = {
      key: privateKey
    }

    if (passphrase !== '') {
      keyOptions.passphrase = passphrase
    }

    const key = crypto.createPrivateKey(keyOptions)
    const buffer = Buffer.isBuffer(payload) ? payload : Buffer.from(payload)

    try {
      return resolve(crypto.privateDecrypt(key, buffer))
    } catch (e) {
      return reject(e)
    }
  })
}

module.exports = {
  generateKeyPair: (modulusLength = 2048, passphrase = '') => {
    return createKeyPair(modulusLength, passphrase)
  },

  encrypt: encryptWithPublicKey,

  decrypt: decryptWithPrivateKey,

  signPayload,

  verifyPayloadSignature
}
