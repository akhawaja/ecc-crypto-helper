const crypto = require('crypto')
const { pem2jwk: pemToJwk, jwk2pem: jwkToPem } = require('pem-jwk')
const permittedModulusLengths = [1024, 2048, 4096]
const permittedHashForSignatures = ['SHA256', 'SHA512']
const MIN_PASSPHRASE_LENGTH = 8
const KEY_TYPE = 'rsa'
const PRIV_KEY_FORMAT = 'pem'
const PRIV_KEY_TYPE = 'pkcs1'
const PUB_KEY_FORMAT = 'pem'
const PUB_KEY_TYPE = 'pkcs1'

/**
 * Create a new RSA key pair.
 *
 * @param {int} modulusLength - The RSA modulus length.
 * @param {string} passphrase - The passphrase to use to protect the private key.
 * @param {Object} [options] - Options.
 * @param {string} [options.publicKeyEncoding] - Encoding to use for the public keys.
 * @param {string} [options.privateKeyEncoding] - Encoding to use for the private keys.
 * @param {string} [options.privateKeyCipher] - Cipher to use for the private keys.
 * @returns {Promise}
 */
const createKeyPair = (modulusLength, passphrase = undefined, options = {}) => {
  const type = KEY_TYPE

  return new Promise(async (resolve, reject) => {
    if (permittedModulusLengths.indexOf(modulusLength) < 0) {
      return reject(
        new Error(`modulusLength must be one of ${permittedModulusLengths}`))
    }

    const keyOptions = {
      modulusLength: modulusLength,
      publicKeyEncoding: {
        type: PUB_KEY_TYPE,
        format: PUB_KEY_FORMAT
      },
      privateKeyEncoding: {
        type: PRIV_KEY_TYPE,
        format: PRIV_KEY_FORMAT
      }
    }

    if (passphrase !== undefined) {
      if (passphrase.length < MIN_PASSPHRASE_LENGTH) {
        return reject(new Error('passphrase too short.'))
      }

      keyOptions.privateKeyEncoding.cipher = 'aes-256-cbc'
      keyOptions.privateKeyEncoding.passphrase = passphrase
    }

    // Override the default options.
    if (options.publicKeyEncoding !== undefined) {
      keyOptions.publicKeyEncoding.type = options.publicKeyEncoding
    }

    if (options.privateKeyEncoding !== undefined) {
      keyOptions.privateKeyEncoding.type = options.privateKeyEncoding
    }

    if (options.privateKeyCipher !== undefined) {
      keyOptions.privateKeyEncoding.cipher = options.privateKeyCipher
    }

    // Generate the key pair.
    crypto.generateKeyPair(type, keyOptions, (err, publicKey, privateKey) => {
      if (err) {
        return reject(err)
      }

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
 * @param {Object} [options] - Options.
 * @param {string} [options.hashAlgorithm] - The SHA2 hash to use.
 * @param {Object} [options.privateKey] - Options for the RSA private key.
 * @param {string} [options.privateKey.format] - Format of the RSA private key.
 * @param {string} [options.privateKey.type] - Type of the RSA private key.
 * @returns {Promise<Buffer>}
 */
const signPayload = async (payload, privateKey, passphrase = undefined, options = {}) => {
  return new Promise(async (resolve, reject) => {
    try {
      let hashAlgorithm = 'sha256'

      if (options.hashAlgorithm !== undefined) {
        if (isHashPermitted(hashAlgorithm) < 0) {
          return reject(
            new Error(`hash must be one of ${permittedHashForSignatures}`))
        }

        hashAlgorithm = options.hashAlgorithm
      }

      const signer = crypto.createSign(hashAlgorithm)
      signer.update(payload)
      signer.end()

      const keyOptions = {
        key: privateKey,
        format: PRIV_KEY_FORMAT,
        type: PRIV_KEY_TYPE
      }

      if (passphrase !== undefined) {
        keyOptions.passphrase = passphrase
      }

      if (options.privateKey !== undefined) {
        if (options.privateKey.format !== undefined) {
          keyOptions.format = options.privateKey.format
        }

        if (options.privateKey.type !== undefined) {
          keyOptions.type = options.privateKey.type
        }
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
 * @param {Object} [options] - Options.
 * @param {Object} [options.publicKey] - The RSA public key options.
 * @param {string} [options.publicKey.format] - The format of the RSA public key (pem or der).
 * @param {string} [options.publicKey.type] - The type of the RSA public key.
 * @param {string} [options.hashAlgorithm] - The SHA2 hash algorithm to use.
 * @returns {Promise<boolean>}
 */
const verifyPayloadSignature = (payload, signature, publicKey, options = {}) => {
  return new Promise(async (resolve, reject) => {
    try {
      let hashAlgorithm = 'sha256'
      if (options.hashAlgorithm !== undefined) {
        hashAlgorithm = options.hashAlgorithm
      }

      if (isHashPermitted(hashAlgorithm) < 0) {
        return reject(
          new Error(`hash must be one of ${permittedHashForSignatures}`))
      }

      const verifier = crypto.createVerify(hashAlgorithm)
      verifier.update(payload)
      verifier.end()

      const publicKeyOptions = {
        key: publicKey,
        format: PUB_KEY_FORMAT,
        type: PUB_KEY_TYPE
      }

      if (options.publicKey !== undefined) {
        if (options.publicKey.format !== undefined) {
          publicKeyOptions.format = options.publicKey.format
        }

        if (options.publicKey.type !== undefined) {
          publicKeyOptions.type = options.publicKey.type
        }
      }

      return resolve(verifier.verify(publicKeyOptions, signature))
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
 * @param {Object} options - Options.
 * @param {string} [options.format] - The format of the key (pem or der)
 * @param {string} [options.padding] - The padding to use when encrypting.
 * @param {string} [options.type] - The type of key. Required when the format of the key is 'der'.
 * @returns {Promise<Buffer>}
 */
const encryptWithKey = (publicKey, payload, options = {}) => {
  return new Promise((resolve, reject) => {
    const buffer = Buffer.isBuffer(payload) ? payload : Buffer.from(payload)
    const keyOptions = {
      key: publicKey,
      format: PUB_KEY_FORMAT,
      type: PUB_KEY_TYPE
    }

    if (options.format !== undefined) {
      keyOptions.format = options.format
    }

    const key = crypto.createPublicKey(keyOptions)
    const encryptOptions = { key }

    if (options.padding !== undefined) {
      encryptOptions.padding = options.padding
    } else {
      encryptOptions.padding = crypto.constants.RSA_PKCS1_OAEP_PADDING
    }

    try {
      return resolve(crypto.publicEncrypt(encryptOptions, buffer))
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
 * @param {string|Buffer} payload - The payload to decrypt.
 * @param {Object} [options] - Options.
 * @param {string} [options.passphrase] = The passphrase used to protect the private key.
 * @param {string} [options.padding] - The padding to use when decrypting the payload.
 * @param {string} [options.format] - The format of the key.
 * @param {string} [options.type] - The type of the key. This is required when the key format is 'der'.
 * @returns {Promise<Buffer>}
 */
const decryptWithKey = (privateKey, payload, options = {}) => {
  return new Promise((resolve, reject) => {
    const buffer = Buffer.isBuffer(payload) ? payload : Buffer.from(payload)
    const keyOptions = {
      key: privateKey,
      format: PRIV_KEY_FORMAT,
      type: PRIV_KEY_TYPE
    }

    if (options.passphrase !== undefined) {
      keyOptions.passphrase = options.passphrase
    }

    if (options.format !== undefined) {
      keyOptions.format = options.format
    }

    if (options.type !== undefined) {
      keyOptions.type = options.type
    }

    const key = crypto.createPrivateKey(keyOptions)
    const decryptOptions = { key }

    if (options.padding !== undefined) {
      decryptOptions.padding = options.padding
    } else {
      decryptOptions.padding = crypto.constants.RSA_PKCS1_OAEP_PADDING
    }

    try {
      return resolve(crypto.privateDecrypt(decryptOptions, buffer))
    } catch (e) {
      return reject(e)
    }
  })
}

/**
 * Convert a RSA PEM certificate to JSON Web Key.
 *
 * @param {string} rsaKey - The RSA key in PEM format.
 * @returns {Promise<Object>} The RSA key as JSON web key.
 */
const convertPemToJwk = (rsaKey) => {
  return new Promise(async (resolve, reject) => {
    try {
      return resolve(pemToJwk(rsaKey))
    } catch (e) {
      return reject(e)
    }
  })
}

/**
 * Convert a RSA JSON Web Key to PEM.
 *
 * @param {Object} jwk - The JSON Web Key to convert.
 * @returns {Promise<string>} The RSA key as PEM.
 */
const convertJwkToPem = (jwk) => {
  return new Promise(async (resolve, reject) => {
    try {
      return resolve(jwkToPem(jwk))
    } catch (e) {
      return reject(e)
    }
  })
}

module.exports = {
  generateKeyPair: createKeyPair,
  encrypt: encryptWithKey,
  decrypt: decryptWithKey,
  signPayload,
  verifyPayloadSignature,
  convertPemToJwk,
  convertJwkToPem
}
