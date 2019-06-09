const crypto = require('crypto')
const base64 = require('./base64')
const { create: createKSUID } = require('./ksuid')

const funcs = {
  /**
   * Generate a random shared secret.
   *
   * @param {number} size - The size of the shared secret.
   * @returns {Promise<Buffer>} The shared secret.
   */
  generateSharedSecret: async (size = 32) => {
    return new Promise((resolve, reject) => {
      let masterKey = undefined
      let iv = undefined

      crypto.randomBytes(size, (err, buf) => {
        if (err) {
          return reject(err)
        }

        masterKey = buf

        crypto.randomBytes(16, (err, buf) => {
          if (err) {
            return reject(`Could not generate an IV: ${err}.`)
          }

          iv = buf

          crypto.scrypt(masterKey, iv, size, (err, secret) => {
            if (err) {
              return reject(`Could not generate a secret: ${err}.`)
            }

            return resolve(secret)
          })
        })
      })
    })
  },

  /**
   * Convert a shared secret to a JSON Web Key.
   *
   * @param {Buffer|string} secret - The shared secret to package in a JWK.
   * @param {string} [keyId - The key identifier to assign.
   * @returns {Promise<Object>} The JSON Web Key.
   */
  convertSharedSecretToJwk: async (secret, keyId = undefined) => {
    return new Promise(async resolve => {
      const sharedSecret = Buffer.isBuffer(secret) ? secret : Buffer.from(secret)
      const kid = keyId !== undefined ? keyId : await createKSUID()
      const encoded = await base64.urlEncode(sharedSecret)
      const jsonWebKey = {
        k: encoded,
        kty: 'oct',
        kid: kid
      }
      return resolve(jsonWebKey)
    })
  },

  /**
   * Generate a shared secret and return it as a JSON Web Key.
   *
   * @param {number} size - The size of the key.
   * @returns {Promise<Object>} The shared secret.
   */
  generateSharedSecretAsJwk: async (size = 32) => {
    return new Promise(async (resolve, reject) => {
      try {
        const sharedSecret = await funcs.generateSharedSecret(size)
        const jwk = await funcs.convertSharedSecretToJwk(sharedSecret)

        return resolve(jwk)
      } catch (e) {
        return reject(`Unable to generate shared secret: ${e}.`)
      }
    })
  }
}

module.exports = funcs
