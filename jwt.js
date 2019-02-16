const jws = require('jws')
const base64 = require('./base64')
const common = require('./common')

/**
 * Decode a JSON web token into its constituent parts.
 *
 * @param {string} jsonWebToken - The JSON web token.
 * @returns {Promise}
 */
const decode = (jsonWebToken) => {
  return new Promise(async (resolve, reject) => {
    let parts = jsonWebToken.split('.')

    if (parts.length < 2) {
      reject(new Error('Invalid JSON web token.'))
    }

    let decoded = {}

    try {
      decoded.header = JSON.parse(await base64.urlDecode(parts[0]))
      decoded.payload = JSON.parse(await base64.urlDecode(parts[1]))
    } catch (err) {
      reject(err)
    }

    if (parts[2] !== void 0) {
      decoded.signature = parts[2]
    }

    return resolve(decoded)
  })
}

/**
 * Build a JSON web token.
 *
 * @param {string} algorithm - The algorithm to use.
 * @param {string|Buffer} secretOrPrivateKey - The shared secret or an ECDH
 *                                             private key in PEM format.
 * @param {Object} claims - Additional claims supplied by the client.
 * @returns {Promise}
 */
const create = (algorithm, secretOrPrivateKey, claims = {}) => {
  return new Promise(async (resolve, reject) => {
    let header = {
      alg: algorithm,
      typ: 'JWT'
    }
    if (claims.iss === void 0) {
      claims.iss = 'urn:iss:crypto-helper'
    }

    if (claims.aud === void 0) {
      claims.aud = 'urn:aud:any-client'
    }

    if (claims.exp === void 0) {
      // Expire in 10-minutes
      claims.exp = Math.round((new Date().getTime()) / 1000) + (60 * 10)
    }

    const currentTime = Math.round((new Date().getTime()) / 1000)
    claims.iat = currentTime
    claims.nbf = currentTime
    claims.jti = ((await common.random())).toString('hex')

    try {
      return jws.createSign({
        header: header,
        payload: claims,
        secret: secretOrPrivateKey
      }).on('done', (signature) => {
        return resolve(signature)
      })
    } catch (err) {
      return reject(err)
    }
  })
}

/**
 * Verify a JSON web token. Verifies the expiration and signature.
 *
 * @param {string} algorithm - The algorithm used.
 * @param {string|Buffer} secretOrPublicKey - The shared secret or ECDH public
 *                                            key in PEM format.
 * @param {string} jsonWebToken - The JSON web token to verify.
 * @returns {Promise}
 */
const verify = (algorithm, secretOrPublicKey, jsonWebToken) => {
  return new Promise(async (resolve, reject) => {
    // Make sure we have a valid JSON Web Token
    if (typeof jsonWebToken !== 'string') {
      reject(new TypeError('jsonWebToken must be a string.'))
    }

    let expiration
    let decoded = await decode(jsonWebToken)
    let claims = decoded.payload
    const currentTime = Math.round(new Date().getTime())

    if ((claims != null ? claims.exp : void 0) !== void 0) {
      expiration = claims.exp * 1000

      if (expiration <= currentTime) {
        reject(new Error('The token has expired.'))
      }
    }

    try {
      // Validate the signature
      return jws.createVerify({
        signature: jsonWebToken,
        algorithm: algorithm,
        key: secretOrPublicKey
      }).on('done', (verified) => {
        return resolve(verified)
      })
    } catch (err) {
      return reject(err)
    }
  })
}

module.exports = {
  decode: decode,

  es384: {
    create: (privateKey, claims) => {
      return create('ES384', privateKey, claims)
    },
    verify: (publicKey, jsonWebToken) => {
      return verify('ES384', publicKey, jsonWebToken)
    }
  },

  es512: {
    create: (privateKey, claims) => {
      return create('ES512', privateKey, claims)
    },
    verify: (publicKey, jsonWebToken) => {
      return verify('ES512', publicKey, jsonWebToken)
    }
  },

  hs384: {
    create: (secret, claims) => {
      return create('HS384', secret, claims)
    },
    verify: (secret, jsonWebToken) => {
      return verify('HS384', secret, jsonWebToken)
    }
  },

  hs512: {
    create: (secret, claims) => {
      return create('HS512', secret, claims)
    },
    verify: (secret, jsonWebToken) => {
      return verify('HS512', secret, jsonWebToken)
    }
  }
}
