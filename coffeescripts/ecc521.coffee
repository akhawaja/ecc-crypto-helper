crypto = require "crypto"
ecKeyUtils = require "eckey-utils"
common = require "./common"

CURVE_NAME = "secp521r1"
HASH_TYPE = "sha512"

module.exports =
  curveName: CURVE_NAME

  ###*
   * Convert a PEM certificate to a JSON Web Key.
   *
   * @param {string|Buffer} privateOrPublicPem - The private or public PEM key.
   * @param {Array} privateKeyOps - The operations intended for the private key.
   * @param {Array} publicKeyOps - The operations intended for the public key.
   * @returns {Object} The converted certificate.
  ###
  convertPemToJwk: (privateOrPublicPem, privateKeyOps = [], publicKeyOps = []) =>
    new Promise (resolve, reject) =>
      if privateKeyOps.length is 0
        privateKeyOps = ["deriveKey", "sign"]

      if publicKeyOps.length is 0
        publicKeyOps = ["verify"]

      try
        parsed = ecKeyUtils.parsePem(privateOrPublicPem)
        params = {}

        if parsed.privateKey isnt undefined and parsed.privateKey isnt null
          params.privateKey = parsed.privateKey

        if parsed.publicKey isnt undefined and parsed.publicKey isnt null
          params.publicKey = parsed.publicKey

        jwk = ecKeyUtils.generateJwk(CURVE_NAME, parsed)
        kid = (await common.randomString()).toString("hex")

        if jwk.privateKey isnt undefined
          jwk.privateKey.kid = kid
          jwk.privateKey.key_ops = privateKeyOps

        if jwk.publicKey isnt undefined
          jwk.publicKey.kid = kid
          jwk.publicKey.key_ops = publicKeyOps

        resolve jwk
      catch err
        reject err

  ###*
   * Convert a JSON Web Key to a PEM certificate.
   *
   * @param {string|Buffer} privateOrPublicJwk - The private or public JSON Web Key.
   * @returns {Object} The converted certificate.
  ###
  convertJwkToPem: (privateOrPublicJwk) =>
    new Promise (resolve, reject) =>
      try
        parsed = ecKeyUtils.parseJwk(privateOrPublicJwk)
        params = {}

        if parsed.privateKey isnt undefined and parsed.privateKey isnt null
          params.privateKey = parsed.privateKey

        if parsed.publicKey isnt undefined and parsed.publicKey isnt null
          params.publicKey = parsed.publicKey

        resolve ecKeyUtils.generatePem(CURVE_NAME, params)
      catch err
        reject err

  ###*
   * Generate an ECDH key pair as a JSON Web Key.
   *
   * @param {Array} privateKeyOps - The operations intended for the private key.
   * @param {Array} publicKeyOps - The operations intended for the public key.
   * @returns {string} The ECDH key pair.
  ###
  generateJwkKeyPair: (privateKeyOps = [], publicKeyOps = []) =>
    if privateKeyOps.length is 0
      privateKeyOps = ["deriveKey", "sign"]

    if publicKeyOps.length is 0
      publicKeyOps = ["verify"]

    new Promise (resolve, reject) =>
      ecdh = crypto.createECDH CURVE_NAME
      ecdh.generateKeys()
      params =
        privateKey: ecdh.getPrivateKey()
        publicKey: ecdh.getPublicKey()

      jwk = ecKeyUtils.generateJwk CURVE_NAME, params
      kid = (await common.randomString()).toString("hex")

      jwk.privateKey.kid = kid
      jwk.privateKey.key_ops = privateKeyOps

      jwk.publicKey.kid = kid
      jwk.publicKey.key_ops = publicKeyOps

      resolve jwk

  ###*
   * Generate an ECDH key pair as PEM certificates.
   *
   * @returns {Object} The PEM certificates.
  ###
  generatePemKeyPair: () =>
    new Promise (resolve, reject) =>
      ecdh = crypto.createECDH CURVE_NAME
      ecdh.generateKeys()
      params =
        privateKey: ecdh.getPrivateKey()
        publicKey: ecdh.getPublicKey()

      resolve ecKeyUtils.generatePem CURVE_NAME, params

  ###*
   * Sign a payload to prevent it from tamper.
   *
   * @param {string} payload - The payload to sign.
   * @param {string} privateKeyPem - The private key in PEM format.
   * @returns {Buffer} The signature for the payload.
  ###
  signPayload: (payload, privateKeyPem) =>
    new Promise (resolve, reject) =>
      if typeof payload isnt "string"
        return reject "Payload must be a string."

      signer = crypto.createSign HASH_TYPE
      message = Buffer.from payload
      signer.update message
      resolve signer.sign privateKeyPem

  ###*
   * Verify the signature of a given payload.
   *
   * @param {string} payload - The payload against which the signature will be checked.
   * @param {string|Buffer} signature - The signature of the payload.
   * @param {Object} publicPemKey - The public ECDH key in PEM format.
   * @returns {boolean}
  ###
  verifyPayloadSignature: (payload, signature, publicKeyPem) =>
    new Promise (resolve, reject) =>
      if typeof payload isnt "string"
        return reject "Payload must be a string."

      verifier = crypto.createVerify HASH_TYPE
      message = Buffer.from payload
      verifier.update message
      resolve verifier.verify publicKeyPem, signature

  ###*
   * Compute an ECDH shared secret.
   *
   * @param {Object} privatePemKey - The private ECDH key in PEM format.
   * @param {Object} otherPublicPemKey - The other public ECDH key in PEM format.
   * @returns {Buffer}
  ###
  computeSecret: (privatePemKey, otherPublicPemKey) =>
    new Promise (resolve, reject) =>
      try
        ecdh = crypto.createECDH CURVE_NAME
        ecdh.setPrivateKey (ecKeyUtils.parsePem(privatePemKey)).privateKey
        resolve ecdh.computeSecret (ecKeyUtils.parsePem(otherPublicPemKey)).publicKey
      catch err
        reject err
