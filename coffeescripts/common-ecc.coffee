crypto = require "crypto"
ecKeyUtils = require "eckey-utils"
base64 = require "./base64"
common = require "./common"
ksuid = require "./ksuid"

###*
 * Generate a key identifier suitable for use as a `kid` in a JSON Web Key.
 *
 * @param {Object} jwk - The JSON Web Key for which a `kid` is going to be generated.
 * @returns {string} The key identifier.
###
generateKeyIdentifier = (jwk) =>
  new Promise (resolve, reject) =>
    if jwk?.publicKey?.x?
      buffer = Buffer.from(await base64.urlDecode(jwk.publicKey.x))
      resolve buffer.slice(0, 4).toString("hex")
    else
      reject new Error "Invalid JSON Web Key supplied."

module.exports =
  ###*
   * Convert a PEM certificate to a JSON Web Key.
   *
   * @param {string} curveName - The type of ECC curve.
   * @param {string|Buffer} privateOrPublicPem - The private or public PEM key.
   * @param {Array} privateKeyOps - The operations intended for the private key.
   * @param {Array} publicKeyOps - The operations intended for the public key.
   * @returns {Object} The converted certificate.
  ###
  convertPemToJwk: (curveName, privateOrPublicPem, privateKeyOps = [], publicKeyOps = []) =>
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

        jwk = ecKeyUtils.generateJwk(curveName, parsed)
        kid = await generateKeyIdentifier(jwk)

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
   * @param {string} curveName - The type of ECC curve.
   * @param {string|Buffer} privateOrPublicJwk - The private or public JSON Web Key.
   * @returns {Object} The converted certificate.
  ###
  convertJwkToPem: (curveName, privateOrPublicJwk) =>
    new Promise (resolve, reject) =>
      try
        parsed = ecKeyUtils.parseJwk(privateOrPublicJwk)
        params = {}

        if parsed.privateKey isnt undefined and parsed.privateKey isnt null
          params.privateKey = parsed.privateKey

        if parsed.publicKey isnt undefined and parsed.publicKey isnt null
          params.publicKey = parsed.publicKey

        resolve ecKeyUtils.generatePem(curveName, params)
      catch err
        reject err

  ###*
   * Generate an ECDH key pair as a JSON Web Key.
   *
   * @param {string} curveName - The type of ECC curve.
   * @param {Array} privateKeyOps - The operations intended for the private key.
   * @param {Array} publicKeyOps - The operations intended for the public key.
   * @returns {string} The ECDH key pair.
  ###
  generateJwkKeyPair: (curveName, privateKeyOps = [], publicKeyOps = []) =>
    if privateKeyOps.length is 0
      privateKeyOps = ["deriveKey", "sign"]

    if publicKeyOps.length is 0
      publicKeyOps = ["verify"]

    new Promise (resolve, reject) =>
      ecdh = crypto.createECDH curveName
      ecdh.generateKeys()
      params =
        privateKey: ecdh.getPrivateKey()
        publicKey: ecdh.getPublicKey()

      jwk = ecKeyUtils.generateJwk curveName, params
      kid = await generateKeyIdentifier(jwk)

      jwk.privateKey.kid = kid
      jwk.privateKey.key_ops = privateKeyOps

      jwk.publicKey.kid = kid
      jwk.publicKey.key_ops = publicKeyOps

      resolve jwk

  ###*
   * Generate an ECDH key pair as PEM certificates.
   *
   * @param {string} curveName - The type of ECC curve.
   * @returns {Object} The PEM certificates.
  ###
  generatePemKeyPair: (curveName) =>
    new Promise (resolve, reject) =>
      ecdh = crypto.createECDH curveName
      ecdh.generateKeys()
      params =
        privateKey: ecdh.getPrivateKey()
        publicKey: ecdh.getPublicKey()

      resolve ecKeyUtils.generatePem curveName, params

  ###*
   * Sign a payload to prevent it from tamper.
   *
   * @param {string} payload - The payload to sign.
   * @param {string} privateKeyPem - The private key in PEM format.
   * @param {string} hashType - The type of SHA2 digest to use. Defaults to SHA-256.
   * @returns {Buffer} The signature for the payload.
  ###
  signPayload: (payload, privateKeyPem, hashType = "sha256") =>
    new Promise (resolve, reject) =>
      if typeof payload isnt "string"
        return reject "Payload must be a string."

      signer = crypto.createSign hashType
      message = Buffer.from payload
      signer.update message
      resolve signer.sign privateKeyPem

  ###*
   * Verify the signature of a given payload.
   *
   * @param {string} payload - The payload against which the signature will be checked.
   * @param {string|Buffer} signature - The signature of the payload.
   * @param {Object} publicPemKey - The public ECDH key in PEM format.
   * @param {string} hashType - The type of SHA2 digest to use. Defaults to SHA-256.
   * @returns {boolean}
  ###
  verifyPayloadSignature: (payload, signature, publicKeyPem, hashType = "sha256") =>
    new Promise (resolve, reject) =>
      if typeof payload isnt "string"
        return reject "Payload must be a string."

      verifier = crypto.createVerify hashType
      message = Buffer.from payload
      verifier.update message
      resolve verifier.verify publicKeyPem, signature

  ###*
   * Compute an ECDH shared secret.
   *
   * @param {string} curveName - The type of ECC curve.
   * @param {Object} privatePemKey - The private ECDH key in PEM format.
   * @param {Object} otherPublicPemKey - The other public ECDH key in PEM format.
   * @returns {Buffer}
  ###
  computeSecret: (curveName, privatePemKey, otherPublicPemKey) =>
    new Promise (resolve, reject) =>
      try
        ecdh = crypto.createECDH curveName
        ecdh.setPrivateKey (ecKeyUtils.parsePem(privatePemKey)).privateKey
        resolve ecdh.computeSecret (ecKeyUtils.parsePem(otherPublicPemKey)).publicKey
      catch err
        reject err
