crypto = require "crypto"
ecKeyUtils = require "eckey-utils"
common = require "./common"

CURVE_NAME = "secp384r1"
HASH_TYPE = "sha384"

module.exports =
  curveName: CURVE_NAME

  convertPemToJwk: (privateKey, publicKey, privateKeyOps = [], publicKeyOps = []) =>
    if privateKeyOps.length is 0
      privateKeyOps = ["deriveKey", "sign"]

    if publicKeyOps.length is 0
      publicKeyOps = ["verify"]

    new Promise (resolve, reject) =>
      params = {}

      if privateKey isnt undefined and privateKey isnt null
        params.privateKey = privateKey

      if publicKey isnt undefined and publicKey isnt null
        params.publicKey = publicKey

      if params.privateKey is undefined and params.publicKey is undefined
        reject new Error("You must supply at least a private key or public key.")

      jwk = ecKeyUtils.generateJwk CURVE_NAME, params
      kid = (await common.randomString()).toString("hex")

      if jwk.privateKey isnt undefined
        jwk.privateKey.kid = kid
        jwk.privateKey.key_ops = privateKeyOps

      if jwk.publicKey isnt undefined
        jwk.publicKey.kid = kid
        jwk.publicKey.key_ops = publicKeyOps

      resolve jwk

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

  generatePemKeyPair: () =>
    new Promise (resolve, reject) =>
      ecdh = crypto.createECDH CURVE_NAME
      ecdh.generateKeys()
      params =
        privateKey: ecdh.getPrivateKey()
        publicKey: ecdh.getPublicKey()

      resolve ecKeyUtils.generatePem CURVE_NAME, params

  signPayload: (payload, privateKeyPem) =>
    new Promise (resolve, reject) =>
      if typeof payload isnt "string"
        return reject "Payload must be a string."

      signer = crypto.createSign HASH_TYPE
      message = Buffer.from payload
      signer.update message
      resolve signer.sign privateKeyPem

  verifyPayloadSignature: (payload, signature, publicKeyPem) =>
    new Promise (resolve, reject) =>
      if typeof payload isnt "string"
        return reject "Payload must be a string."

      verifier = crypto.createVerify HASH_TYPE
      message = Buffer.from payload
      verifier.update message
      resolve verifier.verify publicKeyPem, signature

  parseJwkToPem: (privateOrPublicJwk) =>
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

  parsePemToJwk: (privateOrPublicPem, privateKeyOps = [], publicKeyOps = []) =>
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

        jwk.privateKey.kid = kid
        jwk.privateKey.key_ops = privateKeyOps

        jwk.publicKey.kid = kid
        jwk.publicKey.key_ops = publicKeyOps

        resolve jwk
      catch err
        reject err

  computeSecret: (privatePemKey, otherPublicPemKey) =>
    new Promise (resolve, reject) =>
      try
        ecdh = crypto.createECDH CURVE_NAME
        ecdh.setPrivateKey (ecKeyUtils.parsePem(privatePemKey)).privateKey
        resolve ecdh.computeSecret (ecKeyUtils.parsePem(otherPublicPemKey)).publicKey
      catch err
        reject err
