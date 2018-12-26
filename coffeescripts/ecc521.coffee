crypto = require "crypto"
ecKeyUtils = require "eckey-utils"
common = require "./common"

CURVE_NAME = "secp521r1"
HASH_TYPE = "sha512"

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

  signPayload: (payload, privateKeyJwk) =>
    new Promise (resolve, reject) =>
      if typeof payload isnt "string"
        return reject "Payload must be a string."

      jwk = ecKeyUtils.parseJwk privateKeyJwk
      pems = ecKeyUtils.generatePem CURVE_NAME, {privateKey: jwk.privateKey, publicKey: jwk.publicKey}
      signer = crypto.createSign HASH_TYPE
      message = Buffer.from payload
      signer.update message
      resolve signer.sign pems.privateKey

  verifyPayloadSignature: (payload, signature, publicKeyJwk) =>
    new Promise (resolve, reject) =>
      if typeof payload isnt "string"
        return reject "Payload must be a string."

      jwk = ecKeyUtils.parseJwk publicKeyJwk
      pems = ecKeyUtils.generatePem CURVE_NAME, {publicKey: jwk.publicKey}
      verifier = crypto.createVerify HASH_TYPE
      message = Buffer.from payload
      verifier.update message
      resolve verifier.verify pems.publicKey, signature

  parseJwkToPem: (privateOrPublicJwk) =>
    new Promise (resolve, reject) =>
      resolve ecKeyUtils.parseJwk(privateOrPublicJwk)

  computeSecret: (privatePemKey, otherPublicPemKey) =>
    new Promise (resolve, reject) =>
      try
        ecdh = crypto.createECDH CURVE_NAME
        ecdh.setPrivateKey (ecKeyUtils.parsePem(privatePemKey)).privateKey
        resolve ecdh.computeSecret (ecKeyUtils.parsePem(otherPublicPemKey)).publicKey
      catch err
        reject err
