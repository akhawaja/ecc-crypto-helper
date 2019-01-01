jws = require "jws"
base64 = require "./base64"
common = require "./common"

###*
 * Decode a JSON web token into its constituent parts.
 *
 * @param {string} jsonWebToken - The JSON web token.
 * @returns {Object}
###
decode = (jsonWebToken) =>
  new Promise (resolve, reject) =>
    parts = jsonWebToken.split(".")

    if parts.length < 2
      reject new Error("Invalid JSON web token.")

    decoded = {}

    try
      decoded.header = JSON.parse(await base64.urlDecode(parts[0]))
      decoded.payload = JSON.parse(await base64.urlDecode(parts[1]))
    catch err
      reject err

    if parts[2] isnt undefined
      decoded.signature = parts[2]

    resolve decoded

###*
 * Build a JSON web token.
 *
 * @param {string} algorithm - The algorithm to use.
 * @param {string|Buffer} secretOrPrivateKey - The shared secret or an ECDH
 *                                             private key in PEM format.
 * @param {Object} claims - Additional claims supplied by the client.
 * @returns {string}
###
create = (algorithm, secretOrPrivateKey, claims = {}) =>
  new Promise (resolve, reject) =>
    header =
      alg: algorithm
      typ: "JWT"

    if claims.iss is undefined
      claims.iss = "urn:iss:crypto-helper"

    if claims.aud is undefined
      claims.aud = "urn:aud:any-client"

    if claims.exp is undefined
      # Expire in 10-minutes
      claims.exp = Math.round((new Date().getTime()) / 1000) + (60 * 10)

    currentTime = Math.round((new Date().getTime()) / 1000)
    claims.iat = currentTime
    claims.nbf = currentTime
    claims.jti = (await common.randomString()).toString("hex")

    try
      jws.createSign({
        header: header
        payload: claims
        secret: secretOrPrivateKey
      }).on "done", (signature) => resolve signature
    catch err
      reject err

###*
 * Verify a JSON web token. Verifies the expiration and signature.
 *
 * @param {string} algorithm - The algorithm used.
 * @param {string|Buffer} secretOrPublicKey - The shared secret or ECDH public
 *                                            key in PEM format.
 * @param {string} jsonWebToken - The JSON web token to verify.
 * @returns {boolean}
###
verify = (algorithm, secretOrPublicKey, jsonWebToken) =>
  new Promise (resolve, reject) =>
    # Make sure we have a valid JSON Web Token
    if typeof jsonWebToken isnt "string"
      reject new Error("jsonWebToken must be a string.")

    decoded = await decode(jsonWebToken)
    claims = decoded.payload
    currentTime = Math.round new Date().getTime()

    if claims?.exp isnt undefined
      expiration = claims.exp * 1000
      if expiration <= currentTime
        reject new Error("The token has expired.")

    # Validate the signature
    try
      jws.createVerify({
        signature: jsonWebToken
        algorithm: algorithm
        key: secretOrPublicKey
      }).on "done", (verified) => resolve verified
    catch err
      reject err


module.exports =
  decode: decode

  es384:
    create: (privateKey, claims) =>
      Promise.resolve create("ES384", privateKey, claims)

    verify: (publicKey, jsonWebToken) =>
      Promise.resolve verify("ES384", publicKey, jsonWebToken)

  es512:
    create: (privateKey, claims) =>
      Promise.resolve create("ES512", privateKey, claims)

    verify: (publicKey, jsonWebToken) =>
      Promise.resolve verify("ES512", publicKey, jsonWebToken)

  hs384:
    create: (secret, claims) =>
      Promise.resolve create("HS384", secret, claims)

    verify: (secret, jsonWebToken) =>
      Promise.resolve verify("HS384", secret, jsonWebToken)

  hs512:
    create: (secret, claims) =>
      Promise.resolve create("HS512", secret, claims)

    verify: (secret, jsonWebToken) =>
      Promise.resolve verify("HS512", secret, jsonWebToken)
