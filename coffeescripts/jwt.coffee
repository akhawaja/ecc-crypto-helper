jws = require "jws"
base64 = require "./base64"
common = require "./common"

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
      resolve jws.sign({
        header: header
        payload: claims
        secret: secretOrPrivateKey
      })
    catch err
      reject err

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
      resolve jws.verify(jsonWebToken, algorithm, secretOrPublicKey)
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
