crypto = require "crypto"

hmac = (digest, text, secret) =>
  new Promise (resolve, reject) =>
    resolve crypto.createHmac(digest, secret).update(text).digest()

module.exports =
  hmac256: (text, secret) =>
    Promise.resolve hmac("sha256", text, secret)

  hmac384: (text, secret) =>
    Promise.resolve hmac("sha384", text, secret)

  hmac512: (text, secret) =>
    Promise.resolve hmac("sha512", text, secret)
