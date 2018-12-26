crypto = require "crypto"

module.exports =
  sha256: (text) =>
    new Promise (resolve, reject) =>
      hash = crypto.createHash("sha256")
      resolve hash.update(text).digest()

  sha384: (text) =>
    new Promise (resolve, reject) =>
      hash = crypto.createHash("sha384")
      resolve hash.update(text).digest()

  sha512: (text) =>
    new Promise (resolve, reject) =>
      hash = crypto.createHash("sha512")
      resolve hash.update(text).digest()
