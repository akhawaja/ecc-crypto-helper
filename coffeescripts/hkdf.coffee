common = require "./common"

module.exports =
  derive: (ikm, size, salt = null, info = null) =>
    hkdf = require "futoin-hkdf"

    new Promise (resolve, reject) =>
      if salt is null or salt is undefined
        salt = await common.randomString(32)

      try
        resolve hkdf(ikm, size, salt, info, "SHA-512")
      catch err
        reject err
