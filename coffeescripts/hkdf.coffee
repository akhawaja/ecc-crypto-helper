common = require "./common"

module.exports =
  ###*
   * Derive a cryptographically strong set of values using the contraction and
   * expansion method of HKDF.
   *
   * @param {string} ikm - The initial key material. A shared secret or some
   *                       other random value you know about.
   * @param {number} size - The number of bytes to derive.
   * @param {string} salt - Additional entropy.
   * @param {string} info - Additional entropy to bind the bytes derived to a
   *                        specific entity.
   * @returns {Buffer}
  ###
  derive: (ikm, size, salt = null, info = null) =>
    hkdf = require "futoin-hkdf"

    new Promise (resolve, reject) =>
      if salt is null or salt is undefined
        salt = await common.randomString(32)

      try
        resolve hkdf(ikm, size, salt, info, "SHA-512")
      catch err
        reject err
