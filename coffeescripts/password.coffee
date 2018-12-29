crypto = require "crypto"
common = require "./common"

###*
 * Hash the password using the Scrypt algorithm.
 *
 * @param {string} plainPassword - The password to hash.
 * @param {string} salt - Additional entropy to use when hashing the password.
 * @returns {Buffer}
###
scryptPassword = (plainPassword, salt = null) =>
  new Promise (resolve, reject) =>
    if salt is null
      salt = await common.randomString(32)

    crypto.scrypt plainPassword, salt, 64, (err, derivedKey) =>
      if err isnt null and err isnt undefined
        return reject err

      resolve Buffer.concat [salt, derivedKey]

module.exports =
  hash: (plainPassword) =>
    Promise.resolve scryptPassword(plainPassword)

  match: (plainPassword, derivedPassword) =>
    new Promise (resolve, reject) =>
      if Buffer.isBuffer derivedPassword
        derivedBuffer = derivedPassword
      else # We assume the string is hex encoded
        derivedBuffer = Buffer.from derivedPassword, "hex"

      salt = derivedBuffer.slice 0, 32
      hash = await scryptPassword(plainPassword, salt)

      resolve Buffer.compare(hash, derivedBuffer) is 0
