crypto = require "crypto"
common = require "./common"
hkdf = require "./hkdf"

SALT_SIZE = 64
KEY_LENGTH = 64

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
      salt = await common.random SALT_SIZE

    crypto.scrypt plainPassword, salt, KEY_LENGTH, (err, derivedKey) =>
      if err?
        return reject err

      expandedKey = await hkdf.derive(derivedKey, KEY_LENGTH, salt)
      resolve Buffer.concat [salt, expandedKey]

module.exports =
  ###*
   * Hash the password using a combination of Scrypt and HKDF.
   *
   * @param {string} plainPassword - The password to hash.
   * @returns {Buffer} The hashed password.
  ###
  hash: (plainPassword) =>
    Promise.resolve scryptPassword plainPassword

  ###*
   * Verify that the plain password and derivedPassword match.
   *
   * @param {string} plainPassword - The plain password.
   * @param {string|Buffer} derivedPassword - The previously hashed password.
   * @returns {boolean} true if the password is correct; false otherwise.
  ###
  match: (plainPassword, derivedPassword) =>
    new Promise (resolve, reject) =>
      if Buffer.isBuffer derivedPassword
        derivedBuffer = derivedPassword
      else # We assume the string is hex encoded
        derivedBuffer = Buffer.from derivedPassword, "hex"

      salt = derivedBuffer.slice 0, SALT_SIZE
      hash = await scryptPassword plainPassword, salt

      resolve hash.compare(derivedBuffer) is 0
