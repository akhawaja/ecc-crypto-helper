crypto = require "crypto"
common = require "./common"
hkdf = require "./hkdf"

ITERATIONS = 10000
KEY_LENGTH = 32 # AES-GCM-256 requires a 32-bytes key length
DIGEST = "sha512"
CIPHER = "aes-256-gcm"
SALT_SIZE = 64
AUTH_TAG_SIZE = 16
IV_SIZE = 12 # A 12-bytes (96-bit initialization vector) is recommended for AES-GCM-256

module.exports =
  ###*
   * Encrypt a string using a secret.
   *
   * @param {string} text - The text to encrypt.
   * @param {string|Buffer} secret - The secret to use for decryption.
   * @returns {Buffer} The cipher text.
  ###
  encrypt: (text, secret) =>
    new Promise (resolve, reject) =>
      if typeof text isnt "string"
        reject new Error "text to encrypt must be a string."

      masterKey = null

      # We will presume that the secret is cryptographically strong
      if Buffer.isBuffer secret
        masterKey = secret
      else if typeof secret is "string"
        masterKey = Buffer.from secret
      else
        return reject "secret should be either a String or Buffer. Found '#{typeof secret}'."

      salt = await common.random SALT_SIZE
      iv = await common.random IV_SIZE

      crypto.pbkdf2 masterKey, salt, ITERATIONS, KEY_LENGTH, DIGEST, (err, derivedKey) =>
        if err?
          return reject err

        expandedKey = await hkdf.derive derivedKey, KEY_LENGTH, salt
        cipher = crypto.createCipheriv CIPHER, expandedKey, iv
        cipherText = Buffer.concat [cipher.update(text, "utf8"), cipher.final()]
        authTag = cipher.getAuthTag()
        resolve Buffer.concat [salt, iv, authTag, cipherText]

  ###*
   * Decrypt a previously encrypted text.
   *
   * @param {string|Buffer} cipherText - The encrypted text.
   * @param {string|Buffer} secret - The secret to use for decryption.
   * @returns {string} The decrypted text.
  ###
  decrypt: (cipherText, secret) =>
    new Promise (resolve, reject) =>
      masterKey = null
      cipherTextBuffer = null

      if typeof cipherText is "string"
        cipherTextBuffer = Buffer.from cipherText
      if Buffer.isBuffer cipherText
        cipherTextBuffer = cipherText
      else
        return reject new Error("cipherText should be a Buffer or string. Found '#{typeof cipherTextBuffer}'.")

      if Buffer.isBuffer secret
        masterKey = secret
      else if typeof secret is "string"
        masterKey = Buffer.from secret
      else
        return reject "secret should be either a String or Buffer. Found '#{typeof secret}'."

      salt = cipherTextBuffer.slice 0, SALT_SIZE
      iv = cipherTextBuffer.slice SALT_SIZE, SALT_SIZE + IV_SIZE
      authTag = cipherTextBuffer.slice SALT_SIZE + IV_SIZE, SALT_SIZE + IV_SIZE + AUTH_TAG_SIZE
      cipherText = cipherTextBuffer.slice SALT_SIZE + IV_SIZE + AUTH_TAG_SIZE
      crypto.pbkdf2 masterKey, salt, ITERATIONS, KEY_LENGTH, DIGEST, (err, derivedKey) =>
        expandedKey = await hkdf.derive derivedKey, KEY_LENGTH, salt
        cipher = crypto.createDecipheriv CIPHER, expandedKey, iv
        cipher.setAuthTag authTag
        text = cipher.update(cipherText, "binary", "utf8") + cipher.final("utf8")
        resolve text
