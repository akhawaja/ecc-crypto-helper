crypto = require "crypto"
common = require "./common"

module.exports =
  encrypt: (text, secret) =>
    new Promise (resolve, reject) =>
      masterKey = null

      # We will presume that the secret is cryptographically strong
      if Buffer.isBuffer secret
        masterKey = secret
      else if typeof secret is "string"
        masterKey = Buffer.from secret
      else
        return reject "secret should be either a String or Buffer. Found '#{typeof secret}'."

      salt = await common.randomString 64
      iv = await common.randomString 16

      crypto.pbkdf2 masterKey, salt, 10000, 32, "sha512", (err, derivedKey) =>
        if err?
          return reject err

        cipher = crypto.createCipheriv "aes-256-gcm", derivedKey, iv
        cipherText = Buffer.concat [cipher.update(text, "utf8"), cipher.final()]
        authTag = cipher.getAuthTag()
        resolve Buffer.concat [salt, iv, authTag, cipherText]

  decrypt: (cipherTextBuffer, secret) =>
    new Promise (resolve, reject) =>
      masterKey = null

      if false is Buffer.isBuffer cipherTextBuffer
        return reject "cipherTextBuffer should be of type Buffer. Found '#{typeof cipherTextBuffer}'."

      if Buffer.isBuffer secret
        masterKey = secret
      else if typeof secret is "string"
        masterKey = Buffer.from secret
      else
        return reject "secret should be either a String or Buffer. Found '#{typeof secret}'."

      salt = cipherTextBuffer.slice 0, 64
      iv = cipherTextBuffer.slice 64, 80
      authTag = cipherTextBuffer.slice 80, 96
      cipherText = cipherTextBuffer.slice 96
      crypto.pbkdf2 masterKey, salt, 10000, 32, "sha512", (err, derivedKey) =>
        cipher = crypto.createDecipheriv "aes-256-gcm", derivedKey, iv
        cipher.setAuthTag authTag
        text = cipher.update(cipherText, "binary", "utf8") + cipher.final("utf8")
        resolve text
