CHARACTERS = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
base62 = require("base-x")(CHARACTERS)

module.exports =
  ###*
   * Encode a buffer to Base62.
   *
   * @param {Buffer} buffer - The buffer to encode.
   * @returns {string} The encoded value.
  ###
  encode: (buffer) =>
    new Promise (resolve, reject) =>
      if !Buffer.isBuffer buffer
        return reject new TypeError "Expected buffer to be of type Buffer."

      resolve base62.encode buffer

  ###*
   * Decode a Base62 string to its original buffer.
   *
   * @param {string} text - The string to decode.
   * @returns {Buffer} The decoded buffer.
  ###
  decode: (text) =>
    new Promise (resolve, reject) =>
      if typeof text isnt "string"
        return reject new TypeError "Expected text to be a string."

      resolve base62.decode text
