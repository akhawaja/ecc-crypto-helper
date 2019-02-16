const base62 = require('ksuid/base62')

module.exports = {
  /**
   * Encode a buffer to Base62.
   *
   * @param {Buffer} buffer - The buffer to encode.
   * @returns {Promise} The encoded value.
   */
  encode: (buffer) => {
    return new Promise((resolve, reject) => {
      if (!Buffer.isBuffer(buffer)) {
        return reject(new TypeError('Expected buffer to be of type Buffer.'))
      }
      return resolve(base62.encode(buffer))
    })
  },

  /**
   * Decode a Base62 string to its original buffer.
   *
   * @param {string} text - The string to decode.
   * @returns {Promise} The decoded buffer.
   */
  decode: (text) => {
    return new Promise((resolve, reject) => {
      if (typeof text !== 'string') {
        return reject(
          new TypeError(`Expected text to be a string. Received ${text}.`))
      }
      return resolve(base62.decode(text))
    })
  }
}
