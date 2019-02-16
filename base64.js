module.exports = {
  /**
   * Base64 URL encode a given text.
   *
   * @param {string} text - The text to encode.
   * @returns {Promise} The encoded text.
   */
  urlEncode: (text) => {
    return new Promise((resolve, reject) => {
      let encoded

      if (Buffer.isBuffer(text)) {
        encoded = text.toString('base64')
      } else {
        encoded = Buffer.from(text, 'utf8').toString('base64')
      }

      encoded = encoded.replace('+', '-').replace('/', '_').replace(/=+$/, '')

      return resolve(encoded)
    })
  },
  /**
   * Base64 URL decode a given text.
   *
   * @param {string} encodedText - The Base64 encoded text.
   * @returns {Promise} The decoded text.
   */
  urlDecode: (encodedText) => {
    return new Promise((resolve, reject) => {
      var encoded
      if (typeof encodedText === 'string') {
        encoded = encodedText.replace('-', '+').replace('_', '/')
        while (encoded.length % 4) {
          encoded += '='
        }
        return resolve(Buffer.from(encoded, 'base64').toString('utf-8'))
      } else {
        return reject(new TypeError(
          `Cannot decode non-string value. Found '${typeof encodedText}'.`))
      }
    })
  }
}
