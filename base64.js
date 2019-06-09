module.exports = {
  /**
   * Base64 URL encode a given text.
   *
   * @param {Buffer|string} text - The text to encode.
   * @returns {Promise<string>} The encoded text.
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
   * @returns {Promise<Buffer>} The decoded text.
   */
  urlDecode: (encodedText) => {
    return new Promise((resolve, reject) => {
      let encoded

      if (typeof encodedText === 'string') {
        encodedText += Array(5 - encodedText.length % 4).join('=')
        encoded = encodedText.replace('-', '+').replace('_', '/')

        return resolve(Buffer.from(encoded, 'base64'))
      } else {
        return reject(new TypeError(
          `Cannot decode non-string value. Found '${typeof encodedText}'.`))
      }
    })
  }
}
