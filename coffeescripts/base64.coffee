module.exports =
  ###*
   * Base64 URL encode a given text.
   *
   * @param {string} text - The text to encode.
   * @returns {string} The encoded text.
  ###
  urlEncode: (text) =>
    new Promise (resolve, reject) =>
      if Buffer.isBuffer text
        encoded = text.toString "base64"
      else
        encoded = Buffer.from(text, "utf8").toString("base64")

      encoded = encoded
        .replace("+", "-")
        .replace("/", "_")
        .replace(/=+$/, "")

      resolve encoded

  ###*
   * Base64 URL decode a given text.
   *
   * @param {string} text - The text to decode.
   * @returns {string} The decoded text.
  ###
  urlDecode: (encodedText) =>
    new Promise (resolve, reject) =>
      if typeof encodedText is "string"
        encoded = encodedText
          .replace("-", "+")
          .replace("_", "/")

        while encoded.length % 4
          encoded += "=";

        resolve Buffer.from(encoded, "base64").toString("utf-8")
      else
        reject new TypeError "Cannot decode non-string value. Found '#{typeof encodedText}'."
