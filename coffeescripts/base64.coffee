module.exports =
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
        reject "Cannot decode non-string value. Found '#{typeof encodedText}'."
