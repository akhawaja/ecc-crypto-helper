(function() {
  module.exports = {
    urlEncode: (text) => {
      return new Promise((resolve, reject) => {
        var encoded;
        if (Buffer.isBuffer(text)) {
          encoded = text.toString("base64");
        } else {
          encoded = Buffer.from(text, "utf8").toString("base64");
        }
        encoded = encoded.replace("+", "-").replace("/", "_").replace(/=+$/, "");
        return resolve(encoded);
      });
    },
    urlDecode: (encodedText) => {
      return new Promise((resolve, reject) => {
        var encoded;
        if (typeof encodedText === "string") {
          encoded = encodedText.replace("-", "+").replace("_", "/");
          while (encoded.length % 4) {
            encoded += "=";
          }
          return resolve(Buffer.from(encoded, "base64").toString("utf-8"));
        } else {
          return reject(`Cannot decode non-string value. Found '${typeof encodedText}'.`);
        }
      });
    }
  };

}).call(this);

//# sourceMappingURL=base64.js.map
