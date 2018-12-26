(function() {
  var common, crypto;

  crypto = require("crypto");

  common = require("./common");

  module.exports = {
    encrypt: (text, secret) => {
      return new Promise(async(resolve, reject) => {
        var iv, masterKey, salt;
        masterKey = null;
        // We will presume that the secret is cryptographically strong
        if (Buffer.isBuffer(secret)) {
          masterKey = secret;
        } else if (typeof secret === "string") {
          masterKey = Buffer.from(secret);
        } else {
          return reject(`secret should be either a String or Buffer. Found '${typeof secret}'.`);
        }
        salt = (await common.randomString(64));
        iv = (await common.randomString(16));
        return crypto.pbkdf2(masterKey, salt, 10000, 32, "sha512", (err, derivedKey) => {
          var authTag, cipher, cipherText;
          if (err != null) {
            return reject(err);
          }
          cipher = crypto.createCipheriv("aes-256-gcm", derivedKey, iv);
          cipherText = Buffer.concat([cipher.update(text, "utf8"), cipher.final()]);
          authTag = cipher.getAuthTag();
          return resolve(Buffer.concat([salt, iv, authTag, cipherText]));
        });
      });
    },
    decrypt: (cipherTextBuffer, secret) => {
      return new Promise((resolve, reject) => {
        var authTag, cipherText, iv, masterKey, salt;
        masterKey = null;
        if (false === Buffer.isBuffer(cipherTextBuffer)) {
          return reject(`cipherTextBuffer should be of type Buffer. Found '${typeof cipherTextBuffer}'.`);
        }
        if (Buffer.isBuffer(secret)) {
          masterKey = secret;
        } else if (typeof secret === "string") {
          masterKey = Buffer.from(secret);
        } else {
          return reject(`secret should be either a String or Buffer. Found '${typeof secret}'.`);
        }
        salt = cipherTextBuffer.slice(0, 64);
        iv = cipherTextBuffer.slice(64, 80);
        authTag = cipherTextBuffer.slice(80, 96);
        cipherText = cipherTextBuffer.slice(96);
        return crypto.pbkdf2(masterKey, salt, 10000, 32, "sha512", (err, derivedKey) => {
          var cipher, text;
          cipher = crypto.createDecipheriv("aes-256-gcm", derivedKey, iv);
          cipher.setAuthTag(authTag);
          text = cipher.update(cipherText, "binary", "utf8") + cipher.final("utf8");
          return resolve(text);
        });
      });
    }
  };

}).call(this);

//# sourceMappingURL=aesgcm256.js.map
