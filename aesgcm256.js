(function() {
  var CIPHER, DIGEST, ITERATIONS, KEY_LENGTH, common, crypto;

  crypto = require("crypto");

  common = require("./common");

  ITERATIONS = 10000;

  KEY_LENGTH = 32; // AES-GCM-256 requires a 32-bytes key length

  DIGEST = "sha512";

  CIPHER = "aes-256-gcm";

  module.exports = {
    /**
     * Encrypt a string using a secret.
     *
     * @param {string} text - The text to encrypt.
     * @param {string|Buffer} secret - The secret to use for decryption.
     * @returns {Buffer} The cipher text.
     */
    encrypt: (text, secret) => {
      return new Promise(async(resolve, reject) => {
        var iv, masterKey, salt;
        if (typeof text !== "string") {
          reject(new Error("text to encrypt must be a string."));
        }
        masterKey = null;
        // We will presume that the secret is cryptographically strong
        if (Buffer.isBuffer(secret)) {
          masterKey = secret;
        } else if (typeof secret === "string") {
          masterKey = Buffer.from(secret);
        } else {
          return reject(`secret should be either a String or Buffer. Found '${typeof secret}'.`);
        }
        salt = (await common.random(64));
        iv = (await common.random(12)); // A 12-bytes (96-bit initialization vector) is recommended for AES-GCM-256
        return crypto.pbkdf2(masterKey, salt, ITERATIONS, KEY_LENGTH, DIGEST, (err, derivedKey) => {
          var authTag, cipher, cipherText;
          if (err != null) {
            return reject(err);
          }
          cipher = crypto.createCipheriv(CIPHER, derivedKey, iv);
          cipherText = Buffer.concat([cipher.update(text, "utf8"), cipher.final()]);
          authTag = cipher.getAuthTag();
          return resolve(Buffer.concat([salt, iv, authTag, cipherText]));
        });
      });
    },
    /**
     * Decrypt a previously encrypted text.
     *
     * @param {string|Buffer} cipherText - The encrypted text.
     * @param {string|Buffer} secret - The secret to use for decryption.
     * @returns {string} The decrypted text.
     */
    decrypt: (cipherText, secret) => {
      return new Promise((resolve, reject) => {
        var authTag, cipherTextBuffer, iv, masterKey, salt;
        masterKey = null;
        cipherTextBuffer = null;
        if (typeof cipherText === "string") {
          cipherTextBuffer = Buffer.from(cipherText);
        }
        if (Buffer.isBuffer(cipherText)) {
          cipherTextBuffer = cipherText;
        } else {
          return reject(new Error(`cipherText should be a Buffer or string. Found '${typeof cipherTextBuffer}'.`));
        }
        if (Buffer.isBuffer(secret)) {
          masterKey = secret;
        } else if (typeof secret === "string") {
          masterKey = Buffer.from(secret);
        } else {
          return reject(`secret should be either a String or Buffer. Found '${typeof secret}'.`);
        }
        salt = cipherTextBuffer.slice(0, 64);
        iv = cipherTextBuffer.slice(64, 76);
        authTag = cipherTextBuffer.slice(76, 92);
        cipherText = cipherTextBuffer.slice(92);
        return crypto.pbkdf2(masterKey, salt, ITERATIONS, KEY_LENGTH, DIGEST, (err, derivedKey) => {
          var cipher, text;
          cipher = crypto.createDecipheriv(CIPHER, derivedKey, iv);
          cipher.setAuthTag(authTag);
          text = cipher.update(cipherText, "binary", "utf8") + cipher.final("utf8");
          return resolve(text);
        });
      });
    }
  };

}).call(this);

//# sourceMappingURL=aesgcm256.js.map
