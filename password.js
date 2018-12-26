(function() {
  var common, crypto, scryptPassword;

  crypto = require("crypto");

  common = require("./common");

  scryptPassword = (plainPassword, salt = null) => {
    return new Promise(async(resolve, reject) => {
      if (salt === null) {
        salt = (await common.randomString(32));
      }
      return crypto.scrypt(plainPassword, salt, 64, (err, derivedKey) => {
        if (err !== null && err !== void 0) {
          return reject(err);
        }
        return resolve(Buffer.concat([salt, derivedKey]));
      });
    });
  };

  module.exports = {
    hash: (plainPassword) => {
      return Promise.resolve(scryptPassword(plainPassword));
    },
    match: (plainPassword, derivedPassword) => {
      return new Promise(async(resolve, reject) => {
        var derivedBuffer, hash, salt;
        if (Buffer.isBuffer(derivedPassword)) {
          derivedBuffer = derivedPassword;
        } else {
          derivedBuffer = Buffer.from(derivedPassword, "hex");
        }
        salt = derivedBuffer.slice(0, 32);
        hash = (await scryptPassword(plainPassword, salt));
        return resolve(Buffer.compare(hash, derivedBuffer) === 0);
      });
    }
  };

}).call(this);

//# sourceMappingURL=password.js.map
