(function() {
  var common;

  common = require("./common");

  module.exports = {
    derive: (ikm, size, salt = null, info = null) => {
      var hkdf;
      hkdf = require("futoin-hkdf");
      return new Promise(async(resolve, reject) => {
        var err;
        if (salt === null || salt === void 0) {
          salt = (await common.randomString(32));
        }
        try {
          return resolve(hkdf(ikm, size, salt, info, "SHA-512"));
        } catch (error) {
          err = error;
          return reject(err);
        }
      });
    }
  };

}).call(this);

//# sourceMappingURL=hkdf.js.map
