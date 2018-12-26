(function() {
  var crypto;

  crypto = require("crypto");

  module.exports = {
    sha256: (text) => {
      return new Promise((resolve, reject) => {
        var hash;
        hash = crypto.createHash("sha256");
        return resolve(hash.update(text).digest());
      });
    },
    sha384: (text) => {
      return new Promise((resolve, reject) => {
        var hash;
        hash = crypto.createHash("sha384");
        return resolve(hash.update(text).digest());
      });
    },
    sha512: (text) => {
      return new Promise((resolve, reject) => {
        var hash;
        hash = crypto.createHash("sha512");
        return resolve(hash.update(text).digest());
      });
    }
  };

}).call(this);

//# sourceMappingURL=hash.js.map
