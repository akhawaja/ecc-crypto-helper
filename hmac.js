(function() {
  var crypto, hmac;

  crypto = require("crypto");

  hmac = (digest, text, secret) => {
    return new Promise((resolve, reject) => {
      return resolve(crypto.createHmac(digest, secret).update(text).digest());
    });
  };

  module.exports = {
    hmac256: (text, secret) => {
      return Promise.resolve(hmac("sha256", text, secret));
    },
    hmac384: (text, secret) => {
      return Promise.resolve(hmac("sha384", text, secret));
    },
    hmac512: (text, secret) => {
      return Promise.resolve(hmac("sha512", text, secret));
    }
  };

}).call(this);

//# sourceMappingURL=hmac.js.map
