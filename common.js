(function() {
  var crypto;

  crypto = require("crypto");

  module.exports = {
    /**
     * Generate a random string.
     *
     * @param {number} size - The length of the random string to generate.
     * @returns {string} The random string.
     */
    randomString: (size = 16) => {
      return new Promise((resolve, reject) => {
        var buffer;
        buffer = Buffer.alloc(size);
        return crypto.randomFill(buffer, (err, result) => {
          if (err !== null && err !== void 0) {
            return reject(err);
          } else {
            return resolve(result);
          }
        });
      });
    },
    /**
     * Generate a random number between a range.
     *
     * @param {number} low - The starting range.
     * @param {number} high - The ending range.
     * @returns {number} The random number.
     */
    randomNumber: (low = 1, high = 100000) => {
      return new Promise((resolve, reject) => {
        if (low === high) {
          reject(new Error("low number must be greater than high number."));
        }
        return resolve(Math.floor(Math.random() * (high - low + 1) + low));
      });
    }
  };

}).call(this);

//# sourceMappingURL=common.js.map
