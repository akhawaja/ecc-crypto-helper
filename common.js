const crypto = require('crypto')

module.exports = {
  /**
   * Generate a random value.
   *
   * @param {number} [size=16] - The length of the random value to generate.
   * @returns {Promise<Buffer>} The random value.
   */
  random: (size = 16) => {
    return new Promise((resolve, reject) => {
      let buffer = Buffer.alloc(size)

      return crypto.randomFill(buffer, (err, result) => {
        if (err !== null && err !== void 0) {
          return reject(err)
        } else {
          return resolve(result)
        }
      })
    })
  },

  /**
   * Generate a random number between a range.
   *
   * @param {number} [low=1 - The starting range.
   * @param {number} [high=100000] - The ending range.
   * @returns {Promise<number>} The random number.
   */
  randomNumber: (low = 1, high = 100000) => {
    return new Promise((resolve, reject) => {
      if (low >= high) {
        reject(new Error('low number must be less than high number.'))
      }

      return resolve(Math.floor(Math.random() * (high - low + 1) + low))
    })
  },

  /**
   * Generate a UTC UNIX timestamp in seconds.
   *
   * @returns {Promise<number>} The UTC time as a UNIX timestamp.
   */
  utcTimestamp: () => {
    return new Promise((resolve, reject) => {
      const now = new Date()

      return resolve(Math.floor(
        (now.getTime() + now.getTimezoneOffset() * (60 * 1000)) / 1000))
    })
  },

  /**
   * Get a Date object in the UTC timezone.
   *
   * @returns {Promise<Date>}
   */
  utcDate: () => {
    return new Promise((resolve, reject) => {
      const now = new Date()
      return resolve(
        new Date(now.getTime() + (now.getTimezoneOffset() * 60000)))
    })
  }
}
