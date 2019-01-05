crypto = require "crypto"

module.exports =
  ###*
   * Generate a random value.
   *
   * @param {number} size - The length of the random value to generate.
   * @returns {Buffer} The random value.
  ###
  random: (size = 16) =>
    new Promise (resolve, reject) =>
      buffer = Buffer.alloc size
      crypto.randomFill buffer, (err, result) =>
        if err isnt null and err isnt undefined
          reject err
        else
          resolve result

  ###*
   * Generate a random number between a range.
   *
   * @param {number} low - The starting range.
   * @param {number} high - The ending range.
   * @returns {number} The random number.
  ###
  randomNumber: (low = 1, high = 100000) =>
    new Promise (resolve, reject) =>
      if low is high
        reject new Error("low number must be greater than high number.")

      resolve Math.floor(Math.random() * (high - low + 1) + low)

  ###*
   * Generate a UTC UNIX timestamp in seconds.
   *
   * @returns {number} The UTC time as a UNIX timestamp.
  ###
  utcTimestamp: () =>
    new Promise (resolve, reject) =>
      now = new Date()
      resolve Math.floor((now.getTime() + now.getTimezoneOffset() * (60 * 1000)) / 1000)
