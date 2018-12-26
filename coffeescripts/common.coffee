crypto = require "crypto"

module.exports =
  randomString: (size = 16) =>
    new Promise (resolve, reject) =>
      buffer = Buffer.alloc size
      crypto.randomFill buffer, (err, result) =>
        if err isnt null and err isnt undefined
          reject err
        else
          resolve result

  randomNumber: (low = 1, high = 100000) =>
    new Promise (resolve, reject) =>
      if low is high
        reject new Error("low number must be greater than high number.")

      resolve Math.floor(Math.random() * (high - low + 1) + low)
