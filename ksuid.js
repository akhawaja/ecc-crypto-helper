const MAX_ENCODED_STRING_LENGTH = 27
const PAYLOAD_MAX_LENGTH = 16
const ksuid = require('ksuid')
const common = require('./common')
const hkdf = require('./hkdf')

module.exports = {
  /**
   * Create a new KSUID.
   *
   * @param {number} unixTimestamp - The UNIX timestamp to use.
   * @returns {Promise} The KSUID value.
   */
  create: (unixTimestamp = null) => {
    return new Promise(async (resolve) => {
      let utc

      if (unixTimestamp === null) {
        utc = (await common.utcTimestamp())
      } else {
        utc = unixTimestamp
      }
      const ikm = await common.random(32)
      const payload = await hkdf.derive(ikm, PAYLOAD_MAX_LENGTH)
      const identifier = ksuid.fromParts(utc * 1000, payload)
      return resolve(identifier.string)
    })
  },

  /**
   * Parse a KSUID value and return its component parts.
   *
   * @param {string} ksuidValue - The KSUID value to parse.
   * @returns {Promise} The component parts of the KSUID.
   */
  parse: (ksuidValue) => {
    return new Promise((resolve, reject) => {
      if (ksuidValue.length !== MAX_ENCODED_STRING_LENGTH) {
        reject(new Error('ksuidValue does not appear to be a KSUID.'))
      }

      const parsedIdentifier = ksuid.parse(ksuidValue)

      return resolve({
        ksuid: ksuidValue,
        time: parsedIdentifier.date,
        timestamp: parsedIdentifier.timestamp,
        payload: parsedIdentifier.payload
      })
    })
  }
}
