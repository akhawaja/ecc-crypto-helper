(function() {
  var EPOCH, MAX_ENCODED_STRING_LENGTH, MAX_LENGTH, PAYLOAD_MAX_LENGTH, TIMESTAMP_MAX_LENGTH, common, crypto, hkdf, ksuid;

  EPOCH = 14e11;

  MAX_ENCODED_STRING_LENGTH = 27;

  TIMESTAMP_MAX_LENGTH = 4;

  PAYLOAD_MAX_LENGTH = 16;

  MAX_LENGTH = TIMESTAMP_MAX_LENGTH + PAYLOAD_MAX_LENGTH;

  ksuid = require("ksuid");

  crypto = require("crypto");

  common = require("./common");

  hkdf = require("./hkdf");

  module.exports = {
    /**
     * Create a new KSUID.
     *
     * @param {number} unixTimestamp - The UNIX timestamp to use.
     * @returns {string} The KSUID value.
     */
    create: (unixTimestamp = null) => {
      return new Promise(async(resolve) => {
        var identifier, ikm, payload, utc;
        if (unixTimestamp === null) {
          utc = (await common.utcTimestamp());
        } else {
          utc = unixTimestamp;
        }
        ikm = (await common.random(32));
        payload = (await hkdf.derive(ikm, PAYLOAD_MAX_LENGTH));
        identifier = ksuid.fromParts(utc * 1000, payload);
        return resolve(identifier.string);
      });
    },
    /**
     * Parse a KSUID value and return its component parts.
     *
     * @param {string} ksuidValue - The KSUID value to parse.
     * @returns {Object} The component parts of the KSUID.
     */
    parse: (ksuidValue) => {
      return new Promise((resolve, reject) => {
        var parsedIdentifier;
        if (ksuidValue.length !== MAX_ENCODED_STRING_LENGTH) {
          reject(new Error("ksuidValue does not appear to be a KSUID."));
        }
        parsedIdentifier = ksuid.parse(ksuidValue);
        return resolve({
          ksuid: ksuidValue,
          time: parsedIdentifier.date,
          timestamp: parsedIdentifier.timestamp,
          payload: parsedIdentifier.payload
        });
      });
    }
  };

}).call(this);

//# sourceMappingURL=ksuid.js.map
