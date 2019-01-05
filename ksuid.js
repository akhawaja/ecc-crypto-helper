(function() {
  var EPOCH, MAX_ENCODED_STRING_LENGTH, MAX_LENGTH, PAYLOAD_MAX_LENGTH, TIMESTAMP_MAX_LENGTH, base62, common, crypto, hkdf;

  EPOCH = 1546300800;

  MAX_ENCODED_STRING_LENGTH = 27;

  TIMESTAMP_MAX_LENGTH = 4;

  PAYLOAD_MAX_LENGTH = 16;

  MAX_LENGTH = TIMESTAMP_MAX_LENGTH + PAYLOAD_MAX_LENGTH;

  base62 = require("./base62");

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
      return new Promise(async(resolve, reject) => {
        var buffer, contents, ikm, payload, timestamp, utc;
        if (unixTimestamp === null) {
          utc = (await common.utcTimestamp());
        } else {
          utc = unixTimestamp;
        }
        ikm = (await common.random());
        payload = (await hkdf.derive(ikm, PAYLOAD_MAX_LENGTH));
        timestamp = Buffer.allocUnsafe(TIMESTAMP_MAX_LENGTH);
        timestamp.writeInt32BE(utc, 0);
        buffer = Buffer.concat([timestamp, payload], MAX_LENGTH);
        contents = (await base62.encode(buffer));
        if (contents.length === MAX_ENCODED_STRING_LENGTH) {
          return resolve(contents);
        } else {
          return resolve(contents.slice(0, MAX_ENCODED_STRING_LENGTH));
        }
      });
    },
    /**
     * Parse a KSUID value and return its component parts.
     *
     * @param {string} ksuidValue - The KSUID value to parse.
     * @returns {Object} The component parts of the KSUID.
     */
    parse: (ksuidValue) => {
      return new Promise(async(resolve, reject) => {
        var buffer, payloadBuffer, timestampBuffer, utc;
        if (ksuidValue.length !== MAX_ENCODED_STRING_LENGTH) {
          reject(new Error("ksuidValue does not appear to be a KSUID."));
        }
        buffer = (await base62.decode(ksuidValue));
        timestampBuffer = buffer.slice(0, TIMESTAMP_MAX_LENGTH);
        payloadBuffer = buffer.slice(TIMESTAMP_MAX_LENGTH, PAYLOAD_MAX_LENGTH);
        utc = timestampBuffer.readInt32BE(0);
        return resolve({
          ksuid: ksuidValue,
          time: new Date(utc * 1000),
          timestamp: utc,
          payload: payloadBuffer
        });
      });
    }
  };

}).call(this);

//# sourceMappingURL=ksuid.js.map
