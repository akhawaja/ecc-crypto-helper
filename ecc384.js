(function() {
  var CURVE_NAME, HASH_TYPE, commonEcc;

  commonEcc = require("./common-ecc");

  CURVE_NAME = "secp384r1";

  HASH_TYPE = "sha384";

  module.exports = {
    curveName: CURVE_NAME,
    /**
     * Convert a PEM certificate to a JSON Web Key.
     *
     * @param {string|Buffer} privateOrPublicPem - The private or public PEM key.
     * @param {Array} privateKeyOps - The operations intended for the private key.
     * @param {Array} publicKeyOps - The operations intended for the public key.
     * @returns {Object} The converted certificate.
     */
    convertPemToJwk: (privateOrPublicPem, privateKeyOps = [], publicKeyOps = []) => {
      return Promise.resolve(commonEcc.convertPemToJwk(CURVE_NAME, privateOrPublicPem, privateKeyOps, publicKeyOps));
    },
    /**
     * Convert a JSON Web Key to a PEM certificate.
     *
     * @param {string|Buffer} privateOrPublicJwk - The private or public JSON Web Key.
     * @returns {Object} The converted certificate.
     */
    convertJwkToPem: (privateOrPublicJwk) => {
      return Promise.resolve(commonEcc.convertJwkToPem(CURVE_NAME, privateOrPublicJwk));
    },
    /**
     * Generate an ECDH key pair as a JSON Web Key.
     *
     * @param {Array} privateKeyOps - The operations intended for the private key.
     * @param {Array} publicKeyOps - The operations intended for the public key.
     * @returns {string} The ECDH key pair.
     */
    generateJwkKeyPair: (privateKeyOps = [], publicKeyOps = []) => {
      return Promise.resolve(commonEcc.generateJwkKeyPair(CURVE_NAME, privateKeyOps, publicKeyOps));
    },
    /**
     * Generate an ECDH key pair as PEM certificates.
     *
     * @returns {Object} The PEM certificates.
     */
    generatePemKeyPair: () => {
      return Promise.resolve(commonEcc.generatePemKeyPair(CURVE_NAME));
    },
    /**
     * Sign a payload to prevent it from tamper.
     *
     * @param {string} payload - The payload to sign.
     * @param {string} privateKeyPem - The private key in PEM format.
     * @returns {Buffer} The signature for the payload.
     */
    signPayload: (payload, privateKeyPem) => {
      return Promise.resolve(commonEcc.signPayload(payload, privateKeyPem, HASH_TYPE));
    },
    /**
     * Verify the signature of a given payload.
     *
     * @param {string} payload - The payload against which the signature will be checked.
     * @param {string|Buffer} signature - The signature of the payload.
     * @param {Object} publicPemKey - The public ECDH key in PEM format.
     * @returns {boolean}
     */
    verifyPayloadSignature: (payload, signature, publicKeyPem) => {
      return Promise.resolve(commonEcc.verifyPayloadSignature(payload, signature, publicKeyPem, HASH_TYPE));
    },
    /**
     * Compute an ECDH shared secret.
     *
     * @param {Object} privatePemKey - The private ECDH key in PEM format.
     * @param {Object} otherPublicPemKey - The other public ECDH key in PEM format.
     * @returns {Buffer}
     */
    computeSecret: (privatePemKey, otherPublicPemKey) => {
      return Promise.resolve(commonEcc.computeSecret(CURVE_NAME, privatePemKey, otherPublicPemKey));
    }
  };

}).call(this);

//# sourceMappingURL=ecc384.js.map
