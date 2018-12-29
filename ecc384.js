(function() {
  var CURVE_NAME, HASH_TYPE, common, crypto, ecKeyUtils;

  crypto = require("crypto");

  ecKeyUtils = require("eckey-utils");

  common = require("./common");

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
      return new Promise(async(resolve, reject) => {
        var err, jwk, kid, params, parsed;
        if (privateKeyOps.length === 0) {
          privateKeyOps = ["deriveKey", "sign"];
        }
        if (publicKeyOps.length === 0) {
          publicKeyOps = ["verify"];
        }
        try {
          parsed = ecKeyUtils.parsePem(privateOrPublicPem);
          params = {};
          if (parsed.privateKey !== void 0 && parsed.privateKey !== null) {
            params.privateKey = parsed.privateKey;
          }
          if (parsed.publicKey !== void 0 && parsed.publicKey !== null) {
            params.publicKey = parsed.publicKey;
          }
          jwk = ecKeyUtils.generateJwk(CURVE_NAME, parsed);
          kid = ((await common.randomString())).toString("hex");
          if (jwk.privateKey !== void 0) {
            jwk.privateKey.kid = kid;
            jwk.privateKey.key_ops = privateKeyOps;
          }
          if (jwk.publicKey !== void 0) {
            jwk.publicKey.kid = kid;
            jwk.publicKey.key_ops = publicKeyOps;
          }
          return resolve(jwk);
        } catch (error) {
          err = error;
          return reject(err);
        }
      });
    },
    /**
     * Convert a JSON Web Key to a PEM certificate.
     *
     * @param {string|Buffer} privateOrPublicJwk - The private or public JSON Web Key.
     * @returns {Object} The converted certificate.
     */
    convertJwkToPem: (privateOrPublicJwk) => {
      return new Promise((resolve, reject) => {
        var err, params, parsed;
        try {
          parsed = ecKeyUtils.parseJwk(privateOrPublicJwk);
          params = {};
          if (parsed.privateKey !== void 0 && parsed.privateKey !== null) {
            params.privateKey = parsed.privateKey;
          }
          if (parsed.publicKey !== void 0 && parsed.publicKey !== null) {
            params.publicKey = parsed.publicKey;
          }
          return resolve(ecKeyUtils.generatePem(CURVE_NAME, params));
        } catch (error) {
          err = error;
          return reject(err);
        }
      });
    },
    /**
     * Generate an ECDH key pair as a JSON Web Key.
     *
     * @param {Array} privateKeyOps - The operations intended for the private key.
     * @param {Array} publicKeyOps - The operations intended for the public key.
     * @returns {string} The ECDH key pair.
     */
    generateJwkKeyPair: (privateKeyOps = [], publicKeyOps = []) => {
      if (privateKeyOps.length === 0) {
        privateKeyOps = ["deriveKey", "sign"];
      }
      if (publicKeyOps.length === 0) {
        publicKeyOps = ["verify"];
      }
      return new Promise(async(resolve, reject) => {
        var ecdh, jwk, kid, params;
        ecdh = crypto.createECDH(CURVE_NAME);
        ecdh.generateKeys();
        params = {
          privateKey: ecdh.getPrivateKey(),
          publicKey: ecdh.getPublicKey()
        };
        jwk = ecKeyUtils.generateJwk(CURVE_NAME, params);
        kid = ((await common.randomString())).toString("hex");
        jwk.privateKey.kid = kid;
        jwk.privateKey.key_ops = privateKeyOps;
        jwk.publicKey.kid = kid;
        jwk.publicKey.key_ops = publicKeyOps;
        return resolve(jwk);
      });
    },
    /**
     * Generate an ECDH key pair as PEM certificates.
     *
     * @returns {Object} The PEM certificates.
     */
    generatePemKeyPair: () => {
      return new Promise((resolve, reject) => {
        var ecdh, params;
        ecdh = crypto.createECDH(CURVE_NAME);
        ecdh.generateKeys();
        params = {
          privateKey: ecdh.getPrivateKey(),
          publicKey: ecdh.getPublicKey()
        };
        return resolve(ecKeyUtils.generatePem(CURVE_NAME, params));
      });
    },
    /**
     * Sign a payload to prevent it from tamper.
     *
     * @param {string} payload - The payload to sign.
     * @param {string} privateKeyPem - The private key in PEM format.
     * @returns {Buffer} The signature for the payload.
     */
    signPayload: (payload, privateKeyPem) => {
      return new Promise((resolve, reject) => {
        var message, signature, signer;
        if (typeof payload !== "string") {
          return reject("Payload must be a string.");
        }
        signer = crypto.createSign(HASH_TYPE);
        message = Buffer.from(payload);
        signer.update(message);
        signature = signer.sign(privateKeyPem);
        return resolve(signature);
      });
    },
    /**
     * Verify the signature of a given payload.
     *
     * @param {string} payload - The payload against which the signature will be checked.
     * @param {string|Buffer} signature - The signature of the payload.
     * @param {Object} publicPemKey - The public ECDH key in PEM format.
     * @returns {boolean}
     */
    verifyPayloadSignature: (payload, signature, publicPemKey) => {
      return new Promise((resolve, reject) => {
        var message, signatureBuffer, verifier;
        if (typeof payload !== "string") {
          return reject("Payload must be a string.");
        }
        verifier = crypto.createVerify(HASH_TYPE);
        message = Buffer.from(payload);
        if (Buffer.isBuffer(signature)) {
          signatureBuffer = signature;
        } else if (typeof signature === "string") {
          signatureBuffer = Buffer.from(signature);
        } else {
          reject(new Error("Buffer or string expected for signature."));
        }
        verifier.update(message);
        return resolve(verifier.verify(publicPemKey, signatureBuffer));
      });
    },
    /**
     * Compute an ECDH shared secret.
     *
     * @param {Object} privatePemKey - The private ECDH key in PEM format.
     * @param {Object} otherPublicPemKey - The other public ECDH key in PEM format.
     * @returns {Buffer}
     */
    computeSecret: (privatePemKey, otherPublicPemKey) => {
      return new Promise((resolve, reject) => {
        var ecdh, err;
        try {
          ecdh = crypto.createECDH(CURVE_NAME);
          ecdh.setPrivateKey((ecKeyUtils.parsePem(privatePemKey)).privateKey);
          return resolve(ecdh.computeSecret((ecKeyUtils.parsePem(otherPublicPemKey)).publicKey));
        } catch (error) {
          err = error;
          return reject(err);
        }
      });
    }
  };

}).call(this);

//# sourceMappingURL=ecc384.js.map
