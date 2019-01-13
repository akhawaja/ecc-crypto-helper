(function() {

  /**
   * Generate a key identifier suitable for use as a `kid` in a JSON Web Key.
   *
   * @param {Object} jwk - The JSON Web Key for which a `kid` is going to be generated.
   * @returns {string} The key identifier.
   */
  var base64, common, crypto, ecKeyUtils, generateKeyIdentifier, ksuid;

  crypto = require("crypto");

  ecKeyUtils = require("eckey-utils");

  base64 = require("./base64");

  common = require("./common");

  ksuid = require("./ksuid");

  generateKeyIdentifier = (jwk) => {
    return new Promise(async(resolve, reject) => {
      var buffer, ref;
      if ((jwk != null ? (ref = jwk.publicKey) != null ? ref.x : void 0 : void 0) != null) {
        buffer = Buffer.from((await base64.urlDecode(jwk.publicKey.x)));
        return resolve(buffer.slice(0, 4).toString("hex"));
      } else {
        return reject(new Error("Invalid JSON Web Key supplied."));
      }
    });
  };

  module.exports = {
    /**
     * Convert a PEM certificate to a JSON Web Key.
     *
     * @param {string} curveName - The type of ECC curve.
     * @param {string|Buffer} privateOrPublicPem - The private or public PEM key.
     * @param {Array} privateKeyOps - The operations intended for the private key.
     * @param {Array} publicKeyOps - The operations intended for the public key.
     * @returns {Object} The converted certificate.
     */
    convertPemToJwk: (curveName, privateOrPublicPem, privateKeyOps = [], publicKeyOps = []) => {
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
          jwk = ecKeyUtils.generateJwk(curveName, parsed);
          kid = (await generateKeyIdentifier(jwk));
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
     * @param {string} curveName - The type of ECC curve.
     * @param {string|Buffer} privateOrPublicJwk - The private or public JSON Web Key.
     * @returns {Object} The converted certificate.
     */
    convertJwkToPem: (curveName, privateOrPublicJwk) => {
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
          return resolve(ecKeyUtils.generatePem(curveName, params));
        } catch (error) {
          err = error;
          return reject(err);
        }
      });
    },
    /**
     * Generate an ECDH key pair as a JSON Web Key.
     *
     * @param {string} curveName - The type of ECC curve.
     * @param {Array} privateKeyOps - The operations intended for the private key.
     * @param {Array} publicKeyOps - The operations intended for the public key.
     * @returns {string} The ECDH key pair.
     */
    generateJwkKeyPair: (curveName, privateKeyOps = [], publicKeyOps = []) => {
      if (privateKeyOps.length === 0) {
        privateKeyOps = ["deriveKey", "sign"];
      }
      if (publicKeyOps.length === 0) {
        publicKeyOps = ["verify"];
      }
      return new Promise(async(resolve, reject) => {
        var ecdh, jwk, kid, params;
        ecdh = crypto.createECDH(curveName);
        ecdh.generateKeys();
        params = {
          privateKey: ecdh.getPrivateKey(),
          publicKey: ecdh.getPublicKey()
        };
        jwk = ecKeyUtils.generateJwk(curveName, params);
        kid = (await generateKeyIdentifier(jwk));
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
     * @param {string} curveName - The type of ECC curve.
     * @returns {Object} The PEM certificates.
     */
    generatePemKeyPair: (curveName) => {
      return new Promise((resolve, reject) => {
        var ecdh, params;
        ecdh = crypto.createECDH(curveName);
        ecdh.generateKeys();
        params = {
          privateKey: ecdh.getPrivateKey(),
          publicKey: ecdh.getPublicKey()
        };
        return resolve(ecKeyUtils.generatePem(curveName, params));
      });
    },
    /**
     * Sign a payload to prevent it from tamper.
     *
     * @param {string} payload - The payload to sign.
     * @param {string} privateKeyPem - The private key in PEM format.
     * @param {string} hashType - The type of SHA2 digest to use. Defaults to SHA-256.
     * @returns {Buffer} The signature for the payload.
     */
    signPayload: (payload, privateKeyPem, hashType = "sha256") => {
      return new Promise((resolve, reject) => {
        var message, signer;
        if (typeof payload !== "string") {
          return reject("Payload must be a string.");
        }
        signer = crypto.createSign(hashType);
        message = Buffer.from(payload);
        signer.update(message);
        return resolve(signer.sign(privateKeyPem));
      });
    },
    /**
     * Verify the signature of a given payload.
     *
     * @param {string} payload - The payload against which the signature will be checked.
     * @param {string|Buffer} signature - The signature of the payload.
     * @param {Object} publicPemKey - The public ECDH key in PEM format.
     * @param {string} hashType - The type of SHA2 digest to use. Defaults to SHA-256.
     * @returns {boolean}
     */
    verifyPayloadSignature: (payload, signature, publicKeyPem, hashType = "sha256") => {
      return new Promise((resolve, reject) => {
        var message, verifier;
        if (typeof payload !== "string") {
          return reject("Payload must be a string.");
        }
        verifier = crypto.createVerify(hashType);
        message = Buffer.from(payload);
        verifier.update(message);
        return resolve(verifier.verify(publicKeyPem, signature));
      });
    },
    /**
     * Compute an ECDH shared secret.
     *
     * @param {string} curveName - The type of ECC curve.
     * @param {Object} privatePemKey - The private ECDH key in PEM format.
     * @param {Object} otherPublicPemKey - The other public ECDH key in PEM format.
     * @returns {Buffer}
     */
    computeSecret: (curveName, privatePemKey, otherPublicPemKey) => {
      return new Promise((resolve, reject) => {
        var ecdh, err;
        try {
          ecdh = crypto.createECDH(curveName);
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

//# sourceMappingURL=common-ecc.js.map
