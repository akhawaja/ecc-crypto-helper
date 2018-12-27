(function() {
  var CURVE_NAME, HASH_TYPE, common, crypto, ecKeyUtils;

  crypto = require("crypto");

  ecKeyUtils = require("eckey-utils");

  common = require("./common");

  CURVE_NAME = "secp384r1";

  HASH_TYPE = "sha384";

  module.exports = {
    curveName: CURVE_NAME,
    convertPemToJwk: (privateKey, publicKey, privateKeyOps = [], publicKeyOps = []) => {
      if (privateKeyOps.length === 0) {
        privateKeyOps = ["deriveKey", "sign"];
      }
      if (publicKeyOps.length === 0) {
        publicKeyOps = ["verify"];
      }
      return new Promise(async(resolve, reject) => {
        var jwk, kid, params;
        params = {};
        if (privateKey !== void 0 && privateKey !== null) {
          params.privateKey = privateKey;
        }
        if (publicKey !== void 0 && publicKey !== null) {
          params.publicKey = publicKey;
        }
        if (params.privateKey === void 0 && params.publicKey === void 0) {
          reject(new Error("You must supply at least a private key or public key."));
        }
        jwk = ecKeyUtils.generateJwk(CURVE_NAME, params);
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
      });
    },
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
    signPayload: (payload, privateKeyPem) => {
      return new Promise((resolve, reject) => {
        var message, signer;
        if (typeof payload !== "string") {
          return reject("Payload must be a string.");
        }
        signer = crypto.createSign(HASH_TYPE);
        message = Buffer.from(payload);
        signer.update(message);
        return resolve(signer.sign(privateKeyPem));
      });
    },
    verifyPayloadSignature: (payload, signature, publicKeyPem) => {
      return new Promise((resolve, reject) => {
        var message, verifier;
        if (typeof payload !== "string") {
          return reject("Payload must be a string.");
        }
        verifier = crypto.createVerify(HASH_TYPE);
        message = Buffer.from(payload);
        verifier.update(message);
        return resolve(verifier.verify(publicKeyPem, signature));
      });
    },
    parseJwkToPem: (privateOrPublicJwk) => {
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
    parsePemToJwk: (privateOrPublicPem) => {
      return new Promise((resolve, reject) => {
        var err, params, parsed;
        try {
          parsed = ecKeyUtils.parsePem(privateOrPublicPem);
          params = {};
          if (parsed.privateKey !== void 0 && parsed.privateKey !== null) {
            params.privateKey = parsed.privateKey;
          }
          if (parsed.publicKey !== void 0 && parsed.publicKey !== null) {
            params.publicKey = parsed.publicKey;
          }
          return resolve(ecKeyUtils.generateJwk(CURVE_NAME, params));
        } catch (error) {
          err = error;
          return reject(err);
        }
      });
    },
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
