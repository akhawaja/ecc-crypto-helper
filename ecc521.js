(function() {
  var CURVE_NAME, HASH_TYPE, common, crypto, ecKeyUtils;

  crypto = require("crypto");

  ecKeyUtils = require("eckey-utils");

  common = require("./common");

  CURVE_NAME = "secp521r1";

  HASH_TYPE = "sha512";

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
    signPayload: (payload, privateKeyJwk) => {
      return new Promise((resolve, reject) => {
        var jwk, message, pems, signer;
        if (typeof payload !== "string") {
          return reject("Payload must be a string.");
        }
        jwk = ecKeyUtils.parseJwk(privateKeyJwk);
        pems = ecKeyUtils.generatePem(CURVE_NAME, {
          privateKey: jwk.privateKey,
          publicKey: jwk.publicKey
        });
        signer = crypto.createSign(HASH_TYPE);
        message = Buffer.from(payload);
        signer.update(message);
        return resolve(signer.sign(pems.privateKey));
      });
    },
    verifyPayloadSignature: (payload, signature, publicKeyJwk) => {
      return new Promise((resolve, reject) => {
        var jwk, message, pems, verifier;
        if (typeof payload !== "string") {
          return reject("Payload must be a string.");
        }
        jwk = ecKeyUtils.parseJwk(publicKeyJwk);
        pems = ecKeyUtils.generatePem(CURVE_NAME, {
          publicKey: jwk.publicKey
        });
        verifier = crypto.createVerify(HASH_TYPE);
        message = Buffer.from(payload);
        verifier.update(message);
        return resolve(verifier.verify(pems.publicKey, signature));
      });
    },
    parseJwkToPem: (privateOrPublicJwk) => {
      return new Promise((resolve, reject) => {
        return resolve(ecKeyUtils.parseJwk(privateOrPublicJwk));
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

//# sourceMappingURL=ecc521.js.map
