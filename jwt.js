(function() {
  var base64, common, create, decode, jws, verify;

  jws = require("jws");

  base64 = require("./base64");

  common = require("./common");

  decode = (jsonWebToken) => {
    return new Promise(async(resolve, reject) => {
      var decoded, err, parts;
      parts = jsonWebToken.split(".");
      if (parts.length < 2) {
        reject(new Error("Invalid JSON web token."));
      }
      decoded = {};
      try {
        decoded.header = JSON.parse((await base64.urlDecode(parts[0])));
        decoded.payload = JSON.parse((await base64.urlDecode(parts[1])));
      } catch (error) {
        err = error;
        reject(err);
      }
      if (parts[2] !== void 0) {
        decoded.signature = parts[2];
      }
      return resolve(decoded);
    });
  };

  create = (algorithm, secretOrPrivateKey, claims = {}) => {
    return new Promise(async(resolve, reject) => {
      var currentTime, err, header;
      header = {
        alg: algorithm,
        typ: "JWT"
      };
      if (claims.iss === void 0) {
        claims.iss = "urn:iss:crypto-helper";
      }
      if (claims.aud === void 0) {
        claims.aud = "urn:aud:any-client";
      }
      if (claims.exp === void 0) {
        // Expire in 10-minutes
        claims.exp = Math.round((new Date().getTime()) / 1000) + (60 * 10);
      }
      currentTime = Math.round((new Date().getTime()) / 1000);
      claims.iat = currentTime;
      claims.nbf = currentTime;
      claims.jti = ((await common.randomString())).toString("hex");
      try {
        return resolve(jws.sign({
          header: header,
          payload: claims,
          secret: secretOrPrivateKey
        }));
      } catch (error) {
        err = error;
        return reject(err);
      }
    });
  };

  verify = (algorithm, secretOrPublicKey, jsonWebToken) => {
    return new Promise(async(resolve, reject) => {
      var claims, currentTime, decoded, err, expiration;
      // Make sure we have a valid JSON Web Token
      if (typeof jsonWebToken !== "string") {
        reject(new Error("jsonWebToken must be a string."));
      }
      decoded = (await decode(jsonWebToken));
      claims = decoded.payload;
      currentTime = Math.round(new Date().getTime());
      if ((claims != null ? claims.exp : void 0) !== void 0) {
        expiration = claims.exp * 1000;
        if (expiration <= currentTime) {
          reject(new Error("The token has expired."));
        }
      }
      try {
        // Validate the signature
        return resolve(jws.verify(jsonWebToken, algorithm, secretOrPublicKey));
      } catch (error) {
        err = error;
        return reject(err);
      }
    });
  };

  module.exports = {
    decode: decode,
    es384: {
      create: (privateKey, claims) => {
        return Promise.resolve(create("ES384", privateKey, claims));
      },
      verify: (publicKey, jsonWebToken) => {
        return Promise.resolve(verify("ES384", publicKey, jsonWebToken));
      }
    },
    es512: {
      create: (privateKey, claims) => {
        return Promise.resolve(create("ES512", privateKey, claims));
      },
      verify: (publicKey, jsonWebToken) => {
        return Promise.resolve(verify("ES512", publicKey, jsonWebToken));
      }
    },
    hs384: {
      create: (secret, claims) => {
        return Promise.resolve(create("HS384", secret, claims));
      },
      verify: (secret, jsonWebToken) => {
        return Promise.resolve(verify("HS384", secret, jsonWebToken));
      }
    },
    hs512: {
      create: (secret, claims) => {
        return Promise.resolve(create("HS512", secret, claims));
      },
      verify: (secret, jsonWebToken) => {
        return Promise.resolve(verify("HS512", secret, jsonWebToken));
      }
    }
  };

}).call(this);

//# sourceMappingURL=jwt.js.map
