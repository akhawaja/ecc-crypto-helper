(function() {
  var expect;

  expect = require("chai").expect;

  describe("Specification tests for the helper methods.", () => {
    describe("Testing the common library.", () => {
      var common;
      common = require("../common");
      it("Should generate a random string.", async() => {
        var str1, str2;
        str1 = (await common.randomString());
        str2 = (await common.randomString());
        expect(str1).to.not.equal(str2);
        expect(str1).to.have.lengthOf(16);
        return expect(str2).to.have.lengthOf(16);
      });
      return it("Should generate a random number between a given range.", async() => {
        var high, low, num1;
        low = 1;
        high = 20;
        num1 = (await common.randomNumber(low, high));
        return expect(num1).is.within(low, high);
      });
    });
    describe("Testing the bas64 library.", () => {
      var base64;
      base64 = require("../base64");
      return it("Should URL encode then decode a string correctly.", async() => {
        var decoded, encoded, specimen, text;
        text = "hello world";
        specimen = "aGVsbG8gd29ybGQ";
        encoded = (await base64.urlEncode(text));
        decoded = (await base64.urlDecode(encoded));
        expect(specimen).to.equal(encoded);
        return expect(decoded).to.equal(text);
      });
    });
    describe("Testing the aesgcm256 library.", () => {
      var aes;
      aes = require("../aesgcm256");
      return it("Should encrypt and decrypt a string correctly.", async() => {
        var cipherText, decipherText, password, text;
        password = "This is a secret";
        text = "Nobody should know what this message says.";
        cipherText = (await aes.encrypt(text, password));
        decipherText = (await aes.decrypt(cipherText, password));
        return expect(decipherText).to.equal(text);
      });
    });
    describe("Testing the hash library.", () => {
      var hash, text;
      hash = require("../hash");
      text = "hello world";
      it("Should calculate the sha256 correctly.", async() => {
        var h, specimen;
        specimen = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        h = (await hash.sha256(text));
        return expect(h.toString("hex")).to.equal(specimen);
      });
      it("Should calculate the sha384 correctly.", async() => {
        var h, specimen;
        specimen = "fdbd8e75a67f29f701a4e040385e2e23986303ea10239211af907fcbb8" + "3578b3e417cb71ce646efd0819dd8c088de1bd";
        h = (await hash.sha384(text));
        return expect(h.toString("hex")).to.equal(specimen);
      });
      return it("Should calculate the sha512 correctly.", async() => {
        var h, specimen;
        specimen = "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d" + "4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f";
        h = (await hash.sha512(text));
        return expect(h.toString("hex")).to.equal(specimen);
      });
    });
    describe("Testing the hkdf library.", () => {
      var hkdf;
      hkdf = require("../hkdf");
      it("Should derive a 64-byte value.", async() => {
        var initialKeyMaterial, size, str;
        initialKeyMaterial = "This is a secret";
        size = 64;
        str = (await hkdf.derive(initialKeyMaterial, size));
        return expect(str).to.have.lengthOf(size);
      });
      it("Should derive a 128-byte value.", async() => {
        var initialKeyMaterial, size, str;
        initialKeyMaterial = "This is a secret";
        size = 128;
        str = (await hkdf.derive(initialKeyMaterial, size));
        return expect(str).to.have.lengthOf(size);
      });
      it("Should derive a 256-byte value.", async() => {
        var initialKeyMaterial, size, str;
        initialKeyMaterial = "This is a secret";
        size = 256;
        str = (await hkdf.derive(initialKeyMaterial, size));
        return expect(str).to.have.lengthOf(size);
      });
      return it("Should derive a 512-byte value.", async() => {
        var initialKeyMaterial, size, str;
        initialKeyMaterial = "This is a secret";
        size = 512;
        str = (await hkdf.derive(initialKeyMaterial, size));
        return expect(str).to.have.lengthOf(size);
      });
    });
    describe("Testing the hmac library.", () => {
      var hmac, message, password;
      hmac = require("../hmac");
      message = "This is a top secret message.";
      password = "This is a secret";
      it("Should calculate hmac using sha256 correctly.", async() => {
        var signature, specimen;
        specimen = "634bb279a3d5d77677665c2a5c2c42bd89b93d216085c16429b65563f7945b58";
        signature = (await hmac.hmac256(message, password));
        return expect(signature.toString("hex")).to.equal(specimen);
      });
      it("Should calculate hmac using sha384 correctly.", async() => {
        var signature, specimen;
        specimen = "a1525f3b138f83de947282862fbc4497d1e3ada37e0478562deea07ee6" + "9391abb82d278448dac4dcbd977707c6e610fb";
        signature = (await hmac.hmac384(message, password));
        return expect(signature.toString("hex")).to.equal(specimen);
      });
      return it("Should calculate hmac using sha512 correctly.", async() => {
        var signature, specimen;
        specimen = "ac0c888d0f4b4753a9ffaf1fc732b2a8c814752f43fde826a3bc1c9373" + "f765b5d1914fee1f95448ff3287953750f9e68ab3aae6cd7a98a3745d3ebce4cc63248";
        signature = (await hmac.hmac512(message, password));
        return expect(signature.toString("hex")).to.equal(specimen);
      });
    });
    describe("Testing the password library.", () => {
      var password;
      password = require("../password");
      /*
      This test is the slowest. Most likely it is because scrypt is a slow
      password hashing algorithm in Node.js.
      */
      return it("Should hash and verify the password.", async() => {
        var hashedPassword, match, secret;
        secret = "This is my password";
        hashedPassword = (await password.hash(secret));
        match = (await password.match(secret, hashedPassword));
        expect(hashedPassword).to.have.lengthOf(96);
        return expect(match).to.be.true;
      });
    });
    return describe("Testing the jwt, ecc384, and ecc521 libraries in concert.", () => {
      var claims, ecc384, ecc521, jwt, sharedSecret;
      jwt = require("../jwt");
      ecc384 = require("../ecc384");
      ecc521 = require("../ecc521");
      sharedSecret = "This is a secret";
      claims = {
        username: "unit-test"
      };
      it("Should generate a valid HS384 JSON Web Token.", async() => {
        var decoded, verify, webToken;
        webToken = (await jwt.hs384.create(sharedSecret, claims));
        verify = (await jwt.hs384.verify(sharedSecret, webToken));
        decoded = (await jwt.decode(webToken));
        expect(decoded.payload.username).to.equal(claims.username);
        return expect(verify).to.be.true;
      });
      it("Should generate a valid HS512 JSON Web Token.", async() => {
        var decoded, verify, webToken;
        webToken = (await jwt.hs512.create(sharedSecret, claims));
        verify = (await jwt.hs512.verify(sharedSecret, webToken));
        decoded = (await jwt.decode(webToken));
        expect(decoded.payload.username).to.equal(claims.username);
        return expect(verify).to.be.true;
      });
      it("Should generate a valid ES384 JSON Web Token.", async() => {
        var decoded, pems, verify, webToken;
        pems = (await ecc384.generatePemKeyPair());
        webToken = (await jwt.es384.create(pems.privateKey, claims));
        verify = (await jwt.es384.verify(pems.publicKey, webToken));
        decoded = (await jwt.decode(webToken));
        expect(decoded.payload.username).to.equal(claims.username);
        return expect(verify).to.be.true;
      });
      it("Should generate a valid ES512 JSON Web Token.", async() => {
        var decoded, pems, verify, webToken;
        pems = (await ecc521.generatePemKeyPair());
        webToken = (await jwt.es512.create(pems.privateKey, claims));
        verify = (await jwt.es512.verify(pems.publicKey, webToken));
        decoded = (await jwt.decode(webToken));
        expect(decoded.payload.username).to.equal(claims.username);
        return expect(verify).to.be.true;
      });
      it("Should be able to compute a secret using ECDHE and Sha384.", async() => {
        var aliceKeyPair, bobKeyPair, secret1, secret2;
        bobKeyPair = (await ecc384.generatePemKeyPair());
        aliceKeyPair = (await ecc384.generatePemKeyPair());
        secret1 = (await ecc384.computeSecret(bobKeyPair.privateKey, aliceKeyPair.publicKey));
        secret2 = (await ecc384.computeSecret(aliceKeyPair.privateKey, bobKeyPair.publicKey));
        return expect(Buffer.compare(secret1, secret2)).to.equal(0);
      });
      it("Should be able to compute a secret using ECDHE and Sha512.", async() => {
        var aliceKeyPair, bobKeyPair, secret1, secret2;
        bobKeyPair = (await ecc521.generatePemKeyPair());
        aliceKeyPair = (await ecc521.generatePemKeyPair());
        secret1 = (await ecc521.computeSecret(bobKeyPair.privateKey, aliceKeyPair.publicKey));
        secret2 = (await ecc521.computeSecret(aliceKeyPair.privateKey, bobKeyPair.publicKey));
        return expect(Buffer.compare(secret1, secret2)).to.equal(0);
      });
      it("Should sign and verify a message signed with a P-384 key.", async() => {
        var keyPair, message, signature, verify;
        message = "This is a message that was not tampered with.";
        keyPair = (await ecc384.generatePemKeyPair());
        signature = (await ecc384.signPayload(message, keyPair.privateKey));
        verify = (await ecc384.verifyPayloadSignature(message, signature, keyPair.publicKey));
        return expect(verify).to.be.true;
      });
      it("Should sign and verify a message signed with a P-521 key.", async() => {
        var keyPair, message, signature, verify;
        message = "This is a message that was not tampered with.";
        keyPair = (await ecc521.generatePemKeyPair());
        signature = (await ecc521.signPayload(message, keyPair.privateKey));
        verify = (await ecc521.verifyPayloadSignature(message, signature, keyPair.publicKey));
        return expect(verify).to.be.true;
      });
      it("Should be able to convert keys between PEM and JWK when using ecc384.", async() => {
        var jwk, jwk2, keyPair, pems, pems2;
        keyPair = (await ecc384.generatePemKeyPair());
        jwk = (await ecc384.convertPemToJwk(keyPair.privateKey));
        pems = (await ecc384.convertJwkToPem(jwk.privateKey));
        jwk2 = (await ecc384.convertPemToJwk(pems.privateKey));
        pems2 = (await ecc384.convertJwkToPem(jwk2.privateKey));
        expect(jwk.privateKey.x).to.equal(jwk2.privateKey.x);
        expect(jwk.privateKey.y).to.equal(jwk2.privateKey.y);
        expect(jwk.privateKey.d).to.equal(jwk2.privateKey.d);
        expect(jwk.publicKey.x).to.equal(jwk2.publicKey.x);
        expect(jwk.publicKey.y).to.equal(jwk2.publicKey.y);
        expect(pems.privateKey).to.equal(pems2.privateKey);
        return expect(pems.publicKey).to.equal(pems2.publicKey);
      });
      return it("Should be able to convert keys between PEM and JWK when using ecc521.", async() => {
        var jwk, jwk2, keyPair, pems, pems2;
        keyPair = (await ecc521.generatePemKeyPair());
        jwk = (await ecc521.convertPemToJwk(keyPair.privateKey));
        pems = (await ecc521.convertJwkToPem(jwk.privateKey));
        jwk2 = (await ecc521.convertPemToJwk(pems.privateKey));
        pems2 = (await ecc521.convertJwkToPem(jwk2.privateKey));
        expect(jwk.privateKey.x).to.equal(jwk2.privateKey.x);
        expect(jwk.privateKey.y).to.equal(jwk2.privateKey.y);
        expect(jwk.privateKey.d).to.equal(jwk2.privateKey.d);
        expect(jwk.publicKey.x).to.equal(jwk2.publicKey.x);
        expect(jwk.publicKey.y).to.equal(jwk2.publicKey.y);
        expect(pems.privateKey).to.equal(pems2.privateKey);
        return expect(pems.publicKey).to.equal(pems2.publicKey);
      });
    });
  });

}).call(this);

//# sourceMappingURL=spec.js.map
