# Elliptic Curve Cryptography Helper Library

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Coverage Status](https://coveralls.io/repos/github/akhawaja/ecc-crypto-helper/badge.svg?branch=master)](https://coveralls.io/github/akhawaja/ecc-crypto-helper?branch=master)
[![JavaScript Style Guide](https://img.shields.io/badge/code_style-standard-brightgreen.svg)](https://standardjs.com)

**Discalaimer:** This library contains encryption software that is subject to 
the U.S. Export Administration Regulations. You may not export, re-export, 
transfer or download this code or any part of it in violation of any United 
States law, directive or regulation. In particular this software may not be 
exported or re-exported in any form or on any media to Iran, North Sudan, 
Syria, Cuba, or North Korea, or to denied persons or entities mentioned on any 
US maintained blocked list.

## Introduction
Provides basic functions to start using ECC in your next project. Please see
the `Features` section for a quick description of what is available. 

## Features

- aescbc128: Encrypt and decrypt using AES-CBC-128 scheme.
- aescbc192: Encrypt and decrypt using AES-CBC-192 scheme.
- aescbc256: Encrypt and decrypt using AES-CBC-256 scheme.
- aesgcm128: Encrypt and decrypt using AES-GCM-128 scheme.
- aesgcm192: Encrypt and decrypt using AES-GCM-192 scheme.
- aesgcm256: Encrypt and decrypt using AES-GCM-256 scheme.
- base62: Base62 Encode/decode functions.
- base64: Base64 URL encode/decode functions.
- common: Random string, numbers, and UTC timestamp.
- ecc256: ECC with P-256 functions. Also contains functions to sign and verify
          the signatures, and convert PEM certificates to JWK.
- ecc384: ECC with P-384 functions. Also contains functions to sign and verify
          the signatures, and convert PEM certificates to JWK.
- ecc521: ECC with P-521 functions. Also contains functions to sign and verify
          the signatures, and convert PEM certificates to JWK.
- hash: SHA-256, SHA-384, and SHA-512 functions.
- hmac: Generate HMAC.
- hkdf: Key contraction and expansion algorithm to derive additional bytes.
- jwt: Generate and verify JSON Web Tokens. The JWTs support ES384, ES512, 
       HS384, and HS512 algorithms.
- ksuid: Generate and parse [KSUID](https://github.com/segmentio/ksuid) 
         identifiers. You can use this instead of a UUID.
- password: Password hash and match functions. Uses Scrypt + HKDF for password 
            hashing.
- rsa: Generate key pairs, perform public key encryption and private key 
       decryption, sign and verify using private and public keys respectively.
       Convert RSA keys between PEM and JWK.

## Example Usage

1. Install the library.

```
$> yarn add ecc-crypto-helper
```

2. Just import the file in your NodeJS project and start using it.

```javascript
// Import individual libraries
var common = require("ecc-crypto-helper/common");
common.random().then(function (result) {
    console.log(result.toString("hex"))
});
```

**OR**

```javascript
var eccHelper = require("ecc-crypto-helper")

// Generate a random value
var random = await eccHelper.common.random();

// Generate a random number between 1 and 100
var randomNumber = await eccHelper.common.randomNumber(1, 100);

// Base64 URL encode a string
var encoded = await eccHelper.base64.urlEncode("Hello world");

// Hash a password before storing it in your database
var plainPassword = "I am a super password";
var hashedPassword = (await eccHelper.password.hash(plainPassword)).toString("hex");

// Did the user supply the correct password?
var passwordMatch = await eccHelper.password.match(plainPassword, hashedPassword);

if (passwordMatch) {
    // Let the user in to the application
} else {
    // Password was not correct
}

// Encrypt a string using AES-GCM-256
var password = "This is a secret";
var cipherText = await eccHelper.aesGcm256.encrypt("This is a message", password);

// Decrypt the previously encrypted string
var plainText = await eccHelper.aesGcm256.decrypt(cipherText, password);

// Derive a random set of characters using HKDF
var initialKeyMaterial = "This is a secret";
var size = 64;
var bytesBuffer = await eccHelper.hkdf.derive(initialKeyMaterial, size);

// Generate a JSON Web Token using HS512
var sharedSecret = "This is a secret";
var claims = {"username":"bob"};
var webToken = await eccHelper.jwt.hs512.create(sharedSecret, claims);

// Decode the JSON Web Token
var decodedToken = await eccHelper.jwt.decode(webToken);

// Generate a RSA key pair
var rsaKeyPair = await eccHelper.rsa.generateKeyPair(2048) // 1024, 2048, or 4096
var jwkPrivateKey = await eccHelper.rsa.convertPemToJwk(rsaKeyPair.privateKey)
var jwkPublicKey = await eccHelper.rsa.convertPemToJwk(rsaKeyPair.publicKey)
var rsaPrivateKey = await eccHelper.rsa.convertJwkToPem(jwkPrivateKey)
var rsaPublicKey = await eccHelper.rsa.convertJwkToPem(jwkPublicKey)

// Generate an ECDH key pair
var keyPair = await eccHelper.ecc521.generatePemKeyPair();

// Generate a JSON Web Token using ES512
webToken = await eccHelper.jwt.es512.create(keyPair.privateKey, claims);

// Create and parse KSUID
var ksuid = await eccHelper.ksuid.create();
var parsed = await eccHelper.ksuid.parse(ksuid);

// Generate a shared secret
var sharedSecret = await eccHelper.sharedSecretGenerator.generateSharedSecret(32) // 256-bit key
var sharedSecretToJSONWebKey = await eccHelper.sharedSecretGenerator.convertSharedSecretToJwk(sharedSecret)
var sharedSecretAsJSONWebKey = await eccHelper.sharedSecretGenerator.generateSharedSecretAsJwk(32) // 256-bit key
```

See the `test/spec.js` file for more examples.
