# Elliptic Curve Cryptography Helper Library

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

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

- base64: URL encode/decode functions.
- common: Random string and numbers.
- ecc384: ECC with P-384 functions. Also contains functions to sign and verify
          the signatures, and convert PEM certificates to JWK.
- ecc521: ECC with P-521 functions. Also contains functions to sign and verify
          the signatures, and convert PEM certificates to JWK.
- hash: SHA-256, SHA-384, and SHA-512 functions.
- hmac: Generate HMAC.
- hkdf: Derive bytes using HKDF.
- jwt: Generate and verify JSON Web Tokens. The JWTs support ES384, ES512, 
       HS384, and HS512 algorithms.
- aesgcm256: Encrypt and decrypt using AES-GCM-256 scheme.
- password: Password hash and match functions. Uses Scrypt for password hashing.

## Example Usage

See the `test/spec.js` file for examples.
