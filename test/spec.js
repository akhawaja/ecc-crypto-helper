const expect = require('chai').expect

describe('Specification tests for the helper methods.', () => {
  const common = require('../common')

  describe('Testing the common library.', () => {
    it('Should generate a random string.', async () => {
      const str1 = await common.random()
      const str2 = await common.random()

      expect(str1.toString('hex')).to.not.equal(str2.toString('hex'))
      expect(str1).to.have.lengthOf(16)
      expect(str2).to.have.lengthOf(16)
    })

    it('Should generate a random number between a given range.', async () => {
      const low = 1
      const high = 20
      const num1 = await common.randomNumber(low, high)

      expect(num1).is.within(low, high)
    })

    it('Should throw an error when the low and high numbers are the same.',
      async () => {
        const low = 1
        const high = 1

        common.randomNumber(low, high).catch(err => {
          expect(err instanceof Error).to.equal(true)
        })
      })

    it('Should not generate a random value of size less than zero.',
      async () => {
        const size = -1
        common.random(size).catch((err) => {
          expect(err instanceof RangeError).to.equal(true)
        })
      })

    it('Should calculate UTC Date object,', async () => {
      const utc = await common.utcDate()
      const now = new Date()
      let utcTime = utc.toTimeString().split(' ')[0]
      let nowTimeInUTC = now.toUTCString().split(' ')

      expect(utcTime).to.equal(nowTimeInUTC[nowTimeInUTC.length - 2])
    })
  })

  describe('Testing the base62 library.', () => {
    const base62 = require('../base62')

    it('Should properly encode and decode a value to and from Base62.',
      async () => {
        const buffer = await common.random(20)
        const encoded = await base62.encode(buffer)
        const decoded = await base62.decode(encoded)

        expect(decoded.compare(buffer)).to.equal(0)
      })

    it('Should throw an error if a Buffer is not supplied when encoding.',
      async () => {
        const value = (await common.random()).toString('hex')

        base62.encode(value).catch((err) => {
          expect(err instanceof TypeError).to.equal(true)
        })
      })

    it('Should throw an error if a string is not supplied when decoding.',
      async () => {
        const value = await common.random()
        const encoded = Buffer.from((await base62.encode(value)))

        base62.decode(encoded).catch((err) => {
          expect(err instanceof TypeError).to.equal(true)
        })
      })

    it('Should generate the same value as the ksuid/base62',
      async () => {
        const base62ext = require('ksuid/base62')
        const common = require('../common')

        const buffer = await common.random()
        const encoded1 = await base62.encode(buffer)
        const encoded2 = base62ext.encode(buffer)
        const decoded1 = (await base62.decode(encoded1))
        const decoded2 = base62ext.decode(encoded2)

        expect(encoded1).to.equal(encoded2)
        expect(Buffer.compare(decoded1, decoded2)).to.equal(0)
      })
  })

  describe('Testing the bas64 library.', () => {
    const base64 = require('../base64')

    it('Should URL encode then decode a string correctly.', async () => {
      const text = 'hello world'
      const specimen = 'aGVsbG8gd29ybGQ'
      const encoded = await base64.urlEncode(text)
      const decoded = await base64.urlDecode(encoded)

      expect(specimen).to.equal(encoded)
      expect(decoded).to.equal(text)
    })

    it('Should not decode a non-string value.', () => {
      const buffer = Buffer.from('abc')

      base64.urlDecode(buffer).catch((err) => {
        return expect(err instanceof TypeError).to.be.true
      })
    })
  })

  describe('Testing the aescbc128 library.', () => {
    const aes = require('../aescbc128')

    it('Should encrypt and decrypt a string correctly.', async () => {
      const password = 'This is a secret'
      const text = 'Nobody should know what this message says.'
      const cipherText = await aes.encrypt(text, password)
      const decipherText = await aes.decrypt(
        cipherText.encrypted, password, cipherText.iv)

      expect(decipherText).to.equal(text)
    })
  })

  describe('Testing the aescbc192 library.', () => {
    const aes = require('../aescbc192')

    it('Should encrypt and decrypt a string correctly.', async () => {
      const password = 'This is a secret'
      const text = 'Nobody should know what this message says.'
      const cipherText = await aes.encrypt(text, password)
      const decipherText = await aes.decrypt(
        cipherText.encrypted, password, cipherText.iv)

      expect(decipherText).to.equal(text)
    })
  })

  describe('Testing the aescbc256 library.', () => {
    const aes = require('../aescbc256')

    it('Should encrypt and decrypt a string correctly.', async () => {
      const password = 'This is a secret'
      const text = 'Nobody should know what this message says.'
      const cipherText = await aes.encrypt(text, password)
      const decipherText = await aes.decrypt(
        cipherText.encrypted, password, cipherText.iv)

      expect(decipherText).to.equal(text)
    })
  })

  describe('Testing the aesgcm128 library.', () => {
    const aes = require('../aesgcm128')

    it('Should encrypt and decrypt a string correctly.', async () => {
      const password = 'This is a secret'
      const text = 'Nobody should know what this message says.'
      const aad = Buffer.from('name:unit-test')
      const cipherText = await aes.encrypt(text, password, aad)
      const decipherText = await aes.decrypt(
        cipherText.encrypted, password, cipherText.iv, cipherText.authTag, aad)

      expect(decipherText).to.equal(text)
    })
  })

  describe('Testing the aesgcm192 library.', () => {
    const aes = require('../aesgcm192')

    it('Should encrypt and decrypt a string correctly.', async () => {
      const password = 'This is a secret'
      const text = 'Nobody should know what this message says.'
      const aad = Buffer.from('name:unit-test')
      const cipherText = await aes.encrypt(text, password, aad)
      const decipherText = await aes.decrypt(
        cipherText.encrypted, password, cipherText.iv, cipherText.authTag, aad)

      expect(decipherText).to.equal(text)
    })
  })

  describe('Testing the aesgcm256 library.', () => {
    const aes = require('../aesgcm256')

    it('Should encrypt and decrypt a string correctly.', async () => {
      const password = 'This is a secret'
      const text = 'Nobody should know what this message says.'
      const aad = Buffer.from('name:unit-test')
      const cipherText = await aes.encrypt(text, password, aad)
      const decipherText = await aes.decrypt(
        cipherText.encrypted, password, cipherText.iv, cipherText.authTag, aad)

      expect(decipherText).to.equal(text)
    })
  })

  describe('Testing the hash library.', () => {
    const hash = require('../hash')
    const text = 'hello world'

    it('Should calculate the sha256 correctly.', async () => {
      const specimen = 'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9'
      const h = await hash.sha256(text)

      expect(h.toString('hex')).to.equal(specimen)
    })

    it('Should calculate the sha384 correctly.', async () => {
      const specimen = 'fdbd8e75a67f29f701a4e040385e2e23986303ea10239211af907fcbb8'
        + '3578b3e417cb71ce646efd0819dd8c088de1bd'
      const h = await hash.sha384(text)

      expect(h.toString('hex')).to.equal(specimen)
    })

    it('Should calculate the sha512 correctly.', async () => {
      const specimen = '309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d'
        + '4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f'
      const h = await hash.sha512(text)

      expect(h.toString('hex')).to.equal(specimen)
    })
  })

  describe('Testing the hkdf library.', () => {
    const hkdf = require('../hkdf')

    it('Should derive a 64-byte value.', async () => {
      const initialKeyMaterial = 'This is a secret'
      const size = 64
      const str = await hkdf.derive(initialKeyMaterial, size)

      expect(str).to.have.lengthOf(size)
    })

    it('Should derive a 128-byte value.', async () => {
      const initialKeyMaterial = 'This is a secret'
      const size = 128
      const str = await hkdf.derive(initialKeyMaterial, size)

      expect(str).to.have.lengthOf(size)
    })

    it('Should derive a 256-byte value.', async () => {
      const initialKeyMaterial = 'This is a secret'
      const size = 256
      const str = await hkdf.derive(initialKeyMaterial, size)

      expect(str).to.have.lengthOf(size)
    })

    it('Should derive a 512-byte value.', async () => {
      const initialKeyMaterial = 'This is a secret'
      const size = 512
      const str = await hkdf.derive(initialKeyMaterial, size)

      expect(str).to.have.lengthOf(size)
    })

    it('Should derive repeatable values with same inputs.', async () => {
      const initialKeyMaterial = 'This is a secret.'
      const salt = await common.random()
      const info = 'name=unit-test'
      const size = 64
      const hkdf1 = (await hkdf.derive(initialKeyMaterial, size, salt, info))
      const hkdf2 = (await hkdf.derive(initialKeyMaterial, size, salt, info))

      expect(hkdf1.compare(hkdf2)).to.equal(0)
    })
  })

  describe('Testing the hmac library.', () => {
    const hmac = require('../hmac')
    const message = 'This is a top secret message.'
    const password = 'This is a secret'

    it('Should calculate hmac using sha256 correctly.', async () => {
      const specimen = '634bb279a3d5d77677665c2a5c2c42bd89b93d216085c16429b65563f7945b58'
      const signature = await hmac.hmac256(message, password)

      expect(signature.toString('hex')).to.equal(specimen)
    })

    it('Should calculate hmac using sha384 correctly.', async () => {
      const specimen = 'a1525f3b138f83de947282862fbc4497d1e3ada37e0478562deea07ee6'
        + '9391abb82d278448dac4dcbd977707c6e610fb'
      const signature = await hmac.hmac384(message, password)

      expect(signature.toString('hex')).to.equal(specimen)
    })

    it('Should calculate hmac using sha512 correctly.', async () => {
      const specimen = 'ac0c888d0f4b4753a9ffaf1fc732b2a8c814752f43fde826a3bc1c9373'
        + 'f765b5d1914fee1f95448ff3287953750f9e68ab3aae6cd7a98a3745d3ebce4cc63248'
      const signature = await hmac.hmac512(message, password)

      expect(signature.toString('hex')).to.equal(specimen)
    })
  })

  describe('Testing the password library.', () => {
    const password = require('../password')
    /*
    This test is the slowest. Most likely it is because scrypt is a slow
    password hashing algorithm in Node.js.
    */
    it('Should hash and verify the password.', async () => {
      const secret = 'This is my password'
      const hashedPassword = await password.hash(secret)
      const match = await password.match(secret, hashedPassword)

      expect(hashedPassword).to.have.lengthOf(128)
      expect(match).to.equal(true)
    })
  })

  describe('Testing the jwt, ecc256, ecc384, and ecc521 libraries.', () => {
    const jwt = require('../jwt')
    const ecc256 = require('../ecc256')
    const ecc384 = require('../ecc384')
    const ecc521 = require('../ecc521')
    const sharedSecret = 'This is a secret'
    const claims = {
      username: 'unit-test'
    }

    it('Should generate a valid HS256 JSON Web Token.', async () => {
      const webToken = await jwt.hs256.create(sharedSecret, claims)
      const verify = await jwt.hs256.verify(sharedSecret, webToken)
      const decoded = await jwt.decode(webToken)

      expect(decoded.payload.username).to.equal(claims.username)
      expect(verify).to.equal(true)
    })

    it('Should generate a valid HS384 JSON Web Token.', async () => {
      const webToken = await jwt.hs384.create(sharedSecret, claims)
      const verify = await jwt.hs384.verify(sharedSecret, webToken)
      const decoded = await jwt.decode(webToken)

      expect(decoded.payload.username).to.equal(claims.username)
      expect(verify).to.equal(true)
    })

    it('Should generate a valid HS512 JSON Web Token.', async () => {
      const webToken = await jwt.hs512.create(sharedSecret, claims)
      const verify = await jwt.hs512.verify(sharedSecret, webToken)
      const decoded = await jwt.decode(webToken)

      expect(decoded.payload.username).to.equal(claims.username)
      expect(verify).to.equal(true)
    })

    it('Should generate a valid ES256 JSON Web Token.', async () => {
      const pems = await ecc256.generatePemKeyPair()
      const webToken = await jwt.es256.create(pems.privateKey, claims)
      const verify = await jwt.es256.verify(pems.publicKey, webToken)
      const decoded = await jwt.decode(webToken)

      expect(decoded.payload.username).to.equal(claims.username)
      expect(verify).to.equal(true)
    })

    it('Should generate a valid ES384 JSON Web Token.', async () => {
      const pems = await ecc384.generatePemKeyPair()
      const webToken = await jwt.es384.create(pems.privateKey, claims)
      const verify = await jwt.es384.verify(pems.publicKey, webToken)
      const decoded = await jwt.decode(webToken)

      expect(decoded.payload.username).to.equal(claims.username)
      expect(verify).to.equal(true)
    })

    it('Should generate a valid ES512 JSON Web Token.', async () => {
      const pems = await ecc521.generatePemKeyPair()
      const webToken = await jwt.es512.create(pems.privateKey, claims)
      const verify = await jwt.es512.verify(pems.publicKey, webToken)
      const decoded = await jwt.decode(webToken)

      expect(decoded.payload.username).to.equal(claims.username)
      expect(verify).to.equal(true)
    })

    it('Should be able to compute a secret using ECDHE and Sha256.',
      async () => {
        const bobKeyPair = await ecc256.generatePemKeyPair()
        const aliceKeyPair = await ecc256.generatePemKeyPair()
        const secret1 = await ecc256.computeSecret(bobKeyPair.privateKey,
          aliceKeyPair.publicKey)
        const secret2 = await ecc256.computeSecret(aliceKeyPair.privateKey,
          bobKeyPair.publicKey)

        expect(Buffer.compare(secret1, secret2)).to.equal(0)
      })

    it('Should be able to compute a secret using ECDHE and Sha384.',
      async () => {
        const bobKeyPair = await ecc384.generatePemKeyPair()
        const aliceKeyPair = await ecc384.generatePemKeyPair()
        const secret1 = await ecc384.computeSecret(bobKeyPair.privateKey,
          aliceKeyPair.publicKey)
        const secret2 = await ecc384.computeSecret(aliceKeyPair.privateKey,
          bobKeyPair.publicKey)

        expect(Buffer.compare(secret1, secret2)).to.equal(0)
      })

    it('Should be able to compute a secret using ECDHE and Sha512.',
      async () => {
        const bobKeyPair = await ecc521.generatePemKeyPair()
        const aliceKeyPair = await ecc521.generatePemKeyPair()
        const secret1 = await ecc521.computeSecret(bobKeyPair.privateKey,
          aliceKeyPair.publicKey)
        const secret2 = await ecc521.computeSecret(aliceKeyPair.privateKey,
          bobKeyPair.publicKey)

        expect(Buffer.compare(secret1, secret2)).to.equal(0)
      })

    it('Should sign and verify a message signed with a P-256 key.',
      async () => {
        const message = 'This is a message that was not tampered with.'
        const keyPair = await ecc256.generatePemKeyPair()
        const signature = await ecc256.signPayload(message, keyPair.privateKey)
        const verify = await ecc256.verifyPayloadSignature(message, signature,
          keyPair.publicKey)

        expect(verify).to.equal(true)
      })

    it('Should sign and verify a message signed with a P-384 key.',
      async () => {
        const message = 'This is a message that was not tampered with.'
        const keyPair = await ecc384.generatePemKeyPair()
        const signature = await ecc384.signPayload(message, keyPair.privateKey)
        const verify = await ecc384.verifyPayloadSignature(message, signature,
          keyPair.publicKey)

        expect(verify).to.equal(true)
      })

    it('Should sign and verify a message signed with a P-521 key.',
      async () => {
        const message = 'This is a message that was not tampered with.'
        const keyPair = await ecc521.generatePemKeyPair()
        const signature = await ecc521.signPayload(message, keyPair.privateKey)
        const verify = await ecc521.verifyPayloadSignature(message, signature,
          keyPair.publicKey)

        expect(verify).to.equal(true)
      })

    it('Should be able to convert keys between PEM and JWK when using ecc256.',
      async () => {
        const keyPair = await ecc256.generatePemKeyPair()
        const jwk = await ecc256.convertPemToJwk(keyPair.privateKey)
        const pems = await ecc256.convertJwkToPem(jwk.privateKey)
        const jwk2 = await ecc256.convertPemToJwk(pems.privateKey)
        const pems2 = await ecc256.convertJwkToPem(jwk2.privateKey)

        expect(jwk.privateKey.x).to.equal(jwk2.privateKey.x)
        expect(jwk.privateKey.y).to.equal(jwk2.privateKey.y)
        expect(jwk.privateKey.d).to.equal(jwk2.privateKey.d)
        expect(jwk.publicKey.x).to.equal(jwk2.publicKey.x)
        expect(jwk.publicKey.y).to.equal(jwk2.publicKey.y)
        expect(pems.privateKey).to.equal(pems2.privateKey)
        expect(pems.publicKey).to.equal(pems2.publicKey)
      })

    it('Should be able to convert keys between PEM and JWK when using ecc384.',
      async () => {
        const keyPair = await ecc384.generatePemKeyPair()
        const jwk = await ecc384.convertPemToJwk(keyPair.privateKey)
        const pems = await ecc384.convertJwkToPem(jwk.privateKey)
        const jwk2 = await ecc384.convertPemToJwk(pems.privateKey)
        const pems2 = await ecc384.convertJwkToPem(jwk2.privateKey)

        expect(jwk.privateKey.x).to.equal(jwk2.privateKey.x)
        expect(jwk.privateKey.y).to.equal(jwk2.privateKey.y)
        expect(jwk.privateKey.d).to.equal(jwk2.privateKey.d)
        expect(jwk.publicKey.x).to.equal(jwk2.publicKey.x)
        expect(jwk.publicKey.y).to.equal(jwk2.publicKey.y)
        expect(pems.privateKey).to.equal(pems2.privateKey)
        expect(pems.publicKey).to.equal(pems2.publicKey)
      })

    it('Should be able to convert keys between PEM and JWK when using ecc521.',
      async () => {
        const keyPair = await ecc521.generatePemKeyPair()
        const jwk = await ecc521.convertPemToJwk(keyPair.privateKey)
        const pems = await ecc521.convertJwkToPem(jwk.privateKey)
        const jwk2 = await ecc521.convertPemToJwk(pems.privateKey)
        const pems2 = await ecc521.convertJwkToPem(jwk2.privateKey)

        expect(jwk.privateKey.x).to.equal(jwk2.privateKey.x)
        expect(jwk.privateKey.y).to.equal(jwk2.privateKey.y)
        expect(jwk.privateKey.d).to.equal(jwk2.privateKey.d)
        expect(jwk.publicKey.x).to.equal(jwk2.publicKey.x)
        expect(jwk.publicKey.y).to.equal(jwk2.publicKey.y)
        expect(pems.privateKey).to.equal(pems2.privateKey)
        expect(pems.publicKey).to.equal(pems2.publicKey)
      })
  })

  describe('Test the ksuid library.', () => {
    const ksuid = require('../ksuid')
    const common = require('../common')

    it('Should generate a 27-character KSUID.', async () => {
      const ksuidValue = await ksuid.create()

      expect(ksuidValue).to.have.lengthOf(27)
    })

    it('Should have the expected timestamp value.', async () => {
      const timestamp = (await common.utcTimestamp())
      const ksuidValue = (await ksuid.create(timestamp))
      const componentParts = (await ksuid.parse(ksuidValue))
      const time = (new Date(timestamp * 1e3)).getTime()

      expect(componentParts.time.getTime()).to.equal(time)
      expect(componentParts).to.have.property('ksuid')
      expect(componentParts).to.have.property('time')
      expect(componentParts).to.have.property('payload')
    })
    it('Should have the same timestamp value as supplied.', async () => {
      const timestamp = 1549735200
      const ksuidValue = await ksuid.create(timestamp)
      const componentParts = await ksuid.parse(ksuidValue)
      const time = (new Date(timestamp * 1e3)).getTime()

      expect(componentParts.time.getTime()).to.equal(time)
      expect(componentParts).to.have.property('ksuid')
      expect(componentParts).to.have.property('time')
      expect(componentParts).to.have.property('payload')
    })

    it('Should generate several KSUID values that are sorted alphabetically.',
      async () => {
        let i
        let j
        let ksuidValue
        let sorted
        let bucket = []

        for (i = j = 1; j <= 100; i = ++j) {
          ksuidValue = (await ksuid.create())
          bucket.push(ksuidValue)
        }

        sorted = bucket.sort((a, b) => {
          if (a > b) {
            return 1
          } else if (a < b) {
            return -1
          } else {
            return 0
          }
        })

        expect(sorted).to.equal(bucket)
      })
  })

  describe('Test the RSA library.', () => {
    const rsa = require('../rsa')
    const payload = 'This is a super secret message.'

    it('Should encrypt and decrypt using RSA 2048 key pair', async () => {
      const keyPair = await rsa.generateKeyPair(2048)
      let ciphertext = await rsa.encrypt(keyPair.publicKey, payload)
      let plain = await rsa.decrypt(keyPair.privateKey, ciphertext)

      expect(payload).to.equal(plain.toString())
    })

    it('Should sign and verify using a RSA 2048 key pair', async () => {
      const keyPair = await rsa.generateKeyPair(2048)
      let signature = await rsa.signPayload(payload, keyPair.privateKey)
      let verified = await rsa.verifyPayloadSignature(payload, signature, keyPair.publicKey)

      expect(verified).to.equal(true)
    })

    it('Should encrypt and decrypt using RSA 4096 key pair', async () => {
      const keyPair = await rsa.generateKeyPair(4096)
      let ciphertext = await rsa.encrypt(keyPair.publicKey, payload)
      let plain = await rsa.decrypt(keyPair.privateKey, ciphertext)
      expect(payload).to.equal(plain.toString())
    })

    it('Should sign and verify using a RSA 4096 key pair', async () => {
      const keyPair = await rsa.generateKeyPair(4096)
      let signature = await rsa.signPayload(payload, keyPair.privateKey)
      let verified = await rsa.verifyPayloadSignature(payload, signature, keyPair.publicKey)

      expect(verified).to.equal(true)
    })
  })
})
