var crypto = require('crypto'),
	ecdh = require('../index');

// Pick some curve
var curve = ecdh.getCurve('secp256k1'),
		
// Choose algorithm to the hash function
algorithm = 'sha256',

// Generate random keys for Alice
aliceKeys = ecdh.generateKeys(curve);
	
// Hash something so we can have a digest to sign
var message = new Buffer('Hello World'),
hash = crypto.createHash(algorithm).update(message).digest();
console.log('Hashed message to sign:', hash.toString('hex'));

// Sign it with Alice's key
var signature = aliceKeys.privateKey.sign(hash, algorithm);
console.log('Signature:', signature.toString('hex'));

// Verify it with Alice public key
var valid = aliceKeys.publicKey.verifySignature(hash, signature);
console.log('Signature is', valid ? 'valid :)' : 'invalid!!');