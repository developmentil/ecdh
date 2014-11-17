var ecdh = require('../index');

// Pick some curve
var curve = ecdh.getCurve('secp128r1'),

// Generate random key
privateKey = ecdh.PrivateKey.generate(curve),
// generate public key from private key
publicKey = privateKey.derivePublicKey();

// Or you may get the key from a buffer:
// privateKey = ecdh.PrivateKey.fromBuffer(curve, buf2);

console.log('private key length:', privateKey.buffer.length);
console.log('private key:', privateKey.buffer.toString('hex'));
console.log('public key length:', publicKey.buffer.length);
console.log('public key:', publicKey.buffer.toString('hex'));