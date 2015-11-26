var crypto = require('crypto'),
	BigInteger = require('jsbn').BigInteger,
	ECPointFp = require('./jsbn/ec.js').ECPointFp;


/*** Static functions ***/

exports.BigInteger = BigInteger;
exports.Curves = require('./jsbn/sec.js');

exports.getCurve = function(name) {
	if(!exports.Curves[name])
		throw new Error('Curve `' + name + '` is not supported');
	
	return exports.Curves[name]();
};

exports.getBytesLength = function(curve) {
	return Math.ceil(curve.getN().bitLength() * 0.125);
};

exports.generateR = function(curve, callback) {
	var n = curve.getN();
	return crypto.randomBytes(n.bitLength(), callback);
};

exports.generateKeys = function(curve, r) {
	var privateKey = PrivateKey.generate(curve, r);
	
	return {
		publicKey: privateKey.derivePublicKey(),
		privateKey: privateKey
	};
};


/*** PublicKey class ***/

//var HEADER_XY = 0x04,
//	HEADER_X_EVEN = 0x02,
//	HEADER_X_ODD = 0x03,

var PublicKey = exports.PublicKey = function(curve, Q, buf) {
	this.curve = curve;
	this.Q = Q;
	
	if(buf) {
		this.buffer = buf;
	} else {
		var bytes = exports.getBytesLength(curve),
			size = (bytes * 2);

		this.buffer = new Buffer(size);
		fillBuffer(this.Q.getX().toBigInteger().toString(16), bytes, this.buffer, 0);
		fillBuffer(this.Q.getY().toBigInteger().toString(16), bytes, this.buffer, bytes);
	}
};

PublicKey.fromBuffer = function(curve, buf) {
	var bytes = exports.getBytesLength(curve),
		size = (bytes * 2);

	if(buf.length !== size)
		throw new Error('Invaild buffer length');

	var x = buf.slice(0, bytes), // skip the 04 for uncompressed format
		y = buf.slice(bytes),
		c = curve.getCurve(),

	P = new ECPointFp(c, 
		c.fromBigInteger(new BigInteger(x.toString('hex'), 16)), 
		c.fromBigInteger(new BigInteger(y.toString('hex'), 16))
	);
		
	return new PublicKey(curve, P, buf);
};

//PublicKey.compress = function() {
//	// this will work only on U curve
//	
//	var x = this.Q.getX().toBigInteger(),
//		y = this.Q.getY().toBigInteger();
//
//	var xBa = hexToBuffer(x.toString(16), 'hex'),
//	buf = new Buffer(xBa.length+1);
//
//	if (y.isEven())
//		buf[0] = HEADER_X_EVEN;
//	else
//		buf[0] = HEADER_X_ODD;
//
//	xBa.copy(buf, 1);
//	return buf;
//};

PublicKey.prototype.verifySignature = function(hash, signature) {
	var data = deserializeSig(signature),
	r = data.r,
	s = data.s,
	Q = this.Q,
	e = new BigInteger(hash.toString('hex'), 16),
	n = this.curve.getN(),
	G = this.curve.getG();

    if(r.compareTo(BigInteger.ONE) < 0 || r.compareTo(n) >= 0)
		return false;

    if(s.compareTo(BigInteger.ONE) < 0 || s.compareTo(n) >= 0)
		return false;

    var c = s.modInverse(n),
	u1 = e.multiply(c).mod(n),
	u2 = r.multiply(c).mod(n),
	
	// TODO we may want to use Shamir's trick here:
	point = G.multiply(u1).add(Q.multiply(u2)),
	
	v = point.getX().toBigInteger().mod(n);

    return v.equals(r);
};


/*** PrivateKey class ***/

var PrivateKey = exports.PrivateKey = function(curve, key, buf) {
	this.curve = curve;
	this.d = key;
	
	if(buf) {
		this.buffer = buf;
		this._size = buf.length;
	} else {
		this._size = exports.getBytesLength(curve);
		this.buffer = zeroBuffer(key.toString(16), this._size);
	}
};

PrivateKey.generate = function(curve, r) {
	r = new BigInteger(r || exports.generateR(curve));
	
	var n1 = curve.getN().subtract(BigInteger.ONE),
	priv = r.mod(n1).add(BigInteger.ONE);
	
	return new PrivateKey(curve, priv);
};

PrivateKey.fromBuffer = function(curve, buf) {
	var size = exports.getBytesLength(curve);

	if(buf.length !== size)
		throw new Error('Invaild buffer length');
	
	var key = new BigInteger(buf.toString('hex'), 16);
	return new PrivateKey(curve, key, buf);
};

PrivateKey.prototype.derivePublicKey = function() {
	var P = this.curve.getG().multiply(this.d);
	
	return new PublicKey(this.curve, P);
};

PrivateKey.prototype.deriveSharedSecret = function(publicKey) {
	if(!publicKey || !publicKey.Q)
		throw new Error('publicKey is invaild');
	
    var S = publicKey.Q.multiply(this.d);
    return zeroBuffer(S.getX().toBigInteger().toString(16), this._size);
};

PrivateKey.prototype.sign = function(hash, algorithm) {
	if(!hash || !hash.length)
		throw new Error('hash is invaild');
	if(!algorithm)
		throw new Error('hash algorithm is required');
	
	var n = this.curve.getN(),
	e = new BigInteger(hash.toString('hex'), 16),
	length = exports.getBytesLength(this.curve);
	
	do {
		var k = deterministicGenerateK(hash, this.buffer, algorithm, length),
		G = this.curve.getG(),
		Q = G.multiply(k),
		r = Q.getX().toBigInteger().mod(n);
	} while(r.compareTo(BigInteger.ZERO) <= 0);
	
	var s = k.modInverse(n).multiply(e.add(this.d.multiply(r))).mod(n);
	
	return serializeSig(r, s);
};


/*** local helpers ***/

var DER_SEQUENCE = 0x30,
	DER_INTEGER = 0x02;

function hexToBuffer(hex) {
	if(hex.length % 2 === 1)
		hex = '0' + hex;
	
	return new Buffer(hex, 'hex');
}

function zeroBuffer(hex, bytes) {
	return fillBuffer(hex, bytes, new Buffer(bytes), 0);
}

function fillBuffer(hex, bytes, buf, start) {
	if(hex.length % 2 === 1)
		hex = '0' + hex;
	
	var length = (hex.length * 0.5),
	pos = start + bytes-length;
	
	buf.fill(0, start, pos);
	buf.write(hex, pos, length, 'hex');
	
	return buf;
}

// generate K value based on RFC6979
function deterministicGenerateK(hash, key, algorithm, length) {	
	var v = new Buffer(length),
		k = new Buffer(length);

	v.fill(1);
	k.fill(0);
	
	var hmac = crypto.createHmac(algorithm, k);
	hmac.update(v);
	hmac.update(new Buffer([0]));
	hmac.update(key);
	hmac.update(hash);
	k = hmac.digest();
	
	hmac = crypto.createHmac(algorithm, k);
	hmac.update(v);
	v = hmac.digest();
	
	hmac = crypto.createHmac(algorithm, k);
	hmac.update(v);
	hmac.update(new Buffer([1]));
	hmac.update(key);
	hmac.update(hash);
	k = hmac.digest();
	
	hmac = crypto.createHmac(algorithm, k);
	hmac.update(v);
	v = hmac.digest();
	
	hmac = crypto.createHmac(algorithm, k);
	hmac.update(v);
	v = hmac.digest();
	
	return new BigInteger(v.toString('hex'), 16);
}

function serializeSig(r, s) {
	var rBa = hexToBuffer(r.toString(16), 'hex');
	var sBa = hexToBuffer(s.toString(16), 'hex');
	
	var buf = new Buffer(6 + rBa.length + sBa.length),
	end = buf.length - sBa.length;
	
	buf[0] = DER_SEQUENCE;
	buf[1] = buf.length - 2;
	
	buf[2] = DER_INTEGER;
	buf[3] = rBa.length;
	rBa.copy(buf, 4);
	
	buf[end-2] = DER_INTEGER;
	buf[end-1] = sBa.length;
	sBa.copy(buf, end);

	return buf;
}

function deserializeSig(buf) {
	if(buf[0] !== DER_SEQUENCE)
		throw new Error("Signature is not a valid DERSequence");
	
	if(buf[1] > buf.length-2)
		throw new Error("Signature length is too short");
	
	if(buf[2] !== DER_INTEGER)
		throw new Error("First element in signature must be a DERInteger");
	
	var pos = 4,
	rBa = buf.slice(pos, pos+buf[3]);
	
	pos += rBa.length;
	if(buf[pos++] !== DER_INTEGER)
		throw new Error("Second element in signature must be a DERInteger");
	
	var sBa = buf.slice(pos+1, pos+1+buf[pos]);
	
	return {
		r: new BigInteger(rBa.toString('hex'), 16),
		s: new BigInteger(sBa.toString('hex'), 16)
	};
}