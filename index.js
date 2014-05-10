var crypto = require('crypto');

/**
 * Bytesize.
 */
var len = 128;

/**
 * Iterations. ~300ms
 */
var iterations = 12000;

/**
 * Set length to `n`.
 *
 * @param {Number} n
 * @api public
 */
exports.length = function(n){
	if (0 === arguments.length) return len;
	len = n;
};

/**
 * Set iterations to `n`.
 *
 * @param {Number} n
 * @api public
 */
exports.iterations = function(n){
	if (0 === arguments.length) return iterations;
	iterations = n;
};

/**
 * generate a salt&hash for 'pass' and invoke 'fn(err, salt, hash)'
 * pwd: password to hash
 * fn: fn(err, salt, hash)
 */
exports.hash = function(pwd, fn){
	if (!pwd) return fn(new Error('password missing'));
	crypto.randomBytes(len, function(err, salt){
		if (err) return fn(err);
		salt = salt.toString('base64');
		crypto.pbkdf2(pwd, salt, iterations, len, function(err, hash){
			if (err) return fn(err);
			fn(null, salt, hash.toString('base64'));
		});
	});
};

/**
 * hash password with salt
 * pwd: password to hash
 * salt: salt
 * fn: fn(err, hash)
 */
exports.hash2 = function(pwd, salt, fn){
	if (3 != arguments.length) return fn(new Error("args of dehash isn't 3!"));

	if (!pwd) return fn(new Error('password missing'));
	if (!salt) return fn(new Error('salt missing'));
	crypto.pbkdf2(pwd, salt, iterations, len, function(err, hash){
		if (err) return fn(err);
		fn(null, hash.toString('base64'));
	});
};



