'use strict';
/* global require console Buffer*/
const crypto = require('crypto');

function getHashStrict(passwd, salt, next) {
  let ctx = crypto.createHash('sha1');
  ctx.update(passwd, 'utf-8');
  ctx.update(salt, 'binary');
  let digest = ctx.digest('binary');
  let hash = '{SSHA}' + new Buffer(digest + salt, 'binary').toString('base64');
  return next(null, hash);
}

function getHash(passwd, salt, next) {
  if (next === undefined) {
    next = salt;
    salt = null;
  }
  if (salt === null) {
    crypto.randomBytes(32, function (ex, buf) {
      if (ex) return next(ex);
      getHashStrict(passwd, buf.toString('base64'), next);
      return null;
    });
  } else {
    getHashStrict(passwd, salt, next);
  }
  return null;
}

function checkHash(passwd, hash, next) {
  if (hash.substr(0, 6) != '{SSHA}') {
    return next(new Error('not {SSHA}'), false);
  }
  let bhash = new Buffer(hash.substr(6), 'base64');
  let salt = bhash.toString('binary', 20); // sha1 digests are 20 bytes long
  //console.log(salt)
  getHash(passwd, salt, function (err, newhash) {
    if (err) return next(err)
    return next(null, hash === newhash)
  });
  return null;
}

exports.checkHash = checkHash;
exports.getHash = getHash;
