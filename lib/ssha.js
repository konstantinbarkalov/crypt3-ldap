'use strict';
/* global require console Buffer*/
const crypto = require('crypto');

function _ssha(passwd, salt, next) {
  let ctx = crypto.createHash('sha1');
  ctx.update(passwd, 'utf-8');
  ctx.update(salt, 'binary');
  let digest = ctx.digest('binary');
  let ssha = '{SSHA}' + new Buffer(digest + salt, 'binary').toString('base64');
  return next(null, ssha);
}

function ssha_pass(passwd, salt, next) {
  if (next === undefined) {
    next = salt;
    salt = null;
  }
  if (salt === null) {
    crypto.randomBytes(32, function (ex, buf) {
      if (ex) return next(ex);
      _ssha(passwd, buf.toString('base64'), next);
      return null;
    });
  } else {
    _ssha(passwd, salt, next);
  }
  return null;
}

function checkssha(passwd, hash, next) {
  if (hash.substr(0, 6) != '{SSHA}') {
    return next(new Error('not {SSHA}'), false);
  }
  let bhash = new Buffer(hash.substr(6), 'base64');
  let salt = bhash.toString('binary', 20); // sha1 digests are 20 bytes long
  //console.log(salt)
  ssha_pass(passwd, salt, function (err, newssha) {
    if (err) return next(err)
    return next(null, hash === newssha)
  });
  return null;
}

exports.checkssha = checkssha;
exports.ssha_pass = ssha_pass;
