'use strict';
/* global require console Buffer*/
const crypto = require('crypto');

function getHashSync(passwd, salt) {
  let ctx = crypto.createHash('sha1');
  ctx.update(passwd, 'utf-8');
  ctx.update(salt, 'binary');
  let digest = ctx.digest('binary');
  let hash = '{SSHA}' + new Buffer(digest + salt, 'binary').toString('base64');
  return hash;
}

function getHash(passwd, salt) {
  return new Promise((resolve, reject) => {
    if (!salt) {
      crypto.randomBytes(32, function (err, buf) {
        if (err) { return reject(err) };
        let hash = getHashSync(passwd, buf.toString('base64'));
        resolve(hash);        
      });
    } else {
      let hash = getHashSync(passwd, salt);
      resolve(hash);
    }
  });
}

function checkHash(passwd, hash, next) {
  if (hash.substr(0, 6) != '{SSHA}') {
    return Promise.reject(new Error('not {SSHA}'))
  }
  let bhash = new Buffer(hash.substr(6), 'base64');
  let salt = bhash.toString('binary', 20); // sha1 digests are 20 bytes long
  //console.log(salt)
  return getHash(passwd, salt).then((newhash) => {
    return hash === newhash;
  });
}

exports.checkHash = checkHash;
exports.getHash = getHash;
