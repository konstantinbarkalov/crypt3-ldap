'use strict';
/* global require console Buffer*/
const crypto = require('crypto');
const ldapHashModes = require('./ldapHashModes');

function getHashSync(passwd, salt, mode) {
  if (!ldapHashModes[mode]) {
    throw new Error('unsupported mode: '+ mode);
  }
  let ctx = crypto.createHash(ldapHashModes[mode].cryptoParam);
  ctx.update(passwd, 'utf-8');
  ctx.update(salt, 'binary');
  let digest = ctx.digest('binary');
  let hash = '{' + mode + '}' + new Buffer(digest + salt, 'binary').toString('base64');
  return hash;
}

function getHash(passwd, salt, mode) {
  mode = mode || 'SSHA';
  return new Promise((resolve, reject) => {    
    if (!salt) {
      crypto.randomBytes(32, function (err, buf) {
        if (err) { return reject(err) };
        let hash = getHashSync(passwd, buf.toString('base64'), mode);
        resolve(hash);        
      });
    } else {
      let hash = getHashSync(passwd, salt, mode);
      resolve(hash);
    }
  });
}

function splitHash(hash) {
  let regex = /^{(.+)}(.+)$/; // boobs!
  let regexResult = regex.exec(hash);
  let mode = regexResult[1];
  let base = regexResult[2];
  let salt = extractSalt(mode, base);
  return {mode: mode, base: base, salt: salt};
}

function extractSalt(mode, base) {
  if (!ldapHashModes[mode]) {
    throw new Error('unsupported mode: '+ mode);
  }
  let bufferedHash = new Buffer(base, 'base64');
  let hashBytesLength = ldapHashModes[mode].hashBytesLength;
  let salt = bufferedHash.toString('binary', hashBytesLength); // sha1 digests are 20 bytes long
  return salt;
}


function checkHash(passwd, hash) { 
  let splittedHash;
  try { //can fail on unsupported and abnormal mode signatures
    splittedHash = splitHash(hash);
  } catch (err) {
    return Promise.reject(err);
  }
  //console.log(salt)
  return getHash(passwd, splittedHash.salt, splittedHash.mode).then((newhash) => {
    return hash === newhash;
  });
}

exports.checkHash = checkHash;
exports.getHash = getHash;
