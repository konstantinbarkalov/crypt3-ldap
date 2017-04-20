'use strict';
const crypto = require('crypto');
const hashModes = require('./hashModes');

const shared = require('./shared');
let checkMode=shared.checkMode;
let findMode=shared.findMode;

// ----

function getHashSync(passwd, salt, mode) {
  checkMode(mode);
  let ctx = crypto.createHash(hashModes[mode].cryptoName);
  ctx.update(passwd, 'utf-8');
  ctx.update(salt, 'binary');
  let digest = ctx.digest('binary');
  let hash = weldHash(digest, salt, mode);
  return hash;
}

function weldHash(digest, salt, mode) {
  checkMode(mode);
  let hash = '{' + hashModes[mode].ldapName + '}' + new Buffer(digest + salt, 'binary').toString('base64');
  return hash;
}


function getHash(passwd, salt, mode) {
  mode = mode || 'ssha1';
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
  let modeStr = regexResult[1];
  let mode = findMode('ldapName', modeStr);
  checkMode(mode);
  let digestAndSaltStr = regexResult[2];
  let digest = extractDigest(mode, digestAndSaltStr);
  let salt = extractSalt(mode, digestAndSaltStr);
  return {mode: mode, digest: digest, salt: salt};
}

function extractDigest(mode, digestAndSaltStr) {
  checkMode(mode);
  let bufferedDigestAndSalt = new Buffer(digestAndSaltStr, 'base64');
  let hashBytesLength = hashModes[mode].hashBytesLength;
  let digest = bufferedDigestAndSalt.toString('binary', 0, hashBytesLength); // sha1 digests are 20 bytes long
  return digest;
}

function extractSalt(mode, digestAndSaltStr) {
  checkMode(mode);
  let bufferedDigestAndSalt = new Buffer(digestAndSaltStr, 'base64');
  let hashBytesLength = hashModes[mode].hashBytesLength;
  let salt = bufferedDigestAndSalt.toString('binary', hashBytesLength); // sha1 digests are 20 bytes long
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

exports.weldHash = weldHash;
exports.splitHash = splitHash;
exports.checkHash = checkHash;
exports.getHash = getHash;
