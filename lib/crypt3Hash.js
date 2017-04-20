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
  let hash = '$' + hashModes[mode].crypt3Name
                 + '$' + new Buffer(salt, 'binary').toString('base64')
                 + '$' + new Buffer(digest, 'binary').toString('base64');
  return hash;
}

function getHash(passwd, salt, mode) {
  mode = mode || 'ssha256';
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
  let regex = /^\$([^,$]+)\$([^,$]+)\$([^,$]+)$/;
  let regexResult = regex.exec(hash);
  let mode = findMode('crypt3Name', regexResult[1]);
  checkMode(mode);
  let saltStr = regexResult[2]; // base64 string
  let digestStr = regexResult[3];
  let salt = extractSalt(saltStr); // binary form
  let digest = extractDigest(digestStr); // binary form
  return {mode: mode, digest: digest, salt: salt};
}

function extractDigest(digestStr) {
  let bufferedtDigest = new Buffer(digestStr, 'base64');
  let digest = bufferedtDigest.toString('binary');
  return digest;
}

function extractSalt(saltStr) {
  let bufferedSalt = new Buffer(saltStr, 'base64');
  let salt = bufferedSalt.toString('binary');
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
