'use strict';
/* global require console Buffer*/
const crypto = require('crypto');
const hashModes = require('./hashModes');

function checkMode(mode) {
  if ((!hashModes[mode]) || (!hashModes[mode].ldapName)) {
    throw new Error('unsupported mode: '+ mode);
  }
}

function findMode(attrName, attrValue) {
  let keys = Object.keys(hashModes);
  function findFunction(element) {
    return (hashModes[element][attrName] === attrValue);
  }
  return keys.find(findFunction);
}

// ----


function getHashSync(passwd, salt, mode) {
  checkMode(mode);
  let ctx = crypto.createHash(hashModes[mode].cryptoName);
  ctx.update(passwd, 'utf-8');
  ctx.update(salt, 'binary');
  let digest = ctx.digest('binary');
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
  let baseSalt = regexResult[2]; // base64 string
  let baseHash = regexResult[3];
  let salt = extractSalt(baseSalt); // binary form
  return {mode: mode, salt: salt};
}

function extractSalt(baseSalt) {
  let bufferedSalt = new Buffer(baseSalt, 'base64');
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

exports.checkHash = checkHash;
exports.getHash = getHash;
