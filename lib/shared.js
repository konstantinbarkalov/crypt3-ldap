'use strict';
const crypto = require('crypto');
const hashModes = require('./hashModes');

function checkMode(mode) {
  if ((!hashModes[mode]) || (!hashModes[mode].ldapName) || (!hashModes[mode].crypt3Name)) {
    throw new Error('unsupported mode');
  }
}

function findMode(attrName, attrValue) {
  let keys = Object.keys(hashModes);
  function findFunction(element) {
    return (hashModes[element][attrName] === attrValue);
  }
  return keys.find(findFunction);
}

module.exports = {
  checkMode: checkMode,
  findMode: findMode
}
