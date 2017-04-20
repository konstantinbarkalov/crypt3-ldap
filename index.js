'use strict'
let ssha = {
  ldap: require('./lib/ldapHash'),
  crypt3: require('./lib/crypt3Hash'),
}
module.exports = ssha;
