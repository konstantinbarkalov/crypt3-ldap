'use strict'
let ssha = {
  ldap: require('./lib/ldapHash'),
  crypto3: require('./lib/crypto3Hash'),
}
module.exports = ssha;
