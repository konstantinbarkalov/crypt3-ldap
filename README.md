# Node.js with LDAP and crypt(3)
Utility to parse, check and convert LDAP and [crypt(3)][https://en.wikipedia.org/wiki/Crypt_(C)] salted SHA password hashes in node.js.
Code is based on [jmarca/openldap_ssha](https://github.com/jmarca/openldap_ssha), but:
- rewritten in promised manner;
- SSHA2 support (salted SHA256 and salted SHA512);
- crypt(3) functionality added.

May be used to generate ACL _passwd files_ from _LDAP directory_ for a variety of software, that supports crypt(3) format.

# Tests
Mocha is used for the tests, `npm install` followed by `npm test` or `make test` should run them.
There are some tests originally added by jmarca. Plus some messy tests created to check new functionality, but they need to be refactored.
