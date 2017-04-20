var should = require('should')
var ldapHash = require('../lib/ldapHash')
var crypto = require('crypto')


var passwd = 'foo';
var salt = 'saltt';

var randompass = crypto.randomBytes(32).toString('base64');

var known_hash = '{SSHA}c6AhsUGD7NfYyTofZoKiuP5MDqjAcKGi';

describe('reported issue 1',function(){
    describe('specific password and salt',function(){
        it('should be checkable',function(done){
            ldapHash.getHash(passwd,salt).then((hash)=>{
                should.exist(hash);
                //hash.should.equal(known_hash);
                return ldapHash.checkHash(passwd,hash).then((result)=> {
                    should.exist(result);
                    result.should.equal(true);
                    done();
                }).catch((err)=> {
                    should.not.exist(err);
                });
            }).catch((err)=>{
                should.not.exist(err);
            });
        })
    })
})
