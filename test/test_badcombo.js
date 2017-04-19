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
            ldapHash.getHash(passwd,salt, function(err,hash){
                should.not.exist(err);
                should.exist(hash);
                ldapHash.checkHash(passwd,hash,function(err,result){
                    should.not.exist(err);
                    should.exist(result);
                    result.should.equal(true);
                    done();
                })
            })
        })
    })
})
