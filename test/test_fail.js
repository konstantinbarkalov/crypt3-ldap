var should = require('should')
var ldapHash = require('../lib/ldapHash')
var crypto = require('crypto')

describe('bad things (must fail)',function(){
    describe('bad mode',function(){
        it('should not be checkable',function(done){
                let passwd='pwd', 
                    hash='{SSHB}c6AhsUGD7NfYyTofZoKiuP5MDqjAcKGi';
                ldapHash.checkHash(passwd, hash).then((result)=> {
                    should.not.exist(result);
                    done();
                }).catch((err)=> {
                    should.exist(err);
                    err.message.should.equal('unsupported mode');
                    done();
                });
        })
    })
})
