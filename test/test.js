var should = require('should')
var ldapHash = require('../lib/ldapHash')
var crypto = require('crypto')


var passwd = 'secret';
var salt = 'salt';

var randompass = crypto.randomBytes(32).toString('base64');


var non_ascii_passwd = 'éñÈhello£力';
var precalculated_salt = 'e1eudpva6DrI7sq2UWjiJrDsXONjAizB9y2ed05ozC8=';

describe('getHash',function(){
    describe('known password and salt',function(){
        it('should equal the value from Perl code',function(done){
            ldapHash.getHash(passwd, salt).then((hash)=>{
                should.exist(hash);
                hash.should.equal('{SSHA}gVK8WC9YyFT1gMsQHTGCgT3sSv5zYWx0');
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


    describe('arbitrary password and salt',function(){
        it('should be checkable',function(done){
            ldapHash.getHash(randompass).then((hash)=>{
                should.exist(hash);
                return ldapHash.checkHash(randompass,hash).then((result)=> {
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


    describe('password with non-ascii characters',function(){
        it('should be checkable',function(done){
            ldapHash.getHash(non_ascii_passwd, precalculated_salt).then((hash)=>{
                should.exist(hash);
                hash.should.equal('{SSHA}3TBLUFQ6BeTMRTiS/XjwwMza0F9lMWV1ZHB2YTZEckk3c3EyVVdqaUpyRHNYT05qQWl6Qjl5MmVkMDVvekM4PQ==');
                return ldapHash.checkHash(non_ascii_passwd,hash).then((result)=> {
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
describe('checkHash',function(){
    describe('known password and hash',function(){
        it('should verify the value from slappasswd code 1/2',function(done){
            var known_hash = '{SSHA}c6AhsUGD7NfYyTofZoKiuP5MDqjAcKGi';
            var known_pass = 'secret';
            ldapHash.checkHash(passwd,known_hash).then((result)=> {
                should.exist(result);
                result.should.equal(true);
                done();
            }).catch((err)=> {
                should.not.exist(err);
            });
        })
        it('should verify the value from slappasswd code 2/2',function(done){
            var known_hash = '{SSHA}WyQeTLbK0tJ9eOVr296u6PElsnKddCLm';
            var known_pass = 'secret';
            ldapHash.checkHash(passwd,known_hash).then((result)=> {
                should.exist(result);
                result.should.equal(true);
                done();
            }).catch((err)=> {
                should.not.exist(err);
            });
        })
    })
})
