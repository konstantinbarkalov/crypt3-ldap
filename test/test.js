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
            ldapHash.getHash(passwd, 'salt' , function(err,hash){
                should.not.exist(err);
                should.exist(hash);
                hash.should.equal('{SSHA}gVK8WC9YyFT1gMsQHTGCgT3sSv5zYWx0');
                ldapHash.checkHash(passwd,hash,function(err,result){
                    should.not.exist(err);
                    should.exist(result);
                    result.should.equal(true);
                    done();
                })
            })
        })
    })
    describe('arbitrary password and salt',function(){
        it('should be checkable',function(done){
            ldapHash.getHash(randompass, function(err,hash){
                should.not.exist(err);
                should.exist(hash);
                ldapHash.checkHash(randompass,hash,function(err,result){
                    should.not.exist(err);
                    should.exist(result);
                    result.should.equal(true);
                    done();
                })
            })
        })
    })
    describe('password with non-ascii characters',function(){
        it('should be checkable',function(done){
            ldapHash.getHash(non_ascii_passwd, precalculated_salt, function(err,hash){
                should.not.exist(err);
                should.exist(hash);
                hash.should.equal('{SSHA}3TBLUFQ6BeTMRTiS/XjwwMza0F9lMWV1ZHB2YTZEckk3c3EyVVdqaUpyRHNYT05qQWl6Qjl5MmVkMDVvekM4PQ==');
                ldapHash.checkHash(non_ascii_passwd,hash,function(err,result){
                    should.not.exist(err);
                    should.exist(result);
                    result.should.equal(true);
                    done();
                })
            })
        })
    })
})
describe('checkHash',function(){
    describe('known password and hash',function(){
        it('should verify the value from slappasswd code 1/2',function(done){
            var known_hash = '{SSHA}c6AhsUGD7NfYyTofZoKiuP5MDqjAcKGi';
            var known_pass = 'secret';
            ldapHash.checkHash(passwd,known_hash,function(err,result){
                should.not.exist(err);
                should.exist(result);
                result.should.equal(true);
                done();
            })
        })
        it('should verify the value from slappasswd code 2/2',function(done){
            var known_hash = '{SSHA}WyQeTLbK0tJ9eOVr296u6PElsnKddCLm';
            var known_pass = 'secret';
            ldapHash.checkHash(passwd,known_hash,function(err,result){
                should.not.exist(err);
                should.exist(result);
                result.should.equal(true);
                done();
            })
        })
    })
})
