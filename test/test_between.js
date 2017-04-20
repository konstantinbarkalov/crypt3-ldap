var should = require('should');
var ldapHash = require('../lib/ldapHash');
var crypt3Hash = require('../lib/crypt3Hash');
var crypto = require('crypto')

describe('conversion',function(){
    describe('rewrapping from ldap to crypt3 back and forth and then check',function(){
        it('should verify',function(done){
          let known_pass = 'commonpwd';
          crypt3Hash.getHash(known_pass).then((hash)=>{
            //console.log('init', hash);
            let splitResultC = crypt3Hash.splitHash(hash);
            //console.log('splitResultC', splitResultC);
            let weldResultC = crypt3Hash.weldHash(splitResultC.digest, splitResultC.salt, splitResultC.mode);
            //console.log('weldResult', weldResultC);
            let weldResultL = ldapHash.weldHash(splitResultC.digest, splitResultC.salt, splitResultC.mode);
            //console.log('weldResultL', weldResultL);
            let splitResultL = ldapHash.splitHash(weldResultL);
            //console.log('splitResultL', splitResultL);
            let weldResultLC = crypt3Hash.weldHash(splitResultL.digest, splitResultL.salt, splitResultL.mode);
            //console.log('weldResultLC', weldResultLC);
  
            ldapHash.checkHash(known_pass, weldResultL).then((result)=> {
                should.exist(result);
                result.should.equal(true);
                crypt3Hash.checkHash(known_pass, weldResultLC).then((result)=> {
                    should.exist(result);
                    result.should.equal(true);
                    done();
                }).catch((err)=> {
                    should.not.exist(err);
                });
            }).catch((err)=> {
                should.not.exist(err);
            });
          
          })          
        })
    })
})
