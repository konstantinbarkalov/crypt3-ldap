var should = require('should')
var crypt3Hash = require('../lib/crypt3Hash')
var crypto = require('crypto')

describe('checkHash',function(){
    describe('known password and crypt3-SSHA2 hash',function(){
        it('should verify the crypt3-SSHA512 value from slappasswd code 1/2',function(done){
            var known_hash = '$6$ICJ3N9ChAGpFpGA4$JwckTIzLyBbMO/2lZrw539r9VT91lNr2nPghheMIHRGPZicc28lUp3tvGt3Nh6h3csCFEGZ+w02/l1n6HRZO3Q==';
            var known_pass = 'alesha';
            crypt3Hash.checkHash(known_pass,known_hash).then((result)=> {
                should.exist(result);
                result.should.equal(true);
                done();
            }).catch((err)=> {
                should.not.exist(err);
            });
        })
        it('should verify the crypt3-SSHA512 value from slappasswd code 2/2',function(done){
            var known_hash = '$6$N6Zso3WF1dXt+4em$+MMIXf0Mo1+GYGGEYdPa4DlgbsIHbCuzObJWsEgdxn/yeS4B8moLqkqZsCCL09UCMQGyZcL3eRLicW+aW+nFgw==';
            var known_pass = 'borat';
            crypt3Hash.checkHash(known_pass,known_hash).then((result)=> {
                should.exist(result);
                result.should.equal(true);
                done();
            }).catch((err)=> {
                should.not.exist(err);
            });
        })

    })
})
