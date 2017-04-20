var should = require('should')
var ldapHash = require('../lib/ldapHash')
var crypto = require('crypto')

describe('checkHash',function(){
    describe('known password and SSHA2 hash',function(){
        it('should verify the SSHA256 value from slappasswd code 1/2',function(done){
            var known_hash = '{SSHA256}Eq8sTph8Iak5F3kXPkUeBPTxMV3jSZBjB10SwRwk1zwlxNkgnXMlMolCt9t8LwHvS4EGpzKVqUapx+bkeUzQCQ==';
            var known_pass = 'fuc';
            ldapHash.checkHash(known_pass,known_hash).then((result)=> {
                should.exist(result);
                result.should.equal(true);
                done();
            }).catch((err)=> {
                should.not.exist(err);
            });
        })
        it('should verify the SSHA512 value from slappasswd code 2/2',function(done){
            var known_hash = '{SSHA512}4XgDRit3/qU+zUQoUQnfG5Zhvh3jZAjpIa8N5PPbwY96tPkzlJIT7g1lUuz5QmVwO+5z/1o9aZ6b99eul4W9RCd96vYe/38K23XPufk4YXxUx1s65r6ZDDMF1b9uLv2oe8lLegt1p7Yt7Bg/U7EeiOEAnkfgHvgu8nFMLXeP8Sk=';
            var known_pass = 'pwd';
            ldapHash.checkHash(known_pass,known_hash).then((result)=> {
                should.exist(result);
                result.should.equal(true);
                done();
            }).catch((err)=> {
                should.not.exist(err);
            });
        })

    })
})
