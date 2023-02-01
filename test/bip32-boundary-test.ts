import * as assert from 'assert'
import * as cryptoJS from "crypto-js"
import * as elliptic from 'elliptic'
const P256 = new elliptic.ec('p256')
const Secp256k1 = new elliptic.ec('secp256k1')
import {Secp256k1HDKey as HDKey} from "..";
import {Hex} from "@safeheron/crypto-utils";
describe('Secp256k1 boundary test', function () {
    it('Invalid path', async function () {
        var seed = 'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542'
        var hdkey = HDKey.fromMasterSeed(cryptoJS.enc.Hex.parse(seed))
        let flag_exception = false
        try{
            let illegalPath1 = "m////"
            let illegalPath2 = " / / / / "
            let illegalPath3 = "m/ 223/336 "
            let hdkey_child1= hdkey.derive(illegalPath1)
            let hdkey_child2 = hdkey.derive(illegalPath2)
            let hdkey_child3 = hdkey.derive(illegalPath3)
            console.log(hdkey.xprv)
            console.log(hdkey_child1.xprv)
            console.log(hdkey_child2.xprv)
            console.log(hdkey_child3.xprv)

            console.log('\n\n')
        }catch (e) {
            flag_exception = true
        }
        assert(flag_exception)
    })
})