import * as assert from 'assert'
import * as elliptic from 'elliptic'
import * as BN from 'bn.js'
import {Secp256k1HDKey, P256HDKey, Ed25519HDKey} from "..";

const curves: [string, any, BN][] = [
    ['Secp256k1HDKey', Secp256k1HDKey, new elliptic.ec('secp256k1').n],
    ['P256HDKey', P256HDKey, new elliptic.ec('p256').n],
    ['Ed25519HDKey', Ed25519HDKey, new elliptic.eddsa('ed25519').curve.n],
]

describe('Private key curve order boundary test', function () {
    for (const [name, HDKey, n] of curves) {
        describe(name, function () {
            for (const [label, value] of [['0', new BN(0)], ['n', n], ['n + 1', n.addn(1)]] as [string, BN][]) {
                it(`rejects private key equal to ${label} (hex string)`, function () {
                    const hdkey = new HDKey()
                    assert.throws(() => { hdkey.privateKey = value.toString(16, 64) }, (e: any) => !(e instanceof TypeError))
                })

                it(`rejects private key equal to ${label} (BN)`, function () {
                    const hdkey = new HDKey()
                    assert.throws(() => { hdkey.privateKey = value.clone() }, (e: any) => !(e instanceof TypeError))
                })
            }

            it('accepts private key equal to n - 1', function () {
                const hdkey = new HDKey()
                hdkey.privateKey = n.subn(1).toString(16, 64)
                assert(hdkey.privateKey.eq(n.subn(1)))
                assert(hdkey.publicKey)
            })
        })
    }
})
