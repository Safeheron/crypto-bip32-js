import * as assert from 'assert'
import * as elliptic from 'elliptic'
import * as BN from 'bn.js'
import {Secp256k1HDKey, P256HDKey, Ed25519HDKey} from "..";

const SEED = '000102030405060708090a0b0c0d0e0f'

const curves: [string, any, BN][] = [
    ['Secp256k1HDKey', Secp256k1HDKey, new elliptic.ec('secp256k1').n],
    ['P256HDKey', P256HDKey, new elliptic.ec('p256').n],
    ['Ed25519HDKey', Ed25519HDKey, new elliptic.eddsa('ed25519').curve.n],
]

const notTypeError = (e: any) => !(e instanceof TypeError)

describe('BN input safety test', function () {
    for (const [name, HDKey, n] of curves) {
        describe(name, function () {
            it('rejects negative private key (BN)', function () {
                const hdkey = new HDKey()
                assert.throws(() => { hdkey.privateKey = new BN(-1) }, notTypeError)
                assert.throws(() => { hdkey.privateKey = n.neg() }, notTypeError)
            })

            const badStrings: [string, string][] = [
                ['negative', '-' + '0'.repeat(62) + '1'],
                ['non-hex chars', '0' + 'g'.repeat(63)],
                ['0x prefix', '0x' + '1'.repeat(62)],
                ['whitespace', ' ' + '1'.repeat(63)],
            ]
            for (const [label, value] of badStrings) {
                it(`rejects ${label} private key string`, function () {
                    const hdkey = new HDKey()
                    assert.throws(() => { hdkey.privateKey = value }, notTypeError)
                })
            }

            const badTypes: [string, any][] = [
                ['number', 123],
                ['null', null],
                ['undefined', undefined],
                ['Buffer', Buffer.alloc(32, 1)],
                ['plain object', {}],
            ]
            for (const [label, value] of badTypes) {
                it(`rejects ${label} private key`, function () {
                    const hdkey = new HDKey()
                    assert.throws(() => { hdkey.privateKey = value }, (e: any) => e === 'Private key must be a hex string or BN.')
                })
            }

            it('accepts upper-case hex private key string', function () {
                const hdkey = new HDKey()
                hdkey.privateKey = '0' + 'AB'.repeat(31) + 'C'
                assert(hdkey.privateKey.eq(new BN('0' + 'ab'.repeat(31) + 'c', 16)))
            })

            it('does not alias the BN passed to the privateKey setter', function () {
                const value = new BN('0' + '1'.repeat(63), 16)
                const hdkey = new HDKey()
                hdkey.privateKey = value
                const expected = new HDKey()
                expected.privateKey = '0' + '1'.repeat(63)

                value.iaddn(1)

                assert(hdkey.privateKey.eq(expected.privateKey))
                assert(hdkey.publicKey.eq(expected.publicKey))
            })

            it('does not expose the internal BN through the privateKey getter', function () {
                const hdkey = HDKey.fromMasterSeedHex(SEED)
                const expected = HDKey.fromMasterSeedHex(SEED)

                hdkey.privateKey.iaddn(1)

                assert(hdkey.privateKey.eq(expected.privateKey))
                assert(hdkey.publicKey.eq(expected.publicKey))
            })

            it('privateKey getter returns null for a public-only key', function () {
                const master = HDKey.fromMasterSeedHex(SEED)
                const pub = HDKey.fromPublicKeyAndChainCode(master.publicKey, master.chainCode)
                assert.strictEqual(pub.privateKey, null)
            })

            it('does not alias the BN passed to fromPrivateKeyAndChainCode', function () {
                const master = HDKey.fromMasterSeedHex(SEED)
                const value = master.privateKey.clone()
                const hdkey = HDKey.fromPrivateKeyAndChainCode(value, master.chainCode)

                value.iaddn(1)

                assert(hdkey.privateKey.eq(master.privateKey))
                assert.strictEqual(hdkey.xprv, master.xprv)
            })

            it('publicDerive delta is not affected by mutating a previously returned delta', function () {
                const master = HDKey.fromMasterSeedHex(SEED)
                const pub = HDKey.fromPublicKeyAndChainCode(master.publicKey, master.chainCode)

                const [, rootDelta] = pub.publicDerive('m')
                assert(rootDelta.isZero())
                rootDelta.iaddn(7)

                const [, rootDeltaAgain] = pub.publicDerive('m')
                assert(rootDeltaAgain.isZero())

                const [child, delta] = pub.publicDerive('m/1/2')
                const expected = master.derive('m/1/2')
                assert(child.publicKey.eq(expected.publicKey))
                assert(master.privateKey.add(delta).umod(n).eq(expected.privateKey))
            })
        })
    }
})
