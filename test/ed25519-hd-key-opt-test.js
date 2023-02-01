// Supported in future
'use strict'

const assert = require('assert')
const BN = require('bn.js');

const elliptic = require('elliptic');
const P256 = new elliptic.ec('p256')
const Secp256k1 = new elliptic.ec('secp256k1')
const Ed25519 = new elliptic.eddsa('ed25519')

const bip32 = require("..")
const HDKey = bip32.Ed25519HDKey
const utils = require("../lib/common/utils")

describe('Ed25519 Bip32', function () {
    it('HDKey.fromMasterSeed', async function () {
        let seedHex = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a2"
        let hdkey = HDKey.fromMasterSeed(seedHex)
        console.log(utils.toHex(hdkey.privateKeyL.toArray('le', 32)))
        console.log(utils.toHex(hdkey.privateKeyR.toArray('le', 32)))
        console.log(utils.toHex(Ed25519.encodePoint(hdkey.publicKey)))
        console.log(utils.toHex(hdkey.chainCode.toArray('le', 32)))
        assert(hdkey.privateKeyL.eq(new BN("c87e455e069ef51c4cea4a702477f72303bfac09e2a5ec3b7d33b0284ce2c054", 16, 'le')))
        assert(hdkey.privateKeyR.eq(new BN("3a5e58700dfb5b568c933073b3470bc1477d9d9778dd2d6ad9914a53bd36afd2", 16, 'le')))
        assert(hdkey.chainCode.eq(new BN("4dd9d338bb17939ab4bd4eaa0d16a866090750e9a3ab2b3972016f0db5c98a96", 16, 'le')))

        let exPK = hdkey.publicExtendedKey
        let hdKey2 = HDKey.fromExtendedKey(exPK)
        let exPK2 = hdKey2.publicExtendedKey
        console.log('exPK:  ', exPK)
        console.log('exPK2: ', exPK2)
        assert(hdkey.publicKey.eq(hdKey2.publicKey))
        console.log('\n\n')
    });

    it('Import and export extended key', async function () {
        for(let i = 0; i < 100; i ++){
            let seed = await Rand.randomBN(32)
            let seedHex = utils.padToLength(seed.toString(16), 32)
            let hdkey = HDKey.fromMasterSeed(seedHex)

            let hdKey2 = HDKey.fromExtendedKey(hdkey.privateExtendedKey)
            let hdKey3 = HDKey.fromExtendedKey(hdkey.publicExtendedKey)

            assert(hdKey2.privateKeyL.eq(hdkey.privateKeyL))
            assert(hdKey2.privateKeyR.eqn(0))
            assert(hdKey2.publicKey.eq(hdkey.publicKey))
            assert(hdKey2.privateExtendedKey === hdkey.privateExtendedKey)
            assert(hdKey2.publicExtendedKey === hdkey.publicExtendedKey)

            assert(hdKey3.publicKey.eq(hdkey.publicKey))
            assert(hdKey3.publicExtendedKey === hdkey.publicExtendedKey)
        }

        console.log('\n\n')
    });

    it('Soft derive', async function () {
        let data = [
            {kl: "908b9246562dadcd57ff5a98f983237008d274273cd390e99af885a654e2c054"
                ,kr: "788a780df8db64b53fb417547943904818f468932f1ba4190ca381c66e9d794d"
                ,A: "ced4532c9b9a48955b01115da1a95b870717b9e9bf1bd0336aecfa39b980ba55"
                ,c: "abcf2a39214dcd06858af60ba0f6ca22876278a0e59ed5ece075d89adade92a6"},
            {kl: "10ce25c753172f99d97121cf56d8f3238b62d00098c15d17923689c754e2c054"
                ,kr: "c96eb5c5b47edc2d578263532b310a45c540d91fdd5c568b8718f633b8645b0d"
                ,A: "a33dc311f43b4eeb0bec3581d257d706e28a109d38ca387b0cd7a9d0d16b99bb"
                ,c: "ba0be8fe721595ddd354443b886a18f488ea0acb10e0f384105e8d49b54fb829"},
            {kl: "381f11959da9759363ce53df78218d338af9e15d7222c0a57f8077af58e2c054"
                ,kr: "1e6c7c7229b70a747478eab1cb08ab4e1bf16cb846aca9aa0eb9bb2d5dc9b080"
                ,A: "817653b1f9c3007f829c5d7ec70d1b2420779d4cee1bbe7a2f31051c77318c78"
                ,c: "8e13cfd9be3d933ec365a0820c12aaba7ca48b1d0a97b82d3e11e1b6f1931bd3"},
            {kl: "d044c43e767277e8976bdd804056e51eb2f5d18425a02c6c621c5b9655e2c054"
                ,kr: "e472b10feb070f5765e10093486627a5a8b46de364a4209e31ddc06d986d4042"
                ,A: "75fec950fb4070e35f1e10b822a622aa633cffb5731cde7607a647f0ef6ebe93"
                ,c: "c04079d12ffd7841f398d313162d77d60626229e13a856a73ff85be441df77a5"},
            {kl: "30cdb31e2062e5ef5c554583333899c2effa8a18cf00ed2dc214b1d954e2c054"
                ,kr: "7156bc1e1f7f228c58b35c1fc42f13c48249e357ddfe8f3ed63aac3b6adabcdc"
                ,A: "4d64d672a95f2d0863289b779305b7652e944c361f9b2b4ad06b41aacf1e69d7"
                ,c: "8b740ba78241bf83c2229c893afa5dee10f82a67ef4742535a5508d2a236af9b"},
        ]
        let seedHex = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a2"
        let rootHDKey = HDKey.fromMasterSeed(seedHex)
        for(let i = 0; i < 5; i ++){
            let hdKey = rootHDKey.derive('m/44/60/' + i)
            console.log('pl: ', hdKey.privateKeyL.toString(16))
            console.log('pr: ', hdKey.chainCode.toString(16))
            assert(hdKey.privateKeyR.eq(new BN(data[i].kr, 16, 'le')))
            assert(hdKey.privateKeyL.eq(new BN(data[i].kl, 16, 'le')))
            assert(utils.toHex(Ed25519.encodePoint(hdKey.publicKey)) === data[i].A)
            assert(hdKey.chainCode.eq(new BN(data[i].c, 16, 'le')))
            let [hdKey2, delta] = rootHDKey.publicDerive("m/44/60/" + i)
            assert(hdKey.publicKey.eq(hdKey2.publicKey))
        }
        console.log('\n\n')
    });


    it('Hard derive', async function () {
        let data = [
            {kl: "88c8d476f1e40914d8d0d19793633b572b9bb63d0f3faa3eaddf18a157e2c054"
                ,kr: "32e4366408b3bd3f0929d42e50859101d1dc43e176aeedf66e7e7fd0d61a3224"
                ,A: "c8ee4e3d75d971632d7b100b76c21271e9b239bd72b09a377036efe4409b56f3"
                ,c: "8f8170139bf30602a6d98097056bbcab2cebe69d2dbf8fdf26b99981e57e1d9b"},
            {kl: "c066897134a6f1c189fb906ba41be81497fe3e5fd452f78b1442c5f65ce2c054"
                ,kr: "588ff7278cb1e69689c956ee6d382d10210e6c7cc52dda078436b8cc137fcce6"
                ,A: "304930e51d51a835ec5c6f371f6c24bd5014453ec4977a9c60def8e496026d6c"
                ,c: "0a481a81c2f2578c40d256725c50500c422d815354d4d9604db47fd3b3dd0642"},
            {kl: "b80c4e655c43e900c43d4b96dc26b92c860b431f5d9d7fe8e45f49f15ce2c054"
                ,kr: "cddf157146196027d6485bb9bf648132a7ebadb8712df94ce7f2310ed8dd673e"
                ,A: "fb94ee21754e15b24cc4a42281a14d8cb3e7df142387f45814c0bcbf8bc4bef8"
                ,c: "f91b9c7eb177539b4060dc4686e7dfa9bd6a8b723db8ef8e1b19dfbbdca7ed04"},
            {kl: "40c62359084e50d9bf78e959c0b2a2e106388314a3e4f62438cc83d85ee2c054"
                ,kr: "5d1a02141973f847ca3e11c57e5964146219d99ae9148ac13bbb522dfba8d32c"
                ,A: "b2b164cef88769e9c7361f4e27af017017d059168c871d90e4b37765d5a26822"
                ,c: "2c0f6f7b1e60a0b65d5521d6fbeef9eec30e4039bd81d4838960b6f23bfdcf66"},
            {kl: "18140f625530b9369786b5a53aa35ff95c497d971ddb72d7267ef28d5ce2c054"
                ,kr: "b49feed6fac1dbabfd959e55d2f4c3b4badf2d6b4742a04b11ddac1589ad510b"
                ,A: "f54bb74bc0710cf9c83c391088662c326fd87ef710e7fadc317fd43e04255d26"
                ,c: "78575f72e7c61f9d1486ee12331176124ce3b253682b21d56c41e6cea2e12e8d"},
        ]
        let seedHex = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a2"
        let rootHDKey = HDKey.fromMasterSeed(seedHex)
        for(let i = 0; i < 5; i ++){
            let hdKey = rootHDKey.derive("m/44'/60'/" + i)
            console.log('pl: ', hdKey.privateKeyL.toString(16))
            console.log('pr: ', hdKey.chainCode.toString(16))
            assert(hdKey.privateKeyR.eq(new BN(data[i].kr, 16, 'le')))
            assert(hdKey.privateKeyL.eq(new BN(data[i].kl, 16, 'le')))
            assert(utils.toHex(Ed25519.encodePoint(hdKey.publicKey)) === data[i].A)
            assert(hdKey.chainCode.eq(new BN(data[i].c, 16, 'le')))
        }
        console.log('\n\n')
    });

//

    it('Derive from extended public key', async function () {
        let extendedPK = "epub8YjJEGN2T9xLcEfc6Q9ke2dqbibwfz7VpxZr1MNmSb5Ye8BsuNvyEk4JL1KJkz1yXmNfryUryhj27Xc1EP1mQcM621RSAQKraKNcv8RTDHH"
        let rootHDKey = HDKey.fromExtendedKey(extendedPK)
        let hdKey = rootHDKey.derive("m/44")
        let [hdKey2, delta] = rootHDKey.publicDerive("m/44")
        console.log(utils.toHex(Ed25519.encodePoint(hdKey.publicKey)))
        console.log(utils.toHex(Ed25519.encodePoint(hdKey2.publicKey)))
        console.log('\n\n')
    });
})
