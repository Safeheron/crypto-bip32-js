import * as assert from 'assert'
import * as BN from 'bn.js'
import {Rand, Prime} from "@safeheron/crypto-rand"
import * as elliptic from 'elliptic'
const Ed25519 = new elliptic.eddsa('ed25519')
import * as CryptoJS from "crypto-js"
import {Ed25519HDKey as HDKey} from "..";
import {Hex} from "@safeheron/crypto-utils";

describe('Ed25519 Bip32', function () {
    it('HDKey.fromMasterSeed_example0', async function () {
        let seedHex = "0102030405060708090A0B0C0D0E0F10"
        let hdkey = HDKey.fromMasterSeed(CryptoJS.enc.Hex.parse(seedHex))

        let expected_xpub = hdkey.xpub
        let expected_xprv = hdkey.xprv
        console.log('expected_xprv : ', expected_xprv)
        console.log('expected_xpub:  ', expected_xpub)

        let hdKey2 = HDKey.fromExtendedKey(expected_xpub)
        let expected_xpub2 = hdKey2.xpub
        console.log('expected_xpub2: ', expected_xpub2)
        assert(expected_xpub === expected_xpub2)

        let hdKey3 = HDKey.fromExtendedKey(expected_xprv)
        let expected_xpub3 = hdKey3.xpub
        let expected_xprv3 = hdKey3.xprv
        console.log('expected_xprv3: ', expected_xprv3)
        console.log('expected_xpub3: ', expected_xpub3)
        assert(expected_xpub === expected_xpub3)
        assert(expected_xprv === expected_xprv3)
        assert(hdkey.privateKey.eq(hdKey3.privateKey))

        console.log('\n\n')
    });

    it('HDKey.fromMasterSeed_example1', async function () {
        let hdkey = HDKey.fromMasterSeed(CryptoJS.enc.Utf8.parse('satoshi lives!'))

        let expected_xpub = hdkey.xpub
        let expected_xprv = hdkey.xprv
        console.log('expected_xprv : ', expected_xprv)
        console.log('expected_xpub:  ', expected_xpub)

        let hdKey2 = HDKey.fromExtendedKey(expected_xpub)
        let expected_xpub2 = hdKey2.xpub
        console.log('expected_xpub2: ', expected_xpub2)
        assert(expected_xpub === expected_xpub2)

        let hdKey3 = HDKey.fromExtendedKey(expected_xprv)
        let expected_xpub3 = hdKey3.xpub
        let expected_xprv3 = hdKey3.xprv
        console.log('expected_xprv3: ', expected_xprv3)
        console.log('expected_xpub3: ', expected_xpub3)
        assert(expected_xpub === expected_xpub3)
        assert(expected_xprv === expected_xprv3)
        assert(hdkey.privateKey.eq(hdKey3.privateKey))

        console.log('\n\n')
    });

    it('Soft derive', async function () {
        let data = [
            {priv: "eaf636d740506a41d9dc021ba4fbb23fcd58842a59e5540fe50e89a79f9aea02"
                ,A: "d1b539a1bdddbe093540da258cb17aed1037786c7f2688607deb7e1f71297777"
                ,c: "6bbbf3160db57f23e1c2908c0c730fea657b0e2edbc3737df33e6958dd935b55"},
            {priv: "21b0922201a127c12bea90ca4afb2d74cd9a1aaa44d5b3be521118eb637e1f0d"
                ,A: "1759e6e1968f959d9c88d19564c27b276419a50fce6cb85ac22c8d3761f75517"
                ,c: "e8b8eb8b712201ea7b35085e4b296acd2833cd74d5e95f7b55c9292dc9785d12"},
            {priv: "2b0009824b9a66083a07f1fba4cfc0d739b98b2f0dbf90942c106f0109cf490d"
                ,A: "854c0388c6029ee86f75777dc4109883c0615e1b25811cb37b8050a358ce8f70"
                ,c: "3448fbf20a733c9cf0a80285a323766de10c3f01437ba5140d877363759d4e11"},
            {priv: "6ccdd987ee2a440960349235bfc703599f62b115ba375e9fb6bb0ae218aa9401"
                ,A: "79c06e64f275ebd32c49ed03c29b49af8e3c52d75ba02b5f724c191a2cc7ab36"
                ,c: "d2ca6f99690a8eba382e66a54719d0ed6448b118d233f17c491aea026bb1bde5"},
            {priv: "406878e5926cf1ae404ae37aff03d9e88f4efd76fba3b350a436534318cba90b"
                ,A: "2b614f79ca8bdd30059729a820593aafeecdfc6d3103c563057e8028ad334449"
                ,c: "8f4008c811124ff6466759a11567e9e6dc5a5e611c2ff9a2c517c7cba58605be"},
        ]
        let seedHex = "0102030405060708090A0B0C0D0E0F10"
        let rootHDKey = HDKey.fromMasterSeed(CryptoJS.enc.Hex.parse(seedHex))
        for(let i = 0; i < 5; i ++){
            console.log('m/44/60/' + i, ":")
            let hdKey = rootHDKey.derive('m/44/60/' + i)
            console.log('privateExtendKey: ', hdKey.xprv)
            console.log('publicExtendKey: ', hdKey.xpub)
            console.log('privateKey: ', hdKey.privateKeyAsHex)
            console.log('chainCode : ', Hex.fromBytes(hdKey.chainCode.toArray('be', 32)))
            console.log('publicKey : ', hdKey.publicKeyAsHex)
            assert.strictEqual(hdKey.privateKeyAsHex, data[i].priv)
            assert.strictEqual(hdKey.publicKeyAsHex, data[i].A)
            assert(hdKey.chainCode.eq(new BN(data[i].c, 16)))
            let [hdKey2, delta] = rootHDKey.publicDerive("m/44/60/" + i)
            assert(hdKey.publicKey.eq(hdKey2.publicKey))
        }
        console.log('\n\n')


        rootHDKey = HDKey.fromExtendedKey("eprv423G5rKnJnGfjo7ntuhoFLZnrKhngg44vxgyxkZG8GdXBNyatATq9D5vEPuY31EENn2ZUEETtWXVMD9PuXF5buPzMVWEjBoTVPJdFU6bKRW");
        let hdKey = rootHDKey.derive('m/0')
        console.log('privateExtendKey: ', hdKey.xprv)
        console.log('publicExtendKey: ', hdKey.xpub)

        let [hdKey2, delta] = rootHDKey.publicDerive("m/0")
        console.log('publicExtendKey: ', hdKey2.xpub)
    });

    it('HDKey.fromMasterSeed_example2', async function () {
        let hdkey = HDKey.fromPrivateKeyAndChainCode(new BN("000000000000000000000000000000000000000000000000000000000000000a", 16), new BN(0))
        let childHDKey = hdkey.derive("m/1")
        console.log("child pub: ", Hex.fromBytes(Ed25519.encodePoint(childHDKey.publicKey)))
        console.log("child priv: ", Hex.reverseHex(Hex.pad64(childHDKey.privateKey.toString(16))))
        console.log("child chain: ", childHDKey.chainCode.toString(16))

        let expected_xpub = hdkey.xpub
        let expected_xprv = hdkey.xprv
        console.log('expected_xprv : ', expected_xprv)
        console.log('expected_xpub:  ', expected_xpub)

        let hdKey2 = HDKey.fromExtendedKey(expected_xpub)
        let expected_xpub2 = hdKey2.xpub
        console.log('expected_xpub2: ', expected_xpub2)
        assert(expected_xpub === expected_xpub2)

        let hdKey3 = HDKey.fromExtendedKey(expected_xprv)
        let expected_xpub3 = hdKey3.xpub
        let expected_xprv3 = hdKey3.xprv
        console.log('expected_xprv3: ', expected_xprv3)
        console.log('expected_xpub3: ', expected_xpub3)
        assert(expected_xpub === expected_xpub3)
        assert(expected_xprv === expected_xprv3)
        assert(hdkey.privateKey.eq(hdKey3.privateKey))

        console.log('\n\n')
    });
    it('HDKey tests with C++', async function () {
        let seedHex = "3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678";
        console.log("seed: ", seedHex)
        let hd_root = HDKey.fromMasterSeedHex(seedHex)
    //    console.log(hd_root.publicKey)
        let root_xprv = hd_root.xprv;
        let root_xpub = hd_root.xpub;
        console.log("root xprv: ", root_xprv)
        console.log("root xpub: ", root_xpub)
        console.log('\n\n')

        let walletAccountsNum = 10;
        let walletAccountsPath = []
        let xprvAccounts = []
        let xpubAccounts = []
        let isHardened = true
        for (let i = 0; i < walletAccountsNum; ++i) {
            if (isHardened) {
                isHardened = false;
                walletAccountsPath.push('m/'+ i + "'")
            }
            else {
                isHardened = true;
                walletAccountsPath.push('m/' + i)
            }
            let hdAccount = hd_root.derive(walletAccountsPath[i])
            let xprv_i = hdAccount.xprv;
            let xpub_i = hdAccount.xpub;
            xprvAccounts.push(xprv_i)
            xpubAccounts.push(xpub_i)
            console.log('accounts ' + i, ': path: ', walletAccountsPath[i], ', xprv: ', xprv_i)
            console.log('accounts ' + i, ': path: ', walletAccountsPath[i], ', xpub: ', xpub_i)
            console.log('\n\n')
        }
        let walletAccountsExternalPath = []
        let walletAccountsInternalPath = []
        let xprvAccountsExternal = []
        let xprvAccountsInternal = []
        let xpubAccountsExternal = []
        let xpubAccountsInternal = []
        for(let i = 0; i < walletAccountsNum; i++) {
            //for external chain
            walletAccountsExternalPath.push(walletAccountsPath[i] + '/0')
            let hdAccountEx = hd_root.derive(walletAccountsExternalPath[i])
            xprvAccountsExternal.push(hdAccountEx.xprv)
            xpubAccountsExternal.push(hdAccountEx.xpub)
            console.log('accounts ' + i + ' external: ', 'path: ', walletAccountsExternalPath[i],', xprv: ', xprvAccountsExternal[i])
            console.log('accounts ' + i + ' external: ', 'path: ', walletAccountsExternalPath[i],', xpub: ', xpubAccountsExternal[i])
            console.log('\n')
            //for internal chain
            walletAccountsInternalPath.push(walletAccountsPath[i] + '/1')
            let hdAccountIn = hd_root.derive(walletAccountsInternalPath[i])
            xprvAccountsInternal.push(hdAccountIn.xprv)
            xpubAccountsInternal.push(hdAccountIn.xpub)
            console.log('accounts ' + i + ' internal: ', 'path: ', walletAccountsInternalPath[i],', xprv: ', xprvAccountsInternal[i])
            console.log('accounts ' + i + ' internal: ', 'path: ', walletAccountsInternalPath[i],', xpub: ', xpubAccountsInternal[i])

            console.log('\n\n')
        }
        //one address per account
        let addressExternalPath = []
        let addressInternalPath = []

        let xprvAddressEx = []
        let xprvAddressIn = []
        let xpubAddressEx = []
        let xpubAddressIn = []
        let hasHardened = true;

        for(let i = 0; i < walletAccountsNum; ++i) {
            let t = new BN("80000000", 16)
            let r = await Rand.randomBNLt(t)
            addressExternalPath.push(walletAccountsExternalPath[i] + '/' + r.toString(10))
            addressInternalPath.push(walletAccountsInternalPath[i] + '/' + r.toString(10))
            if(hasHardened) {
                let addressEx = hd_root.derive(addressExternalPath[i])
                xprvAddressEx.push(addressEx.xprv)
                console.log('account ', i, ' :', 'external: ', 'path: ', addressExternalPath[i], 'xprv: ', addressEx.xprv)
                console.log('account ', i, ' :', 'external: ', 'path: ', addressExternalPath[i], 'xpub: ', addressEx.xpub)
                console.log('\n')
                let addressIn = hd_root.derive(addressInternalPath[i])
                xprvAddressIn.push(addressIn.xprv)
                console.log('account ', i, ' :', 'internal: ', 'path: ', addressInternalPath[i], 'xprv:', addressIn.xprv)
                console.log('account ', i, ' :', 'internal: ', 'path: ', addressInternalPath[i], 'xpub: ', addressIn.xpub)
                hasHardened = false;
            } else {
                let [addressEx, dealt] = hd_root.publicDerive(addressExternalPath[i])
                xpubAddressEx.push(addressEx.xpub)
                console.log('account ', i, ' :', 'external: ', 'path: ', addressExternalPath[i], 'xpub:', addressEx.xpub)
                console.log('\n')
                let [addressIn, dealt1] = hd_root.publicDerive(addressInternalPath[i])
                xpubAddressIn.push(addressIn.xpub)
                console.log('account ', i, ' :', 'internal: ', 'path: ', addressInternalPath[i], 'xpub:', addressIn.xpub)
                hasHardened = true;
            }
            console.log('\n\n')
        }
    });

})
