import * as assert from 'assert'
import * as cryptoJS from "crypto-js"
import * as elliptic from 'elliptic'
const P256 = new elliptic.ec('p256')
import {P256HDKey as HDKey} from "..";
import {Hex} from "@safeheron/crypto-utils";

describe('Elliptic P256 Bip32', function () {
    it('HDKey.fromMasterSeed', async function () {
        var seed = 'ccc5dbb81c9bc81b77a867047fa30700164b3db5bd0bc65f41644039532f9da6ff2f5e260d48e9530c88c0aa031f53832f8b5d602bb7532008824d04089f45b9'
        var hdkey = HDKey.fromMasterSeed(cryptoJS.enc.Hex.parse(seed))
        console.log(hdkey.xprv)
        console.log(hdkey.xpub)
        console.log('\n\n')
    });

    it('HDKey.fromExtendedPrivateKey', async function () {
        var hdkey = HDKey.fromExtendedKey('xprv9s21ZrQH143K2eBLubjMRHojzLTXitCmaDinD6KWvuuCyteQYwHNY1QSfsA7PcVArajMthHj5r5jG9aS52vQGUuqa9ZmbpLCjKUfhH6zFGW')
        console.log(hdkey.xprv)
        console.log(hdkey.xpub)
        hdkey = hdkey.deriveChild(0)
        assert.strictEqual(hdkey.xprv,'xprv9vXT6QXaywnXMCh1bK1bTeNEys3yrjzXN8uyokdsQ7kXHrhxKUKJ5R65uHDBY6Qs85KFhdnit92ze9JmcgRpb2Znya2bQGZpgmNjEEuytU3')
        assert.strictEqual(hdkey.xpub,'xpub69WoVv4UpKLpZgmUhLYbpnJyXttUGCiNjMqac93UxTHWAf36s1dYdDQZkXnY7mYGt9xKUP2tMZb9FtcHvAM9BsfarCpx4efDsDot3Cq2mya')
        console.log('\n\n')
    });

    it('HDKey.fromExtendedPublicKey', async function () {
        var hdkey = HDKey.fromExtendedKey('xpub661MyMwAqRbcF8Fp1dGMnRkUYNJ28LvcwSeP1Uj8VFSBrgyZ6Ubd5oivXA3sayX2Qa5MtuPQDXyaMmG4Y7N68itzUqMGpBwYa4nLEF81eHe')
        hdkey = hdkey.deriveChild(0)
        assert.strictEqual(hdkey.xpub,'xpub69WoVv4UpKLpZgmUhLYbpnJyXttUGCiNjMqac93UxTHWAf36s1dYdDQZkXnY7mYGt9xKUP2tMZb9FtcHvAM9BsfarCpx4efDsDot3Cq2mya')
        console.log('\n\n')
    });

    it('HDKey.derive', async function () {
        var seed = '78512254e94f98d3a049c214faf6582687b3aebf8d68359cf44e0c345d533ccb'
        var hdkey = HDKey.fromMasterSeed(cryptoJS.enc.Hex.parse(seed))
        var xprv  = "xprv9s21ZrQH143K2QEAV2AAMSXaiyYcWgfyqZjYRSv95adiiHM4dywDzhoBXrQxahUrkxXMiNqtxHM7tLcZs4aWZpVznWSHYZopE9YKPtnhUVm"
        var xpub =  "xpub661MyMwAqRbcEtJdb3hAiaUKH1P6v9PqCnf9DqKkdvAhb5gDBXFUYW7fP82NiGaXdUjjbRQYc8oWnuzcMruKPf1soJwrD52Wi3M54egFkpa"
        assert.strictEqual(hdkey.xprv, xprv)
        assert.strictEqual(hdkey.xpub, xpub)

        //hdkey = hdkey.derive("m/44'/60'/0'/0")
        xprv = "xprv9z6F4ERdtAZquKgL8nvkC6b5DjiYwHszwEKfULkvC7MpvvsjjjUJmUFzEsQiW37duGD77HFCrZ7tT4WRZtGACq8aztpNrDnYzZV8Y6D8W7W"
        xpub = "xpub6D5bTjxXiY897okoEpTkZEXommZ3LkbrJTFGGjAXkStoojCtHGnZKGaU6Aj5id1Tt5H3hGUnUUs22r1dhc4Ff1umibhJtoYceDhjsajcqhS"
        hdkey = hdkey.derive("m/44'/60'/0'")
        assert.strictEqual(hdkey.xprv, xprv)
        assert.strictEqual(hdkey.xpub, xpub)

        xprv = "xprvA2NM3CHHTHwjUFXnkiHgNLuC2Wx4RnouFMhyrTUgg5N9u2t7vHiwnWz7QT7y2B4Ex53QNLAmZpa1hBQBB3jyesNZt1Jr4geKBFdTWsf6c2s"
        xpub = "xpub6FMhShpBHfW2gjcFrjpgjUqvaYnYqFXkcadaeqtJEQu8mqDGTq3CLKJbFiMeZ9AThBZ5XzFYEDsanYRs4UnWEQEiB4q8EdjSyXpDXTivZcX"
        hdkey = hdkey.deriveChild(0)
        assert.strictEqual(hdkey.xprv, xprv)
        assert.strictEqual(hdkey.xpub, xpub)
        console.log('\n\n')
    });

    it('HDKey.publicDerive', async function () {
        var hdkey = HDKey.fromExtendedKey('xprv9s21ZrQH143K4FrkGDz3qkWpDcY4Fu1AHvMPA95JivKLnF7VVUiPqmZzcUGFRPWF6tU6wYRDqbL1WSV5RhaDxLXo5WbbouRFwMzPAr7KXGV')
        console.log("public extented key:", hdkey.xpub)
        const [childHDKey, delta] = hdkey.publicDerive("m/44/60/0/0/9")
        console.log(Hex.pad64(childHDKey.publicKey.getX().toString(16)))
        console.log(Hex.pad64(childHDKey.publicKey.getY().toString(16)))
        let priv = hdkey.privateKey.add(delta)
        let publicKey = P256.g.mul(priv)
        console.log(Hex.pad64(publicKey.getX().toString(16)))
        console.log(Hex.pad64(publicKey.getY().toString(16)))

        for(let i = 0;i < 10; i ++){
            let tPath = "m/44/60/0/0/" + i
            const [tChildHDKey, tDelta] = hdkey.publicDerive(tPath)
            console.log(tPath, ": \n")
            console.log("  -  ", tChildHDKey.xpub)
            console.log("  -  ", tDelta.toString(16))
        }

        console.log('\n\n')
    });


    let derivationCases = [
        {
            seed: 'ccc5dbb81c9bc81b77a867047fa30700164b3db5bd0bc65f41644039532f9da6ff2f5e260d48e9530c88c0aa031f53832f8b5d602bb7532008824d04089f45b9',
            extendedKeys:[
                {
                    path: "m/44\'/60\'/0\'",
                    extendedPrivateKey:'xprv9zJSuQvSteeeZivRg2zdXYBzzTjivNvzM7tMsAzE1vH5CGs6mv4qRnhsuKTQaLnA5o4B8FxuJgQMXFRFS7Mko6pGiAKLX2LdMmjAvYZNZqg',
                    extendedPublicKey:'xpub6DHoJvTLj2CwnCztn4Xdtg8jYVaDKqeqiLoxfZPqaFp455CFKTP5yb2Mka3fhHUHGgy7Te9Arb6uEufo9GETtzPsUdMYGnpUK5kKmP7XYwp',
                },{
                    path: "m/44'/60'/0'/0",
                    extendedPrivateKey: "xprvA1peMT28YArLF6MA9MyhLFaTU2tDcAZXxNhboMn3RrsFomiaMfY9S3rRkiWVCZrrwD96uYc7TgRMyaD7yGmZzWGXJk5kZsXjGoUL2tDtRdQ",
                    extendedPublicKey: "xpub6EozkxZ2NYQdTaRdFPWhhPXC24ii1dHPKbdCbkBezCQEga3iuCrPyrAubzdZ7wc5iGoyDnNtRq8zEXaX4KXcX91aoerpk726nZHawpAyaKk"
                }
            ],
            finalKeys:[
                {
                    path: "m/44'/60'/0'/0/0",
                    privateKey: "803c871d8d175174910d28e11e79ebe5a060e9a6c62e0170ac9544201650a053",
                    publicKey: "6b591b35330c15c1f5ac39c4313b26cbf291aff8ec7ef6225a578c34254b5bbcd918870827c845fefa19102c5110472be5ec7a9269efc0fc51e2bb03daa20337",
                }, {
                    path: "m/44'/60'/0'/0/1",
                    privateKey: "1edca13c1ef14aa3ca700329324215c7a5281b169164928cc99927e41fd2b1f7",
                    publicKey: "21f1102c285c5942b5e0af0cfa26e839c81625bf3510872046629a5c7c91d50d732bea84c0e06d1c70a2c8d9c328f046713e84b8ab13b6eff9c9073323c9417f",
                }, {
                    path: "m/44'/60'/0'/0/2",
                    privateKey: "8ea9791404abe0e53f4bfc000b1c3e925a40a076446225c265be1e5aadbaa2c4",
                    publicKey: "1b317a3e6250e51984e21f457815f2012aad52bfcaa4ecfa23d5d03c03d5a6f854a3bdc3edc994c372545607a308bfc97fb335df07668793addefbe995ee169d",
                }, {
                    path: "m/44'/60'/0'/0/3",
                    privateKey: "b4daf001e53ff422837e2fe52271764e61ca859d0cf99f48bd565b55e413f980",
                    publicKey: "c213d8c3bceefc91d60665be0571012e5fd62829f559c01d8236b4d809ac21dfae159c965b2357bb406e35d41e47db8f4ccb6fde879b2989c62c24b311b8233b",
                }, {
                    path: "m/44'/60'/0'/0/4",
                    privateKey: "8618da6b20e7bcf3ce2aa5f4d0d530bc987193b78704a1a0435f75e269f64da9",
                    publicKey: "e528a7dd829fd88a6827e5aa6fb43c7bfb67776e01e95cb92664ad2995e0c76354bcd0b8cc2dd0d759002ee117d51906d922a9b8d2b9466c48f1c85632d9340e",
                },{
                    path: "m/44'/60'/0'/0/5",
                    privateKey: "8214954ad51efe7c1a46e8aa7f03cdd9b6af36684d7f4f2d7234ace6d3f1f917",
                    publicKey: "e4aeeaf3c861af976a5ba59078fd76a43ea5509b42fca491456bdb3e125194867713682e03459ce4035fb0828aff40da8a3119009777666742cc67658bf33db7",
                }, {

                    path: "m/44'/60'/0'/0/6",
                    privateKey: "3c59608e8450c64a3a826300c72fccf97de26d43ffabe735b5e1f38fcabcd2b5",
                    publicKey: "dc26ff5e6ae91c1bffb9d69bd39305fd4a28108179565ab7dcab3548e03d692785e40cbb8fc5624011deba297ab30d02a1e1f572f238ec4d1e2d96094e85faaf",
                }, {
                    path: "m/44'/60'/0'/0/7",
                    privateKey: "b9a3c3e90f4af1e159323928255eeffac67e30d885aed380f8a9630e2d1cf07b",
                    publicKey: "f9d678eb5757f583c5638d601a9697650d2d50630a0f19a20b2e634e76b83fb65b7a57389fc4647aaf2e644def137d7cb15b878985e03b5d65c8237029d920fd",
                }, {
                    path: "m/44'/60'/0'/0/8",
                    privateKey: "e3342c2f56b6aa68a9bcd0ab4d71a5c222337cfa99b0a538c211fc91e09a08e1",
                    publicKey: "6ac876c8f614c3ab543c0dfc8773ead88a440d93c67ebff122dd53d6a58ce42a35a9b43827a59d8532614923092279fc973b2091deed91ff9dffc4af363af287",
                }, {
                    path: "m/44'/60'/0'/0/9",
                    privateKey: "279aa7a73793d7d02eb6242b8564d01242d75c4d153e58f24ce0e3fe4c5c19ff",
                    publicKey: "b8ed3fa4bc2c3e5901b86bd42d400361a595c5302afcdc4d77b5a8e7c78109fcce6a28aeaeee2f78e7ea3e54ffe63a626e0164fc35e08e712986a43e21e6adc2",
                }
            ]
        }
    ]

    function runDerivationCases(t) {
        var seed = t.seed
        var hdkey = HDKey.fromMasterSeed(cryptoJS.enc.Hex.parse(seed))
        console.log('xpub: ', hdkey.xpub)
        console.log('xprv: ', hdkey.xprv)
        t.extendedKeys.forEach(function (ek) {
            let hk = hdkey.derive(ek.path)
            assert.strictEqual(hk.xprv, ek.extendedPrivateKey)
            assert.strictEqual(hk.xpub, ek.extendedPublicKey)
        })
        t.finalKeys.forEach(function (fk) {
            let hk = hdkey.derive(fk.path)
            assert.strictEqual(Hex.pad64(hk.privateKey.toString(16)), fk.privateKey)
        })
        console.log('\n\n')
    }

    it('Derivation', async function (){
        for(let i = 0; i < derivationCases.length; i ++) {
            runDerivationCases(derivationCases[i])
        }
    });

    let standardPublicDerivationCases = [
        {
            extendedPublicKey: 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ1rxaVqyxRSgbLorQN2Q1RJiLfHtqHqAcK8WosMpL4tCGungDyV',
            extendedChildKeys: [
                {
                    path: "m/0",
                    extendedPublicKey: "xpub69EQfYm9HMHRFL8nUzGN1LvUo3kPfjcEt8qs2akezrm43pShTBDcYZ6aPJvry8qCouefnBmeSg9A8RNqvF55RixD5xbAGnefdSzMa1G5P8L"
                },
                {
                    path: "m/0/1",
                    extendedPublicKey: "xpub6Ary9ioEwgcVS445AV8yE2FBcQ1siaYTPJiM5UmxUk562fnhsTozedVUzjY2Xob4uaeZQPhAivNM8xGrGQLhrFCmAmuj2p4UzmdjdTM5EwH"
                },
                {
                    path: "m/0/1/2",
                    extendedPublicKey: "xpub6Co8WqLg5prbGtdWW41EujRjTiaMFDZyt3W8iJKEY84aCtoWSdmuLnb2ZHb2feKFwkGvM5gidNdg3tNq1Zc78fApKUR6PGT3tX15oUtsPsm"
                },
                {
                    path: "m/0/1/2/2",
                    extendedPublicKey: "xpub6E7bW6xY6uQwQZXkZyxpReHBCeBwK38kx86X8txo5W6Y9CK4hZZpCnfsiSmyHmkTRcE4BAfEHSdjBLQTK9vxbWnxsmaEQ3YHrse4hR5uHp4"
                },
                {
                    path: "m/0/1/2/2/1000000000",
                    extendedPublicKey: "xpub6G6vsHuFchxbm3HqXpG1KzDU4uhHneYKqUS3WB3oNo4V1gU9UhbHsfb6pwEpMxg3jaS7s7cCz1CiiEnKios56MR1atdshs79nUsa4McoWh6"
                },
            ]
        },
        {
            extendedPublicKey: 'xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu88PRW8Roww5CfAtDP9kVhL3q5wFNzWFtkmiZYMz2EdR2EzWVu1',
            extendedChildKeys: [
                {
                    path: "m/0",
                    extendedPublicKey: "xpub68RvquFPLkiSWCTmTapgErvVAWHcHrouFBhBiwWMvP1rQi3W3Lb8mMq4GxvdiJnrobNVd3boVC3aXihoqX6zMnWsqaMj1WngwZG5FGGgePV"
                },
                {
                    path: "m/0/2147483647",
                    extendedPublicKey: "xpub6AJLQK45bSEhaf9cid3s1uEc3Ci7tZnHMUhqsYxseFrP3MGp9MU2NTNpKrCqdtqxKM1rFLtjLcQ6whAAHafggzUrgR39kv7a2Mir94UwaSL"
                },
                {
                    path: "m/0/2147483647/1",
                    extendedPublicKey: "xpub6DNrdmNFA4KpdhbstxBJHwiV4MZCDuKsNszrYg8EhQ53YZd22iqhkk1qKJGSjWLEcRRrWu9mPHpnbnpZ5AtKRVtfw9k6ViL3A28ur1T7MXo"
                },
                {
                    path: "m/0/2147483647/1/2147483646",
                    extendedPublicKey: "xpub6ELeU8rFzLwNJP9RELUBUYr4BAkkcMNVQHJE1vAT8EJLCV1BktmC14NBaU2E4KbuUB6MML832ePgbLB1QNn1q8mVcm1M71R6mzpfhgukRny"
                },
                {
                    path: "m/0/2147483647/1/2147483646/2",
                    extendedPublicKey: "xpub6HGdqkbABiyZSfQZVTjzqdf6DGWa4sAiQxMdS8PWJxMPRNnZjK4HtGNh57duvafQWb9TFyy3NvYDQBpGj8GSwnQgjCEr3SmpMGNKBLYjUoT"
                },
            ]
        },
        {
            extendedPublicKey: 'xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP5g9nPtMtoVhGphh2J6Af7iEETDpvaPR642VyUAG8cbuFkdUL3r',
            extendedChildKeys: [
                {
                    path: "m/0",
                    extendedPublicKey: "xpub684hDmeehkYNmR1t96xVm1ViXroxKWWnaftt5QsBKmMgcnhreCrat2yUQXiBvbKVJaUhMdnBV7CZWjDpmwP3kEf9bEtp1wmLEK88yScE2FB"
                },
            ]
        },
        {
            extendedPublicKey: 'xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5FQ6jj6QWL1XquBQYg2jSfMXkjhyh6op2PvByre73yHih14k5uy',
            extendedChildKeys: [
                {
                    path: "m/0",
                    extendedPublicKey: "xpub68uEAS6Wt5aH984dtDnaRVxD3th5oauwNjDqEPfjKmHMur8UtmFS3zpL8ru4PqAbASHBawCbhZV2RWdfK36ru8zJop3EYRrMsq3mZ84bGpc"
                },
                {
                    path: "m/0/1",
                    extendedPublicKey: "xpub6AFUe4k6Jz3PZccp3ji6spFToFrBeyhZr4oFQXEYKNZZDRpi3U5DBDX3A51gMaCBFrhzVyrKarGjy7pKB3D73wgdRCpFAZ9HW5eNDytz3DU"
                },
            ]
        },
    ]

    function runStandardPublicDerivationCases(t) {
        var hdkey = HDKey.fromExtendedKey(t.extendedPublicKey)
        console.log('xpub: ', hdkey.xpub)
        t.extendedChildKeys.forEach(function (ek) {
            const [tChildHDKey, tDelta] = hdkey.publicDerive(ek.path)
            assert.strictEqual(tChildHDKey.xpub, ek.extendedPublicKey)
        })
    }

    it('HDKey Standard Public Derivation Test', async function (){
        for(let i = 0; i < standardPublicDerivationCases.length; i ++) {
            runStandardPublicDerivationCases(standardPublicDerivationCases[i])
        }
    });


    let standardPrivateDerivationCases = [
        {
            seed: '000102030405060708090a0b0c0d0e0f',
            extendedChildKeys: [
                {
                    path: "m",
                    extendedPrivateKey: "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
                    extendedPublicKey: "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ1rxaVqyxRSgbLorQN2Q1RJiLfHtqHqAcK8WosMpL4tCGungDyV",
                },
                {
                    path: "m/0'",
                    extendedPrivateKey: "xprv9vF4G3EPneG6BgTH9TysyDsDfoeB6aQw9wQ15pT35i6Q4jfpUkUdXpLzxRY1M6693yvb4Cgt7zw714stMbFj9tFiSw3XLvv9ZvWxcttAPGK",
                    extendedPublicKey: "xpub69EQfYmHd1pPQAXkFVWtLMoxDqUfW38nXAKbtCree3dNwXzy2Hnt5cfUoiSeFbuWm8oBwH45fgAYBiRnnRDWSJwDEQpHY2aKjUZUm9siJE9"
                },
                {
                    path: "m/0'/1",
                    extendedPrivateKey: "xprv9xAe6YM81aekrnNuPpG8hW7gmjJmW8pc1TzEoiNNvHuDx9Bp712czjhtLrt2ZgggSDGLaPJWPTehbwrYZdkQfQ6yKFT9RdU2PrV3RgpGCCh",
                    extendedPublicKey: "xpub6B9zW3t1qxD45GTNVqo94e4RKm9FubYTNguqc6mzUdSCpwWxeYLsYY2NC7oPecGSDf6Fvc1RexMBA5WtAjfU5CYmjrkFqSrPNQbtNzMGPZQ"
                },
                {
                    path: "m/0'/1/2'",
                    extendedPrivateKey: "xprv9zFx47oHFws5UHe6qRC3BDhjhXuMBctBAvqNcQw1EjKg6NczGJghreceH5SAdcHjwmJeFNrddaRmdDQQiUiVj2ynEoHumq42QNgPgBZ7CZE",
                    extendedPublicKey: "xpub6DFJTdLB6KRNgmiZwSj3YMeUFZjqb5c2Y9kyQoLco4reyAx8oqzxQSw88MQLex8JKES1f4MzTKhhjj5V7Q16rF23FsdtnohNoYeB5NmBnP2"
                },
                {
                    path: "m/0'/1/2'/2",
                    extendedPrivateKey: "xprvA1QyAkii7ePZyGc85PNtPbEViFdgZdcNFV1bREGxjoZ2yoVbC6TsNoZhSsWENhkHszoiaToBVhUJpJaA8HVvbeKV4rP1HSN2NzZvaA2ufDX",
                    extendedPublicKey: "xpub6EQKaGFbx1wsBkgbBQutkjBEGHUAy6LDchwCDcgaJ961rbpjjdn7vbtBJ7rvJfGWFdML5tCTSqDqPPrgXcQN1hCD7RF7SeUgGFqpMuNHZqL"
                },
                {
                    path: "m/0'/1/2'/2/1000000000",
                    extendedPrivateKey: "xprvA376yCR3Fidcx55VckEt1SdHfQNfiHzcjEPr5vbMGEdRF8MHvTivwWNswJeANnrMnE2DD7AK9dkfKEgUSNmprLyNoTC5XpNVENzHjDJBGGA",
                    extendedPublicKey: "xpub6G6TNhww66BvAZ9ximmtNaa2DSDA7kiU6TKStJzxpaAQ7vgSU13BVJhMna9qZrKWb2aLsV4CsDbV8k5uVtyhmUcUmvtxTk4GBLBGJzKPVGQ"
                },
            ]
        },
        {
            seed: 'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542',
            extendedChildKeys: [
                {
                    path: "m",
                    extendedPrivateKey: "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U",
                    extendedPublicKey: "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu88PRW8Roww5CfAtDP9kVhL3q5wFNzWFtkmiZYMz2EdR2EzWVu1",
                },
                {
                    path: "m/0",
                    extendedPrivateKey: "xprv9uSaSPiVWPA9HiPJMZHfsiykcUT7tQ63sxmavZ6kN3UsXuiMVoGtDZWaRh6BnitcKkVVcygccruXCPv8moJmqhKPc4VYdggVSbqzhVJ2tPd",
                    extendedPublicKey: "xpub68RvquFPLkiSWCTmTapgErvVAWHcHrouFBhBiwWMvP1rQi3W3Lb8mMq4GxvdiJnrobNVd3boVC3aXihoqX6zMnWsqaMj1WngwZG5FGGgePV"
                },
                {
                    path: "m/0/2147483647'",
                    extendedPrivateKey: "xprv9wJyzoXL6jDNZzxEkLBXfQcpRtAHGnMeYcvQNsgKai6PpLmg48ouWvcbzjhpBzmiqJjz4P5egtfHx9t75LDiYcbfsAGuLHMNLeS7qjPrDcZ",
                    extendedPublicKey: "xpub6AJLQK4Dw6mfnV2hrMiY2YZYyuzmgF5Vuqr1BG5w93dNh96pbg8A4iw5r2NH2ujZFNCzj27QMHZnPPPeV5RqCauFSDYBkKXtoXAVfzedSFm"
                },
                {
                    path: "m/0/2147483647'/1",
                    extendedPrivateKey: "xprv9xvaETDxuFq5cyuJHUC3S7bD7bPGR7uafuQb8Lvm8UqVUV1hCnSyrcZ2MYrEPKHP1A5fM14fN1XFqMXgvfWDvZhVayzf6A62mHYnqrRQywB",
                    extendedPublicKey: "xpub6BuvdxkrjdPNqTymPVj3oFXwfdDkpadS38LBvjLNgpNUMHLqkKmEQQsWCo7nk3NXCCxZKP5kAscqRq6YYzcq3LJ9gAt34wMhH9VFPgAm4BB"
                },
                {
                    path: "m/0/2147483647'/1/2147483646'",
                    extendedPrivateKey: "xprvA1frKLpupMitrnxrbdNfzZyxdeaJZHLz3W9WvDHrkokuCMSZ4bZM5f8HLFmCG2E7pFptb2y9kXbEbbRHXAPzG3BSUp7oLJqS3cZ2WxLhNfn",
                    extendedPublicKey: "xpub6EfCirMoejHC5H3KheugMhvhBgQnxk4qQj57ibhUK9Ht59mhc8sbdTSmBW8iP1j7knfX2mNYAr1npCuWXztmWSodFpjzpvfotjxuRTEVbqR"
                },
                {
                    path: "m/0/2147483647'/1/2147483646'/2",
                    extendedPrivateKey: "xprvA3zRSnAaGxNtcLaWBnorUfawU8aRbvE99uu5peQKf5Gra5685rpihBaCDrmHZ6s2fVWFNbC5qCb9SXRPVhxizeC1u8XkrSxaYYGW27oZmNp",
                    extendedPublicKey: "xpub6GymrHhU7KwBppeyHpLrqoXg2AQv1NwzX8pgd2owDQoqSsRGdQ8yEytg58wGGzUPzFBANBoCTNMGqZChkTcC8LnL8hCGKriJDEDBfp6ATsS"
                },
            ]
        },
        {
            seed: '4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be',
            extendedChildKeys: [
                {
                    path: "m",
                    extendedPrivateKey: 'xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6',
                    extendedPublicKey: 'xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP5g9nPtMtoVhGphh2J6Af7iEETDpvaPR642VyUAG8cbuFkdUL3r',
                },
                {
                    path: "m/0'",
                    extendedPrivateKey: "xprv9u5LpG7uD3X3jZXeDCXwksKgL3D41BALpFA86x63XF7Xqj3B6NiCpzqsx8HZmTriX1TW7BSp5QAw5boAeCT9nwmRYCukVMiGKNsVV6vvu8X",
                    extendedPublicKey: "xpub684hDmeo3R5Lx3c7KE4x81GQt53YQdtCBU5iuLVf5aeWiXNKdv2TNoAMoQPbGn3XYzMmMYZuwSHhKH3WeWvJ5RcHFuhMbST6oeRuCSVtpvH"
                },
            ]
        },
        {
            seed: '3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678',
            extendedChildKeys: [
                {
                    path: "m",
                    extendedPrivateKey: 'xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv',
                    extendedPublicKey: 'xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5FQ6jj6QWL1XquBQYg2jSfMXkjhyh6op2PvByre73yHih14k5uy',
                },
                {
                    path: "m/0'",
                    extendedPrivateKey: "xprv9uuskvZmPNYx7MGCCp8nVs8y2wNCbKW7yKe3EtC1D6yd7hS1zncnJ8Ci9ZTfpK8RisJRgyENReKNSkjceA2d5zA919bXjVc7inV2o6xEcDK",
                    extendedPublicKey: "xpub68uEAS6fDk7FKqLfJqfns15hayCgznDyLYZe3GbcmSWbzVmAYKw2qvXBzptv1b6artTJh8vDkBzNNGky4sZyJTkngWuFvkCtzTRJ6BZEjQ2"
                },
                {
                    path: "m/0'/1'",
                    extendedPrivateKey: "xprv9xdi1f5ckLzhyBNV2bjhkwGZ4RepjSsgw9EcFeBhUqoBrswTNNSUFvFSBNcGuUcxb4hecaeoU7wMpCdDJVsPZf9s7Q4HQb2bJykhHbZovri",
                    extendedPublicKey: "xpub6Bd4RAcWaiZ1BfSx8dGi85DHcTVK8ubYJNAD42bK3BLAjgGbuukioiZv2go5hwn7im8o99LBi31oj2fdSYzH8j42GDMkJL7EN5D7xqZnxZf"
                },
            ]
        },
    ]

    function runStandardPrivateDerivationCases(t) {
        var hdkey = HDKey.fromMasterSeed(cryptoJS.enc.Hex.parse(t.seed))
        console.log('xpub: ', hdkey.xpub)
        console.log('xprv: ', hdkey.xprv)
        t.extendedChildKeys.forEach(function (ek) {
            let hk = hdkey.derive(ek.path)
            assert.strictEqual(hk.xprv, ek.extendedPrivateKey)
            assert.strictEqual(hk.xpub, ek.extendedPublicKey)
        })
    }

    it('HDKey Standard Private Derivation Test', async function (){
        for(let i = 0; i < standardPrivateDerivationCases.length; i ++) {
            runStandardPrivateDerivationCases(standardPrivateDerivationCases[i])
        }
    });

})
