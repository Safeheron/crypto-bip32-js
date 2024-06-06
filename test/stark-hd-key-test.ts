import * as assert from 'assert'
import * as cryptoJS from "crypto-js"
import {STARKHDKey as HDKey, STARK} from "..";
import {Hex} from "@safeheron/crypto-utils";

describe('Elliptic STARK Curve Encryption', function () {
    it('HDKey.fromMasterSeed', async function () {
        var seed = '823662a8da34a37daf945048adce45804a2ecee33e48eecc6f4fcf5c25b8b4df454635cf0f59a5b91b506281a2b1adcbf573970783401783c52fbc93b4a34339'
        var hdkey = HDKey.fromMasterSeed(cryptoJS.enc.Hex.parse(seed))
        console.log(hdkey.xprv)
        console.log(hdkey.xpub)
        console.log('\n\n')
    });

    it('HDKey.fromExtendedPrivateKey', async function () {
        var hdkey = HDKey.fromExtendedKey('xprv9s21ZrQH143K4TRpPm2z39uprRc2XVqFyRF9SpSdqieE7E1sQy2shDYzeugagMLSCZBrpXz4fHT4o5NtoPutYVaN22Dmc9J1HZyoDUxJGG6')
        console.log(hdkey.xprv)
        console.log(hdkey.xpub)
        hdkey = hdkey.deriveChild(0)
        assert.strictEqual(hdkey.xprv,'xprv9vKzhbAVRy7bGLwyQdCnxHczS5Vg7YJcmfpi6k934XQ1ubvVRBp7vkutntqWrK6QcBxqjEKcjstyZhp2vtnKyv5qwgvNy7bPQs4EDeLUdjb')
        assert.strictEqual(hdkey.xpub,'xpub69KM76hPGLftUq2SWejoKRZiz7LAX12U8tkJu8YecrvznQFdxj8NUZENe9r49uR9Vv2aAd3TbsNRgTjXuLhkNegzszpumSM887o8dwp8drE')
        console.log('\n\n')
    });

    it('HDKey.fromExtendedPublicKey', async function () {
        var hdkey = HDKey.fromExtendedKey('xpub661MyMwAqRbcGwWHVnZzQHrZQTSWvxZ7LeAkFCrFQ4BCz2M1xWM8F1sUWCfDTnvDcaWn6Z4QpRLGr5PsYBxFpq236SmhZEUnZb55b4FcrJo')
        hdkey = hdkey.deriveChild(0)
        assert.strictEqual(hdkey.xpub,'xpub69KM76hPGLftUq2SWejoKRZiz7LAX12U8tkJu8YecrvznQFdxj8NUZENe9r49uR9Vv2aAd3TbsNRgTjXuLhkNegzszpumSM887o8dwp8drE')
        console.log('\n\n')
    });

    it('HDKey.derive', async function () {
        var seed = '1c984ff60ad4a020816f95a888936e2fa962600b975d47dae176e4f323db2f5e'
        var hdkey = HDKey.fromMasterSeed(cryptoJS.enc.Hex.parse(seed))
        var xprv  = "xprv9s21ZrQH143K2X5Ur3wFjqvKD56fg7C6tGbRjkLYfFFrJYcdkEGAvRoiiqJJ2r3RJ6KyoRGr2aqy7icv15BcF5YGW7hvgfnmF3UkNexHH7n"
        var xpub =  "xpub661MyMwAqRbcF19wx5UG6ys3m6wA5ZuxFVX2Y8kADanqBLwnHmaRUE8Ca6Ly9eFfxHye1KKD2tMpmihScZYcDHFQB8Q1WKcsHGdyMW5uBwJ"
        assert.strictEqual(hdkey.xprv, xprv)
        assert.strictEqual(hdkey.xpub, xpub)

        xprv = "xprv9zRdS84mJKMGZmtbPFCzJwUXzVPR5naoDUzDFrZfGYSPcFV1KryPKf4NtbWTwKmUNtiDZyxLkya4sferbVZs6WPBmxi1wfgjRc8c6Nu9oqu"
        xpub = "xpub6DQyqdbf8guZnFy4VGjzg5RGYXDuVFJeahup4EyGpsyNV3p9sQHdsTNrjrZ2BZdTcaG3pb7VgF44wABdEUFVi42ATk1ytoZhzuudhaPW17u"
        hdkey = hdkey.derive("m/44'/60'/0'")
        assert.strictEqual(hdkey.xprv, xprv)
        assert.strictEqual(hdkey.xpub, xpub)

        xprv = "xprvA25YyyPrViF32UzxxJz82kdP4Uc7hZtGhuoBHsdPKRQZxQZVdBA7hL2KdMy65agFHcZjMvdDYqHVPvDjUeRtPpk6xRpx8Q43kYoEv8N6ZFG"
        xpub = "xpub6F4uPUvkL5oLEy5S4LX8Pta7cWSc72c858in6G2zskwYqCteAiUNF8LoUczLUCHWUmWWJLXWCpHxReAxyreh51tAZpEoa1PibQTfBvXUH77"
        hdkey = hdkey.deriveChild(0)
        assert.strictEqual(hdkey.xprv, xprv)
        assert.strictEqual(hdkey.xpub, xpub)
        console.log('\n\n')
    });

    it('HDKey.publicDerive', async function () {
        var hdkey = HDKey.fromExtendedKey('xprv9s21ZrQH143K4TRpPm2z39uprRc2XVqFyRF9SpSdqieE7E1sQy2shDYzeugagMLSCZBrpXz4fHT4o5NtoPutYVaN22Dmc9J1HZyoDUxJGG6')
        console.log("public extented key:", hdkey.xpub)
        const [childHDKey, delta] = hdkey.publicDerive("m/44/60/0/0/9")
        console.log(Hex.pad64(childHDKey.publicKey.getX().toString(16)))
        console.log(Hex.pad64(childHDKey.publicKey.getY().toString(16)))
        let priv = hdkey.privateKey.add(delta)
        let publicKey = STARK.g.mul(priv)
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
            seed: '823662a8da34a37daf945048adce45804a2ecee33e48eecc6f4fcf5c25b8b4df454635cf0f59a5b91b506281a2b1adcbf573970783401783c52fbc93b4a34339',
            extendedKeys:[
                {
                    path: "m/44\'/60\'/0\'",
                    extendedPrivateKey:'xprv9y6YmrRso72Jb93H6tYmKLzmQrYrqR7gBp4aATGCrGj8DBb9Am63bttiVht5mq9YnEkXC64YT83fuhUHdQM54BaTxN5WeXtUPGDm9oUHG9u',
                    extendedPublicKey:'xpub6C5uBMxmdUabod7kCv5mgUwVxtPMEsqXZ2zAxqfpQcG75yvHiJQJ9hDCLztKz1DAKM6zxLNrAnEoZJJ1wuMKjwnEXHQJ9HNbmak6y47rQjp',
                },{
                    path: "m/44'/60'/0'/0",
                    extendedPrivateKey: "xprvA1pxVss2pzY2GZwXmqgFmfDqhxZ6by9EVoV52xvpqLXeW1dFXKUPib1f8QFTCyT9AyV6sgsz6mhxKatTTvSm6KpvSf9zKpLm15rr1LtQrBt",
                    extendedPublicKey: "xpub6EpJuPPvfN6KV41zssDG8oAaFzPb1Rs5s2QfqMLSPg4dNoxQ4rneGPL8yfH863ibWKvSGiy14bg1HdZgBhouadSc7n7wGDKVmYSU2ETD3CK"
                }
            ],
            finalKeys:[
                {
                    path: "m/44'/60'/0'/0/0",
                    privateKey: "05d499a11264878abf05e1457f8d781723bf12df4b52e34dbd0f2483e4a872e7",
                    publicKey: "00c6ba6339579a9def208f620562dc74a93d7965ad98b1e3d5223a94a49dd4090510f5b2e2799ce2175c09f1f66f003df27d290220c8de770bf3cab1cca3bf49",
                }, {
                    path: "m/44'/60'/0'/0/1",
                    privateKey: "07a71c74007f6d0a5ecd938abafc3c8dad2df0767fbd711b1ed463d6acf82c6a",
                    publicKey: "05fff8c0f1771234c924e9cd67e60eee149113f703fd5a2dd814fc94a4f9248e043614a893e63de088e7399cf6eee77cbaedd7e0488b8d01a5259ebf9f3d54ee",
                }, {
                    path: "m/44'/60'/0'/0/2",
                    privateKey: "036eaca453cbec52703fd3eeb059bafffa81830c26f6c8da284b7c1b4cef0833",
                    publicKey: "03f12cda076a80f6cafc64b705fa152486bb7640f762cc3b7a3342f0af56239106482338108c876a862a82ff2402cb45af384b749f4c56dac835b1ab34230747",
                }, {
                    path: "m/44'/60'/0'/0/3",
                    privateKey: "03fe2db076e326778d3fea75dbd50fef1f9b32dfdc5c71dd77d1be7183a9388f",
                    publicKey: "00c37e2d0f6cc406877b3d221b4522a03baa4955b5bebabc073410cac6216ccd015df14d04bcdca4f4f78b58a47a96ff11db2e3cd68d807f24f0ff773e1dc4a2",
                }, {
                    path: "m/44'/60'/0'/0/4",
                    privateKey: "05a53dc4f273cf88c92511aa16f12a8bd7092db100df933d82b87714618c6b73",
                    publicKey: "075e482bf0306768314d0debfe0bcd17104a7169a1c24cdaa0aacc43b6e072a1042ed3fb127b35c4e919f79899b62bf6fead3321e73e0b15ba07a4dcd2f85188",
                },{
                    path: "m/44'/60'/0'/0/5",
                    privateKey: "042d20b3f0bd4d1172ea4cdc5da18b48397074b695d7bc9e4911634b677de740",
                    publicKey: "03337d1095912dbeb1035301ea6a6067a804f1d3de17b28f723f2a16b002b2bf06a1a8c84f683ec4e1c3b78d083165258992246c1543d719bb0ebfd9b8ceb553",
                }, {

                    path: "m/44'/60'/0'/0/6",
                    privateKey: "0482c1c88296d886d5817dd67bc312155be303bcd6654b95e99b871a5f9fe9ea",
                    publicKey: "02c27330e82b4970cfc32aa96f9362010fae906462c189c8231b4a4129cf4d6e0606a8bf69109a8b84533252e78fc16ccb2205bf044c5089045f4a95dbcb7e48",
                }, {
                    path: "m/44'/60'/0'/0/7",
                    privateKey: "04440b1010a6396ab97ff0574d8b6980e16504beb713a50ad905ce5f209942d9",
                    publicKey: "05ddda1a4750a8d250ade882f3b0ddf1dd5dedf5d66258a3c1ebe4abdba8cb4d0218ae085ec27a9a70d4659f300c0df6d72b7dd3a3ccbf9298e7e8deb275107b",
                }, {
                    path: "m/44'/60'/0'/0/8",
                    privateKey: "025efdf616ff23b92c77c9d156fa212e4152468f9e21f0a5340437a33ea8c85c",
                    publicKey: "0766f9ce96f99aac196a431fee5c31d94af23a818ead5296b2496acfd416693a0626efcff2a7252b869e40a2795023555c9fe037deef0cda94efae331d6aeeab",
                }, {
                    path: "m/44'/60'/0'/0/9",
                    privateKey: "06b51d2d1875de6f6c871d148d0f239d3752ff2a91c3facde6939b09f73639cf",
                    publicKey: "04a000f994a12c627aec53d27660f1079318a7828bf8d591c975c6107e4d47d30128a5e4d184c780eb9894a8fea4648b1e37b135e0ef6dfa8ed303082adf2ef6",
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
            extendedPublicKey: 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gYyotNvvyxfSFHdYRvhrRqqhYtQ65nr6npp4ECa1Aihfue7ur72A',
            extendedChildKeys: [
                {
                    path: "m/0",
                    extendedPublicKey: "xpub69227CXwEoNKQdt3r6yJuvgzGTCjxSezbddDweKKtdiKfgeVqSGGUm1Ae37SuyHiNNWb2Qw2Qjaewjff5emRXMtWYtSw32VuRHdCzThPhCq"
                },
                {
                    path: "m/0/1",
                    extendedPublicKey: "xpub69zhLcrRsGCdhM545KBYQXHxAJDhBCBtWKZD5xV1HnVJCygDrAmwPrBbQotCFX8AfzhD7oVoQNwqP852SHkqo1DYV4t2nTTPVFN4YioJtYF"
                },
                {
                    path: "m/0/1/2",
                    extendedPublicKey: "xpub6D9bjCqim13X2yxCMmb44JvT27CuFkzq8fVdySw8R2Kn1fXc2srSZRZ44bGFf6cCWAeHNK78f1F6bidTh7YusnCpcNjtePErAPBJoTD9BNF"
                },
                {
                    path: "m/0/1/2/2",
                    extendedPublicKey: "xpub6EoB8vpGQe9sWFXke52yDTkHUubaiGj9PH5yVGbtZoWdB3ff8A638cGo4xzR9tgxzGzS8rNtCzRntrethRcA7iUGtbYa6tiB3xxtc6Javkh"
                },
                {
                    path: "m/0/1/2/2/1000000000",
                    extendedPublicKey: "xpub6HDm6q8B7zsLMkPVjcWPXUxRFoQjMwBA1rBuBdVx56MfEYrRyr5x1zmg9CNHowG1HdyQWWdDrC7KXwa2Py7PuCRUeDiPg1iUS4swAcufsjq"
                },
            ]
        },
        {
            extendedPublicKey: 'xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu4kY8n5bioLdUfEPLTSv1VNE1z8dekhgcwmzoR1weBESR596GUo',
            extendedChildKeys: [
                {
                    path: "m/0",
                    extendedPublicKey: "xpub68PVuZWELRWcMzpysZGfM9HQutEghoLZon1UtdbNjaxbp2zj8Ef4XAXYWR8b6DrxDESK8gGchD8Hv56rv1ML1GEALgu6f3wRjH2id2nrPgv"
                },
                {
                    path: "m/0/2147483647",
                    extendedPublicKey: "xpub69zfHQmZtFoiziFt9YvVuFfzTG7ZyZLKeXTLeG2pBHsLcz6jPc4BAG8tK2GEGLBU9duUdi64mJ9cmxHpC2LFXd7susryP4eGxq7zfFsrbxY"
                },
                {
                    path: "m/0/2147483647/1",
                    extendedPublicKey: "xpub6D8cuRPc836j6C8L8MWNwDP5wnvQAsrUctA8tFXheVCkdSVfoF9nxmt2WKvqbiq5VQChHwu4s7EW4JmLqr2KYUaegmTF588fG1yKiu7YRGN"
                },
                {
                    path: "m/0/2147483647/1/2147483646",
                    extendedPublicKey: "xpub6EqHNbyB3BnwomyrKTnN5uVboMsZb1QtHNxSWWb4pupdjdVBHg8wz9EemSXxe7zHFAe1hxZZinDppXDUpjNfLFynYxFMoTvsFj1AMxKywFG"
                },
                {
                    path: "m/0/2147483647/1/2147483646/2",
                    extendedPublicKey: "xpub6GTMMm8HX23pwCGYVF1AjN93uoV9LnTvrpDn5MsxCeSdeYvyRTvKMP6oCpHS3dyKaYq1GFkCBFVN9vvTAqdS9phyHjcrJPUPjgkJo4DZDEA"
                },
            ]
        },
        {
            extendedPublicKey: 'xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP53GjbHYCecidbWiVNSJMnzpCf331yzw7WJEmGmLMxpCDX38ZnJ',
            extendedChildKeys: [
                {
                    path: "m/0",
                    extendedPublicKey: "xpub67ycPEGkNZakY4AZYC7XieSZs5LEjf9gUowfNkvRJieWFPRJfskjnqfM6tesExV5QqR4PBPzaczP1NRq8NN3FoP383kUr9H3s7tz6bjGYKb"
                },
            ]
        },
        {
            extendedPublicKey: 'xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5G8gzs4ymLKzuZeqHyeBL9t194sU9awg7SEWUyQseFn9frxaqmi',
            extendedChildKeys: [
                {
                    path: "m/0",
                    extendedPublicKey: "xpub68gpKxmdWrsVAVVdxcBX8q3fC6pKCRbBTKg47eVg19cbGr2LcdSU5YwZETZsvUpPqLyuL7BdzEjc15mNKuP6VSRs6t8vQv4e6PSh5tYmtNv"
                },
                {
                    path: "m/0/1",
                    extendedPublicKey: "xpub6BBXA3vbmzBJ3YErcDw8FLHp3xuradSnZE9TrshWsjufv8QQzTAcxiW9aPZLXhvKZPcuyca2HyqwtehD28bM3nH9GP1uUXjATKkd1BnfjUM"
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
                    extendedPrivateKey: "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChijknudrxQkeY8C4q7g8b8PfQCYmkU8HXGzd7skrQXcpv7joExj",
                    extendedPublicKey: "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gYyotNvvyxfSFHdYRvhrRqqhYtQ65nr6npp4ECa1Aihfue7ur72A",
                },
                {
                    path: "m/0'",
                    extendedPrivateKey: "xprv9v2fhh1Bk6LzNA4ASFo32ffLfZGdUstmT41HhnbrC7yfSh8137rGJ4rnPb8PRB1Hhp1vXxGBeLTf6aQyrzub2h18rjV6toZ9XsDH6AVTmeV",
                    extendedPublicKey: "xpub69227CY5aTuHae8dYHL3Poc5Db77tLccpGvtWB1TkTWeKVT9afAWqsBGEt7fRQJPSw4bxsjfQewweKUNDuhWevBc1vcG37Qu73fsKt5eRBj"
                },
                {
                    path: "m/0'/1",
                    extendedPrivateKey: "xprv9wWA1hHBaGjD6EJN46wVCWgpVqfH4FByNYyGnb2e6ZeRjjfvS7Lch23x8BpdXUPVq9YS6qi5un2svXbZGoS9umki9aYa1dxYUuNQQ7QP8tZ",
                    extendedPublicKey: "xpub6AVWRCp5QeHWJiNqA8UVZedZ3sVmThupjmtsaySFeuBQcY14yeesEpNRySsKGB3vdTodVfNDPaZsMgZR5Q8up28mVJsWaTeyLjGLqW1uRbH"
                },
                {
                    path: "m/0'/1/2'",
                    extendedPrivateKey: "xprv9zG39oaRDennrwmj4UFj8bpkzrFmh3qf6WfvuRiHvs4fANRxNnPvuWj9rQQC6nkaoFf9tcqFqsrjWEYuwp8Pb494bB4bJNgr1zAYmogTe45",
                    extendedPublicKey: "xpub6DFPZK7K42M65RrCAVnjVjmVYt6G6WZWTjbXhp7uVCbe3Am6vKiBTK3dhfS3xxG5fveJepBDP1pJSMzQDBi8VNmsrKLKxFPNcov8hDC69sN"
                },
                {
                    path: "m/0'/1/2'/2",
                    extendedPrivateKey: "xprvA2R7A45S6Sw85mLqdRuq5c4RcPqNxhvFo5qPvzGWwbqrdTDQUp7uha3dMfJtgSyeueChZkdoPdGjJSp9F8hHMVzxjcqY9gbRg9dfkat3xu8",
                    extendedPublicKey: "xpub6FQTZZcKvpVRJFRJjTSqSk1AARfsNAe7AJkzjNg8VwNqWFYZ2MSAFNN7CvJe9R3ZSAkSjdoFt37bb3FmErYJzFJXEmatZBHbeuuAwn3UJiG"
                },
                {
                    path: "m/0'/1/2'/2/1000000000",
                    extendedPrivateKey: "xprvA2wqej1NYMiNyVPBbZjdNf6NxQX5QPUB79xqTQdmJmjnegt4j9ajbizeDhnE1s69zBRWJ1LNeFo5wCUpV9qPkZgRp5dzMiaUWQrsdPyXuFA",
                    extendedPublicKey: "xpub6FwC4EYGNjGgByTehbGdjo37WSMZorC2UNtSFo3Ns7GmXVDDGgtz9XK84xqfNRmRNRJ2UJYyJQtsiBQniGdC1bhMcNEMESVTkmJSt8D6GFa"
                },
            ]
        },
        {
            seed: 'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542',
            extendedChildKeys: [
                {
                    path: "m",
                    extendedPrivateKey: "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3ojGxZbUMbgMgGvXRikYAQ8AAhnJJWS9YGiU5g52KcNPhwiSNdR",
                    extendedPublicKey: "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu4kY8n5bioLdUfEPLTSv1VNE1z8dekhgcwmzoR1weBESR596GUo",
                },
                {
                    path: "m/0",
                    extendedPrivateKey: "xprv9uQ9W3yLW3xK9WkWmXjez1LgMrQCJLciSZ5t6FBmBFRcwEfaahLoyND4f8BeFNSCQhm4Nqzkq6uGU3zC8C5E7d1UM4LVpEaJAd1DzusuVTn",
                    extendedPublicKey: "xpub68PVuZWELRWcMzpysZGfM9HQutEghoLZon1UtdbNjaxbp2zj8Ef4XAXYWR8b6DrxDESK8gGchD8Hv56rv1ML1GEALgu6f3wRjH2id2nrPgv"
                },
                {
                    path: "m/0/2147483647'",
                    extendedPrivateKey: "xprv9w1JsuEpPYnPwFMns91HKzEbQYM2feN4wmZ1aH24UvBAGQ2HNVLUbXbDtFovf7N8MkxVq7aL7YmEwwNCmaGswoHW2g23CCv1238QAUfWeeo",
                    extendedPublicKey: "xpub69zfHQmiDvLh9jSFyAYHh8BKxaBX575vJzUcNfRg3Fi99CMRv2ej9KuhjWrccsWdjgzaXqiM1XuYTntNPcmMwP6m5iXdeFE99hLxuVD9G4y"
                },
                {
                    path: "m/0/2147483647'/1",
                    extendedPrivateKey: "xprv9y5wi5CNpCM3gVF8R3PUEyaateE2wuxHYxaoas59iNVpmN6tsNH2WN7nv2vLMvZasQNfymg9QiLSp3KDW9PEoGHH3qSXrUynQ6BduW1xYdL",
                    extendedPublicKey: "xpub6C5J7ajGeZuLtyKbX4vUc7XKSg4XMNg8vBWQPFUmGi2oeAS3QubH4ASGmHxc2qn2JMUMEgRnZJm4osVkk66p1RKWckaTXjdJ9UHboZRb31Q"
                },
                {
                    path: "m/0/2147483647'/1/2147483646'",
                    extendedPrivateKey: "xprv9zsjeqBFQQ55B4kiiDcpr9X9StKSA4DohtJ7oacdhoVhzYBSpeS1TstktGrZRtgqoqTjd5MchKPP6CkMRSbLJLKpjgi4F8q9rywwD9dYns5",
                    extendedPublicKey: "xpub6Ds64Li9EmdNPYqBpF9qDHTszv9vZWwf57Diby2FG92gsLWbNBkG1gDEjXty9dKj3ENDMZKPosUEUhcqYXxaph7Bvb93z3kyXsnssngNQih"
                },
                {
                    path: "m/0/2147483647'/1/2147483646'/2",
                    extendedPrivateKey: "xprvA2jGT6wCMKpUiJXFE3i7JqeNW2rDxyoinYi2jsHCvxJxzUnmyoTppvdKGRcTUd1WUPUqKxCZsEC7RnP99EGzZXoHKb52GxA8SmKwuZnwcyU",
                    extendedPublicKey: "xpub6FicrcU6BhNmvnbiL5F7fyb744giNSXa9mddYFgpVHqwsH7vXLn5Niwo7iadvakmhcQN1ze47NfQrdLX8mFJFedxeGeFusjrxbdtTrd14We"
                },
            ]
        },
        {
            seed: '4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be',
            extendedChildKeys: [
                {
                    path: "m",
                    extendedPrivateKey: 'xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6',
                    extendedPublicKey: 'xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP53GjbHYCecidbWiVNSJMnzpCf331yzw7WJEmGmLMxpCDX38ZnJ',
                },
                {
                    path: "m/0'",
                    extendedPrivateKey: "xprv9tzFyijzsrZRWwYzZadurqzN3UWvLMkrVrfEnjAPpRKMyVHYGrK3Uo7xLpXgyoc7he8hXAo3cY6ShSZn1k7E6VAzxjxr9FSiSDor8XcVWLy",
                    extendedPublicKey: "xpub67ycPEGtiE7ijRdTfcAvDyw6bWMQjpUhs5aqb7a1NkrLrHcgpPdJ2bSSC7WvC6fQCz7mKJYR66pQrZW5oCEzHDoWS73KnLQgRXQDWG4X1c2"
                },
            ]
        },
        {
            seed: '3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678',
            extendedChildKeys: [
                {
                    path: "m",
                    extendedPrivateKey: 'xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyAEN7fcfmGXgzVZn9rViy7Q1ZH8YqeNQu7ocbeTTWEsDqrzkqg',
                    extendedPublicKey: 'xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5G8gzs4ymLKzuZeqHyeBL9t194sU9awg7SEWUyQseFn9frxaqmi',
                },
                {
                    path: "m/0'",
                    extendedPrivateKey: "xprv9uhTvTEt29rA7PkdZUGy492DJPLoxBfRpYS54KK7tm1fHdQnDpExgEw3DXKZQMs4aGiaTyNLxefwYigydRF94TnKehvpYxhFZUe43VAYwW1",
                    extendedPublicKey: "xpub68gpKxmmrXQTKsq6fVoyRGxwrRBJMePHBmMfrhijT6YeARjvmMZDE3FX4pFgCQikGFtxWEF6BeKTgWZz56pNn64FKQZCXw2fDcqjexmRj8u"
                },
                {
                    path: "m/0'/1'",
                    extendedPrivateKey: "xprv9wkMpy6Zty6XJiag2ghgEHxx6GMKERQ6gMPfh6zhjfuwCzSCxMoWQSVx34oy3R8JRqsGMSxtcSGDg2m3x7bDoAoEyPhKtSmgM3ddBCeH6wi",
                    extendedPublicKey: "xpub6AjiEUdTjLepXCf98iEgbRugeJBodt7x3aKGVVQKJ1Sv5nmMVu7kxEpRtMmkux9UcGx7dznrrEBd2GAhp8ak7rtbVDVd1Ft1ibudcKrwcdn"
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
