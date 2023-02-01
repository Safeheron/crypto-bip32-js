import * as assert from 'assert'
import * as cryptoJS from "crypto-js"
import * as elliptic from 'elliptic'
const P256 = new elliptic.ec('p256')
const Secp256k1 = new elliptic.ec('secp256k1')
import {Secp256k1HDKey as HDKey} from "..";
import {Hex} from "@safeheron/crypto-utils";

describe('Elliptic Curve Encryption', function () {
    it('HDKey.fromMasterSeed', async function () {
        var seed = 'a0c42a9c3ac6abf2ba6a9946ae83af18f51bf1c9fa7dacc4c92513cc4dd015834341c775dcd4c0fac73547c5662d81a9e9361a0aac604a73a321bd9103bce8af'
        var hdkey = HDKey.fromMasterSeed(cryptoJS.enc.Hex.parse(seed))
        console.log(hdkey.xprv)
        console.log(hdkey.xpub)
        console.log('\n\n')
    });

    it('HDKey.fromExtendedPrivateKey', async function () {
        var hdkey = HDKey.fromExtendedKey('xprv9yUAqePdq9JYrAnxHWns8ooPknGjWSLkCYtKNB1EEqFKoqrX4DV91bP7YAefJzQU8CRHpsioXdVTMGHu8BhmGhPYSnXRoe8Sy31aoQGnQco')
        console.log(hdkey.xprv)
        console.log(hdkey.xpub)
        hdkey = hdkey.deriveChild(0)
        assert.strictEqual(hdkey.xprv,'xprvA1CnPMjbTkNNtEVrTvG8SHrLPp7tc6xXDkpY59NGSy6fyHmLzTrFdcHWq5cqsiwK758pGuBaX9XJY1kR6PacgG3sJbAmcQCsarTgh8EJvY2')
        assert.strictEqual(hdkey.xpub,'xpub6EC8nsGVJ7vg6iaKZwo8oRo4wqxP1ZgNayk8sXmt1Jder66VY1AWBQbzgKz2X9fhvyJDtAZ425KwFm9bKLYD9cUUjddMevsRD2Qdrnk9a1m')
        console.log('\n\n')
    });

    it('HDKey.fromExtendedPublicKey', async function () {
        var hdkey = HDKey.fromExtendedKey('xpub6CTXF9vXfWrr4esRPYKsVwk8Jp7Duu4bZmovAZQqoAnJgeBfbkoPZPhbPTvgcm2HRM7TmyYuLKS6MNh4eHvGV2nZAjtYXg7hbNWz2vZ7rMv')
        hdkey = hdkey.deriveChild(0)
        assert.strictEqual(hdkey.xpub,'xpub6EC8nsGVJ7vg6iaKZwo8oRo4wqxP1ZgNayk8sXmt1Jder66VY1AWBQbzgKz2X9fhvyJDtAZ425KwFm9bKLYD9cUUjddMevsRD2Qdrnk9a1m')
        console.log('\n\n')
    });

    it('HDKey.derive', async function () {
        var seed = '439cf456bec21b3134b586c50d80dcbb6358c9d483fb65fe3e4a90d0a108e42089c9923304638c21e555553b8f61bb48be27615e727a46a443311f4cbf607ceb'
        var hdkey = HDKey.fromMasterSeed(cryptoJS.enc.Hex.parse(seed))
        console.log(hdkey.xprv)
        console.log(hdkey.xpub)
        //hdkey = hdkey.derive("m/44'/60'/0'/0")
        hdkey = hdkey.derive("m/44'/60'/0'")
        console.log(hdkey.xprv)
        console.log(hdkey.xpub)
        hdkey = hdkey.deriveChild(0)
        console.log(hdkey.xprv)
        console.log(hdkey.xpub)
        console.log('\n\n')
    });

    function runCase(t) {
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

    let testCases = [
        {
            seed: '439cf456bec21b3134b586c50d80dcbb6358c9d483fb65fe3e4a90d0a108e42089c9923304638c21e555553b8f61bb48be27615e727a46a443311f4cbf607ceb',
            extendedKeys:[
                {
                    path: "m/44\'/60\'/0\'",
                    extendedPrivateKey:'xprv9yUAqePdq9JYrAnxHWns8ooPknGjWSLkCYtKNB1EEqFKoqrX4DV91bP7YAefJzQU8CRHpsioXdVTMGHu8BhmGhPYSnXRoe8Sy31aoQGnQco',
                    extendedPublicKey:'xpub6CTXF9vXfWrr4esRPYKsVwk8Jp7Duu4bZmovAZQqoAnJgeBfbkoPZPhbPTvgcm2HRM7TmyYuLKS6MNh4eHvGV2nZAjtYXg7hbNWz2vZ7rMv',
                },{
                    path: "m/44'/60'/0'/0",
                    extendedPrivateKey: "xprvA1CnPMjbTkNNtEVrTvG8SHrLPp7tc6xXDkpY59NGSy6fyHmLzTrFdcHWq5cqsiwK758pGuBaX9XJY1kR6PacgG3sJbAmcQCsarTgh8EJvY2",
                    extendedPublicKey: "xpub6EC8nsGVJ7vg6iaKZwo8oRo4wqxP1ZgNayk8sXmt1Jder66VY1AWBQbzgKz2X9fhvyJDtAZ425KwFm9bKLYD9cUUjddMevsRD2Qdrnk9a1m"
                }
            ],
            finalKeys:[
                {
                    path: "m/44'/60'/0'/0/0",
                    privateKey: "07cc37fe89786282296952fb4835d1476ecc2c45bfa91fa5c691ef1ea2186c36",
                    publicKey: "b98da98747e0fe4945203807ea3d457b8dca15331e42a6c0bb620dffe958288874d819221672e9dc021011fab407cb77367a883352096c0d5b43a577a4930616",
                }, {
                    path: "m/44'/60'/0'/0/1",
                    privateKey: "9086fbf4deca1cd9425e66705203421340d075b007b09890edb63cbedb5d79a8",
                    publicKey: "5bef4f4cd3c5be92a01dc47b0e98f22e24c0b8caa4358f61a463e540457563ce61e287895fc09e3ba9c316dd3b1eae40681eab2fc0f4ea308c5015deaee08325",
                }, {
                    path: "m/44'/60'/0'/0/2",
                    privateKey: "cdea5485073b84d4e3209b6c6008230edc0b7df152f78bb0c5524da67daf214e",
                    publicKey: "ac164534573b1718dbd24b926944d5dbd30de07b6c5020c2a204f3bca51eccb68fc99bee2d4fe1b997c4b33bf6a96ef47a68364d74b117304eff7cd36fad6d80",
                }, {
                    path: "m/44'/60'/0'/0/3",
                    privateKey: "56adc0f53cb1375d66180daecc7c8de318b20144ceeca933c451068c9ff566ed",
                    publicKey: "ed42f6e7a6f6386c2d18b208aebb7b2abf655755f2fbd75d0844863494a748a892bfdd680dbdbb5462ee1b514c4e57ee61d01d4698756e3759555a72aa90f94a",
                }, {
                    path: "m/44'/60'/0'/0/4",
                    privateKey: "93a1f833a5a2883b6ddd1f1f7904f005c1595872f9f81983b9b5606632aabe29",
                    publicKey: "a24c3f4e522095c64cec543a6fbc7aa66a385d11895e10f9dbf30130735037b90af6b3bb808d1eeedea8f503c6e4794d5c7d313176ad674423dc41557b6e6e1a",
                },{
                    path: "m/44'/60'/0'/0/5",
                    privateKey: "044b99c5bebfe79500c39f554c9d2f6e25b211b47a2baea1d258e228b09fc01b",
                    publicKey: "37e310f496f186736f23d3fa31454cfd56a57b40082ba74fb9e9dd82b25a8c40749f8419af0e1ba942ab2be6d606105c032704d98b94f82bb87863deb9298643",
                }, {

                    path: "m/44'/60'/0'/0/6",
                    privateKey: "4036548180ace2524db1a989481e4fefd5c1c62e55e062a91371f4c89b845d75",
                    publicKey: "93535f50d60d1ee74eea213523adc92fa4ec670d96609ec9385b741c97b26828fcb1dae876cbad8fd59e17a15fde1804ac15aac67effa5d82f7109a652af32c7",
                }, {
                    path: "m/44'/60'/0'/0/7",
                    privateKey: "f65b65f991d2269492096d9a1f611687d3f40c7b13e9f67f9673c50c31232e46",
                    publicKey: "716ef85cc1fcb8a57680bcb897ee5249638fd1909336f8b5a70b24a49dd0ad7c710d5f33e7056da7e3f76fd99d31c2635059742004c5d754f16c981f8b307dc5",
                }, {
                    path: "m/44'/60'/0'/0/8",
                    privateKey: "14463042574a78b4a12aa5225f3f4e194a28f9f32bce818a071621c2d102ad7d",
                    publicKey: "a6f0ec38653eb3f945953052eb518846a022839472bb39b1f8b535989a33d34f5d45606e420d2927380d15156b36916e0ce5033c35f929e10134741021da6b65",
                }, {
                    path: "m/44'/60'/0'/0/9",
                    privateKey: "57a2225e268db85a36130f982f3e441abb84bd3bb95f771348ab10b64a7a775e",
                    publicKey: "8c6bab0b10a32d9d866c7c4a42c090d84508d45896339b4a9cbc01718a1223ca7ee1ad2abcbf6881181b5fd3a158a840190d89e412f5e46739ecad2e3c31fb99",
                }
            ]
        }
    ]

    it('HDKey.test', async function (){
        for(let i = 0; i < testCases.length; i ++) {
            runCase(testCases[i])
        }
    });

    it('HDKey.publicDerive, for HD MPC ECDSA', async function () {
        var hdkey = HDKey.fromExtendedKey('xprv9s21ZrQH143K3vh26yNdQCf8euP1DWqXv1zAoZB6JARsK96tsCwxgoBQbso7WAP18Jr4tGcE7evR1vahPAAntkdxP7UyeWfA9skuFyRcum9')
        console.log("public extented key:", hdkey.xpub)
        const [childHDKey, delta] = hdkey.publicDerive("m/44/60/0/0/9")
        console.log(Hex.pad64(childHDKey.publicKey.getX().toString(16)))
        console.log(Hex.pad64(childHDKey.publicKey.getY().toString(16)))
        let priv = hdkey.privateKey.add(delta)
        let publicKey = Secp256k1.g.mul(priv)
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


    let officialTestCases = [
        {
            seed: '000102030405060708090a0b0c0d0e0f',
            extendedKeys: [
                {
                    path: "m",
                    extendedPrivateKey: 'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi',
                    extendedPublicKey: 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8',
                },
                {
                    path: "m/0'",
                    extendedPrivateKey: "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
                    extendedPublicKey: "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"
                },
                {
                    path: "m/0'/1",
                    extendedPrivateKey: "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
                    extendedPublicKey: "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"
                },
                {
                    path: "m/0'/1/2'",
                    extendedPrivateKey: "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
                    extendedPublicKey: "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5"
                },
                {
                    path: "m/0'/1/2'/2",
                    extendedPrivateKey: "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
                    extendedPublicKey: "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV"
                },
                {
                    path: "m/0'/1/2'/2/1000000000",
                    extendedPrivateKey: "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
                    extendedPublicKey: "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"
                },
            ]
        },
        {
            seed: 'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542',
            extendedKeys: [
                {
                    path: "m",
                    extendedPrivateKey: 'xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U',
                    extendedPublicKey: 'xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB',
                },
                {
                    path: "m/0",
                    extendedPrivateKey: "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt",
                    extendedPublicKey: "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"
                },
                {
                    path: "m/0/2147483647'",
                    extendedPrivateKey: "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9",
                    extendedPublicKey: "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a"
                },
                {
                    path: "m/0/2147483647'/1",
                    extendedPrivateKey: "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef",
                    extendedPublicKey: "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon"
                },
                {
                    path: "m/0/2147483647'/1/2147483646'",
                    extendedPrivateKey: "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc",
                    extendedPublicKey: "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL"
                },
                {
                    path: "m/0/2147483647'/1/2147483646'/2",
                    extendedPrivateKey: "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j",
                    extendedPublicKey: "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt"
                },
            ]
        },
        {
            seed: '4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be',
            extendedKeys: [
                {
                    path: "m",
                    extendedPrivateKey: 'xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6',
                    extendedPublicKey: 'xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13',
                },
                {
                    path: "m/0'",
                    extendedPrivateKey: "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L",
                    extendedPublicKey: "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y"
                },
            ]
        },
        {
            seed: '3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678',
            extendedKeys: [
                {
                    path: "m",
                    extendedPrivateKey: 'xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv',
                    extendedPublicKey: 'xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmgBUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa',
                },
                {
                    path: "m/0'",
                    extendedPrivateKey: "xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G",
                    extendedPublicKey: "xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xfFEqHd2AddP56Tqp4o56AePAgCjYdvpW2PU2jbUPFKsav5ut6Ch1m"
                },
                {
                    path: "m/0'/1'",
                    extendedPrivateKey: "xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1",
                    extendedPublicKey: "xpub6BJA1jSqiukeaesWfxe6sNK9CCGaujFFSJLomWHprUL9DePQ4JDkM5d88n49sMGJxrhpjazuXYWdMf17C9T5XnxkopaeS7jGk1GyyVziaMt"
                },
            ]
        },
    ]

    function runOfficialCase(t) {
        var seed = t.seed
        var hdkey = HDKey.fromMasterSeed(cryptoJS.enc.Hex.parse(seed))
        console.log('xpub: ', hdkey.xpub)
        console.log('xprv: ', hdkey.xprv)
        t.extendedKeys.forEach(function (ek) {
            let hk = hdkey.derive(ek.path)
            assert.strictEqual(hk.xprv, ek.extendedPrivateKey)
            assert.strictEqual(hk.xpub, ek.extendedPublicKey)
        })
    }

    it('HDKey.Official Test', async function (){
        for(let i = 0; i < officialTestCases.length; i ++) {
            runOfficialCase(officialTestCases[i])
        }
    });

})
