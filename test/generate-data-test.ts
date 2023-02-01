import * as assert from 'assert'
import * as BN from 'bn.js'
import {Rand, Prime} from "@safeheron/crypto-rand"
import * as elliptic from 'elliptic'
const Ed25519 = new elliptic.eddsa('ed25519')
import * as CryptoJS from "crypto-js"
import {Ed25519HDKey as HDKey} from "..";
const fs = require("fs")

describe.skip('generate data', function () {
    it('generate priv data', async function () {
        this.timeout(0)
        let seed = await Rand.randomBNStrict(32)
        let seedHex = seed.toString(16)
        console.log("seed_str: ", seedHex)
        try {
        fs.writeFileSync('priv_derivation_js.txt', seedHex + '\n' + 'm' + '\n', "utf8")
        } catch(err) {
            return console.error(err)
        }

        let hd_root = HDKey.fromMasterSeed(CryptoJS.enc.Hex.parse(seedHex))
        let root_xprv = hd_root.xprv;
        console.log("root_xprv: ", root_xprv)
        try {
            fs.appendFileSync('priv_derivation_js.txt', root_xprv + '\n', "utf8")
        } catch (err) {
            return console.error(err)
        }
        let root_xpub = hd_root.xpub;
        console.log("root_xpub: ", root_xpub)
        try {
            fs.appendFileSync('priv_derivation_js.txt', root_xpub + '\n', "utf8")
        } catch (err) {
            return console.error(err)
        }

        let path = []
        path[0] = []
        let max = new BN("80000000", 16)

        for (let i = 0; i < 1000; i++) {
            let r = await Rand.randomBNLt(max)
            let path_str = "m/" + r.toString(10)
            let hardened = await Rand.randomBN(4)
            if (hardened >= max) {
                path_str += "'";
            }
            try {
            fs.appendFileSync('priv_derivation_js.txt', path_str + '\n', "utf8")
            } catch (err) {
                return console.error(err)
            }
            let child = hd_root.derive(path_str)
            let child_xprv = child.xprv
            try {
                fs.appendFileSync('priv_derivation_js.txt', child_xprv + '\n', "utf8")
            } catch (err) {
                return console.error(err);
            }
            let child_xpub = child.xpub
            try {
                fs.appendFileSync('priv_derivation_js.txt', child_xpub+ '\n', "utf8")
            } catch (err) {
                return console.error(err);
            }
            path[0].push(path_str)
        }
        for (let j = 1; j < 5; j++) {
            path[j] = []
            for (let i = 0; i < 1000; i++) {
                let r = await Rand.randomBNLt(max)
                let path_str = path[j-1][i] + '/' + r.toString(10)
                let hardened = await Rand.randomBN(4)
                if (hardened >= max) {
                    path_str += "'";
                }
                try {
                    fs.appendFileSync('priv_derivation_js.txt', path_str + '\n', "utf8")
                } catch (err) {
                    return console.error(err)
                }
                let child = hd_root.derive(path_str);
                let child_xprv = child.xprv;
                try {
                    fs.appendFileSync('priv_derivation_js.txt', child_xprv + '\n', "utf8")
                } catch (err) {
                    return console.error(err);
                }
                let child_xpub = child.xpub;
                try {
                    fs.appendFileSync('priv_derivation_js.txt', child_xpub+ '\n', "utf8")
                } catch (err) {
                    return console.error(err);
                }
                path[j].push(path_str)
            }
        }
    });

    it('generate pub data', async function () {
        this.timeout(0)
        let seed = await Rand.randomBNStrict(32)
        let seedHex = seed.toString(16)
        console.log("seed_str: ", seedHex)
        try {
            fs.writeFileSync('pub_derivation_js.txt', seedHex + '\n' + 'm' + '\n', "utf8")
        } catch (err) {
            return console.error(err)
        }
        let hd_root = HDKey.fromMasterSeed(CryptoJS.enc.Hex.parse(seedHex))
        let root_xpub = hd_root.xpub;
        try {
            fs.appendFileSync('pub_derivation_js.txt', root_xpub + '\n', "utf8")
        } catch (err) {
            return console.error(err)
        }
        console.log("root_xpub: ", root_xpub)

        let path = []
        path[0] = []
        let max = new BN("80000000", 16)
        for (let i = 0; i < 1000; i++) {
            let r = await Rand.randomBNLt(max)
            let path_str = "m/" + r.toString(10)
            try {
                fs.appendFileSync('pub_derivation_js.txt', path_str + '\n', "utf8")
            } catch (err) {
                return console.error(err)
            }

            let [child, dealt] = hd_root.publicDerive(path_str)

            let child_xpub = child.xpub
            try {
                fs.appendFileSync('pub_derivation_js.txt', child_xpub + '\n', "utf8")
            } catch (err) {
                return console.error(err)
            }
            path[0].push(path_str)
        }
        for (let j = 1; j < 5; j++) {
            path[j] = []
            for (let i = 0; i < 1000; i++) {
                let r = await Rand.randomBNLt(max)
                let path_str = path[j-1][i] + '/' + r.toString(10)
                try {
                    fs.appendFileSync('pub_derivation_js.txt', path_str + '\n', "utf8")
                } catch(err) {
                    return console.error(err)
                }

                let [child, dealt] = hd_root.publicDerive(path_str);

                let child_xpub = child.xpub;
                try {
                    fs.appendFileSync('pub_derivation_js.txt', child_xpub + '\n', "utf8")
                } catch (err) {
                    return console.error(err)
                }
                path[j].push(path_str)
            }
        }
    });

    it('verify priv data', async function (){
        this.timeout(0)
        let data
        try {
             data = fs.readFileSync("priv_derivation.txt", "utf8")
        } catch (err) {
            return console.log(err)
        }
        const lines = data.split(/\r?\n/)
        let seedHex = lines[0]
        console.log("seedHex: ", seedHex)
        let hd_root = HDKey.fromMasterSeed(CryptoJS.enc.Hex.parse(seedHex));
        let m = lines[1]
        console.log("m: ", m)
        let root_xprv = hd_root.xprv;
        let root_xprv_expected = lines[2]
        console.log("root_xprv_expected: ", root_xprv_expected)
        assert(root_xprv == root_xprv_expected)
        let root_xpub = hd_root.xpub;
        let root_xpub_expected = lines[3]
        console.log("root_xpub_expected: ", root_xpub_expected)
        assert(root_xpub == root_xpub_expected)
        let i
        for (i = 4; i < lines.length; i = i + 3) {
            let path = lines[i];
            let child = hd_root.derive(path);
            let child_xprv = child.xprv;
            let child_xprv_expected =  lines[i + 1];
            let child_xpub = child.xpub;
            let child_xpub_expected = lines[i + 2];
            assert(child_xprv == child_xprv_expected)
            assert(child_xpub == child_xpub_expected)
        }
    })
    it('verify pub data', async function (){
        this.timeout(0)
        let data
        try {
            data = fs.readFileSync("pub_derivation.txt", "utf8")
        } catch (err) {
            return console.log(err)
        }
        const lines = data.split(/\r?\n/)
        let seedHex = lines[0]
        console.log("seedHex: ", seedHex)
        let hd_root = HDKey.fromMasterSeed(CryptoJS.enc.Hex.parse(seedHex));
        let m = lines[1]
        let root_xpub = hd_root.xpub;
        let root_xpub_expected = lines[2]
        assert(root_xpub == root_xpub_expected)
        console.log("root_xpub_expected: ", root_xpub_expected)
        let i
        for (i = 3; i < lines.length; i = i + 2) {
            let path = lines[i];
            let [child, dealt] = hd_root.publicDerive(path);
            let child_xpub = child.xpub;
            let child_xpub_expected = lines[i + 1];
            assert(child_xpub == child_xpub_expected)
        }
    })
})