import * as assert from 'assert'
import * as bs58check from 'bs58check'
import * as BN from 'bn.js'
import * as elliptic from 'elliptic'
import * as cryptoJS from "crypto-js"
const Ed25519 = new elliptic.eddsa('ed25519')
import {Hex, CryptoJSBytes} from "@safeheron/crypto-utils"

const MASTER_SECRET = cryptoJS.enc.Utf8.parse('Bitcoin seed')
const HARDENED_OFFSET = 0x80000000
const LEN = 78

const ZERO = new BN('0', 16)

// Bitcoin hardcoded by default, can use package `coininfo` for others
const BITCOIN_VERSIONS = {private: 0x03126f7c, public: 0x031273b7}

// function Buffer2CryptoJSArray(buffer){
//     const hexStr = buffer.toString('hex')
//     return Hex.pad64(hexStr)
// }

function HashForPrivateDerive(chainCode, index, privateKey){
    // data = 0x00 || ser256(kpar) || ser32(index)
    let data = '00' + Hex.fromBytes(privateKey.toArray('le', 32)) + Hex.pad8(index.toString(16))
    let chainCodeWordArray = Hex.toCryptoJSBytes(Hex.pad64(chainCode.toString(16)))
    let dataWordArray = cryptoJS.enc.Hex.parse(data)
    let h = cryptoJS.HmacSHA512(dataWordArray, chainCodeWordArray)
    let hStr = cryptoJS.enc.Hex.stringify(h)
    return hStr
}

function HashForPublicDerive(chainCode, index, publicKey){
    // Mark: for ed25519 the length of serP(point(kpar)) is 32
    // data = 0x05 || serP(point(kpar)) || ser32(index)
    //      = 0x05 || serP(Kpar) || ser32(index)
    let data = '05' + Hex.fromBytes(Ed25519.encodePoint(publicKey)) + Hex.pad8(index.toString(16))
    let chainCodeWordArray = Hex.toCryptoJSBytes(Hex.pad64(chainCode.toString(16)))
    let dataWordArray = cryptoJS.enc.Hex.parse(data)
    let h = cryptoJS.HmacSHA512(dataWordArray, chainCodeWordArray)
    let hStr = cryptoJS.enc.Hex.stringify(h)
    return hStr
}

function hash160(wordArray: CryptoJSBytes) {
    let sha = cryptoJS.SHA256(wordArray)
    return cryptoJS.RIPEMD160(sha)
}

export class Ed25519HDKey {
    public versions: { private: number, public: number }
    public depth: number
    public index: number
    private _privateKey: BN
    private _publicKey: any // elliptic point
    public chainCode: any
    private _fingerprint: number
    public parentFingerprint: number
    private _identifier: any

    public static HARDENED_OFFSET = HARDENED_OFFSET

    public constructor(versions: { private: number, public: number }) {
        this.versions = versions || BITCOIN_VERSIONS
        this.depth = 0
        this.index = 0
        this._privateKey = null // BN
        this._publicKey = null // elliptic point
        this.chainCode = null
        this._fingerprint = 0
        this.parentFingerprint = 0
        this._identifier = null
    }

    public get fingerprint(): number {
        return this._fingerprint
    }

    public get identifier(): number {
        return this._identifier
    }

    public get pubKeyHash(): number {
        return this._identifier
    }

    public get privateKey(): BN {
        return this._privateKey
    }

    public set privateKey(value: string | BN) {
        if (typeof value === 'string') {
            assert.equal(value.length, 32 * 2, 'Private key must be 32 bytes.')
            var valueNum = new BN(value, 16)
            if (valueNum.gt(Ed25519.curve.n) || valueNum.eq(0)) throw 'Invalid private key'
            this._privateKey = valueNum
        } else {
            //value = value.umod(Ed25519.curve.n)
            // Check if value % order === 0
            assert(!value.gt(Ed25519.curve.n) && !value.eq(0), 'Invalid private key')
            this._privateKey = value
        }

        this._publicKey = Ed25519.g.mul(this._privateKey)
        this._identifier = hash160(
            cryptoJS.enc.Hex.parse(Hex.fromBytes(Ed25519.encodePoint(this.publicKey))))
        this._fingerprint = parseInt(cryptoJS.enc.Hex.stringify(this._identifier).substr(0, 4 * 2), 16)
    }

    public get privateKeyAsHex() {
        return Hex.fromBytes(this._privateKey.toArray('le', 32))
    }

    public get publicKey(): any {
        return this._publicKey
    }

    public set publicKey(value: any) {
        if(typeof value === 'string'){
            assert.equal(value.length, 32 * 2, 'Public key must be 32 bytes(Ed25519 public key).')
            this._publicKey = Ed25519.decodePoint(value, 'hex')
        }else {
            assert(Ed25519.curve.validate(value), 'Invalid public key')
            this._publicKey = value
        }

        this._identifier = hash160(
            cryptoJS.enc.Hex.parse(Hex.fromBytes(Ed25519.encodePoint(this.publicKey))))
        this._fingerprint = parseInt(cryptoJS.enc.Hex.stringify(this._identifier).substr(0, 4*2), 16)
        this._privateKey = null
    }

    public get publicKeyAsHex() {
        return Hex.fromBytes(Ed25519.encodePoint(this._publicKey))
    }

    public get xprv(): string {
        if (this._privateKey) {
            // with prefix
            let keyBuff = '00' + this.privateKeyAsHex
            return bs58check.encode(Ed25519HDKey.serialize(this, this.versions.private, keyBuff))
        }
        else return null
    }

    public get xpub(): string {
        let keyBuff = '00' + this.publicKeyAsHex
        return bs58check.encode(Ed25519HDKey.serialize(this, this.versions.public, keyBuff))
    }

    public derive(path: string): Ed25519HDKey {
        if (path === 'm' || path === 'M' || path === "m'" || path === "M'") {
            return this
        }

        let entries = path.split('/')
        let hdkey = this
        entries.forEach(function (c, i) {
            if (i === 0) {
                assert(/^[mM]{1}/.test(c), 'Path must start with "m" or "M"')
                return
            }

            let hardened = (c.length > 1) && (c[c.length - 1] === "'")

            if (c[c.length - 1] === "'") {
                c = c.substring(0, c.length - 1);
            }

            if (/^\d+$/.test(c)) {
                let childIndex = parseInt(c, 10) // & (HARDENED_OFFSET - 1)
                assert(childIndex < HARDENED_OFFSET, 'Invalid index')
                if (hardened) childIndex += HARDENED_OFFSET

                // @ts-ignore
                hdkey = hdkey.deriveChild(childIndex)
            } else {
                throw "Invalid index"
            }
        })

        return hdkey
    }

    public deriveChild(index: number): Ed25519HDKey {
        let isHardened = index >= HARDENED_OFFSET

        let I = ""
        if (isHardened) { // Hardened child
            assert(this._privateKey, 'Could not derive hardened child key')
            I = HashForPrivateDerive(this.chainCode, index, this._privateKey)
        } else { //  No-harden child
            I = HashForPublicDerive(this.chainCode, index, this._publicKey)
        }

        // Big endian
        let IL = new BN(Hex.reverseHex(I.substr(0, 64)), 16)
        let IR = new BN(I.substr(64), 16)

        let hd = new Ed25519HDKey(this.versions)

        // Private parent key -> private child key
        if (this._privateKey) {
            // ki = parse256(IL) + kpar (mod n)
            try {
                let _privateKey = this._privateKey.add(IL).umod(Ed25519.curve.n)
                // throw if IL >= n || (privateKey + IL) === 0
                if(_privateKey.eqn(0)) throw "Invalid child private key!"
                hd.privateKey = _privateKey
            } catch (err) {
                // In case parse256(IL) >= n or ki == 0, one should proceed with the next value for i
                return this.deriveChild(index + 1)
            }
            // Public parent key -> public child key
        } else {
            // Ki = point(parse256(IL)) + Kpar
            //    = G*IL + Kpar
            try {
                let _publicKey = this._publicKey.add(Ed25519.g.mul(IL))
                // throw if IL >= n || (g**IL + publicKey) is infinity
                if(_publicKey.isInfinity()) throw "Invalid child public key!"
                hd.publicKey = _publicKey
            } catch (err) {
                // In case parse256(IL) >= n or Ki is the point at infinity, one should proceed with the next value for i
                return this.deriveChild(index + 1)
            }
        }

        hd.chainCode = IR
        hd.depth = this.depth + 1
        hd.parentFingerprint = this.fingerprint// .readUInt32BE(0)
        hd.index = index

        return hd
    }


    public publicDerive(path: string): [Ed25519HDKey, BN] {
        let delta = ZERO

        if (path.indexOf("'") != -1) {
            throw "Could not derive hardened child key!"
        }

        let entries = path.split('/')
        let hdkey = this
        entries.forEach(function (c, i) {
            if (i === 0) {
                assert(/^[mM]{1}/.test(c), 'Path must start with "m" or "M"')
                return
            }

        //    let hardened = (c.length > 1) && (c[c.length - 1] === "'")
            if (/^\d+$/.test(c)) {
                let childIndex = parseInt(c, 10) // & (HARDENED_OFFSET - 1)
                assert(childIndex < HARDENED_OFFSET, 'Invalid index')
                //   if (hardened) childIndex += HARDENED_OFFSET
                const [_hdkey, _delta] = hdkey.publicDeriveChild(childIndex)
                delta = delta.add(_delta).umod(Ed25519.curve.n)
                // @ts-ignore
                hdkey = _hdkey
            } else {
                throw "Invalid index"
            }
        })

        return [hdkey, delta]
    }

    public publicDeriveChild(index: number): [Ed25519HDKey, BN] {
        //let isHardened = index >= HARDENED_OFFSET

        // No-Harden child
        let I = HashForPublicDerive(this.chainCode, index, this._publicKey)
        // IL: little-endian
        let IL = new BN(Hex.reverseHex(I.substr(0, 64)), 16)
        // It doesn't matter for iR's encode.
        let IR = new BN(I.substr(64), 16)

        let hd = new Ed25519HDKey(this.versions)

        // Public parent key -> public child key
        // Ki = point(parse256(IL)) + Kpar
        //    = G*IL + Kpar
        try {
            let _publicKey = this._publicKey.add(Ed25519.g.mul(IL))
            // throw if IL >= n || (g**IL + publicKey) is infinity
            if(_publicKey.isInfinity()) throw "Invalid child public key!"
            hd.publicKey = _publicKey
        } catch (err) {
            // In case parse256(IL) >= n or Ki is the point at infinity, one should proceed with the next value for i
            return this.publicDeriveChild(index + 1)
        }

        hd.chainCode = IR
        hd.depth = this.depth + 1
        hd.parentFingerprint = this.fingerprint// .readUInt32BE(0)
        hd.index = index

        let delta = IL
        return [hd, delta]
    }

    public sign(hash: number[]): number[] {
        throw "Not implemented!"
    }

    public verify(hash: number[], signature: []): boolean {
        throw "Not implemented!"
    }

    public static fromMasterSeed(seedWordArray: CryptoJSBytes): Ed25519HDKey {
        let I = cryptoJS.enc.Hex.stringify(cryptoJS.HmacSHA512(seedWordArray, MASTER_SECRET))
        // Big endian
        let IL = new BN(Hex.reverseHex(I.substr(0, 64)), 16)
        let IR = new BN(I.substr(64), 16)

        IL = IL.umod(Ed25519.curve.n)
        if (IL.eqn(0)) {
            throw "Invalid Master Key!"
        }

        let hdkey = new Ed25519HDKey(BITCOIN_VERSIONS)
        hdkey.privateKey = IL
        hdkey.chainCode = IR

        return hdkey
    }

    public static fromMasterSeedHex(seedHex: string): Ed25519HDKey {
        return Ed25519HDKey.fromMasterSeed(cryptoJS.enc.Hex.parse(seedHex))
    }

    public static fromPublicKeyAndChainCode(publicKey: any, chainCode: any): Ed25519HDKey {
        let hdkey = new Ed25519HDKey(BITCOIN_VERSIONS)
        hdkey.publicKey = publicKey
        hdkey.chainCode = chainCode

        return hdkey
    }

    public static fromPrivateKeyAndChainCode(privateKey: BN, chainCode: any): Ed25519HDKey {
        let hdkey = new Ed25519HDKey(BITCOIN_VERSIONS)
        hdkey.privateKey = privateKey
        hdkey.chainCode = chainCode

        return hdkey
    }

    public static fromExtendedKey(base58key: string) {
        // => version(4) || depth(1) || fingerprint(4) || index(4) || chain(32) || key(33)
        // Mark: key(33) = 00 + priv(32)/pub(32)
        let versions = BITCOIN_VERSIONS
        let hdkey = new Ed25519HDKey(versions)

        let keyBuffer = bs58check.decode(base58key)
        let keyBufferHex = keyBuffer.toString('hex')

        let version = parseInt(keyBufferHex.substr(0, 4 * 2), 16)
        assert(version === versions.private || version === versions.public, 'Version mismatch: does not match private or public')

        hdkey.depth = parseInt(keyBufferHex.substr(4 * 2, 2), 16)

        hdkey.parentFingerprint = parseInt(keyBufferHex.substr(5 * 2, 4 * 2), 16)

        hdkey.index = parseInt(keyBufferHex.substr(9 * 2, 4 * 2), 16)

        hdkey.chainCode = new BN(keyBufferHex.substr(13 * 2, 32 * 2), 16)

        let prefix = parseInt(keyBufferHex.substr(45 * 2, 2), 16)
        assert(prefix === 0, "prefix should be zero")
        if(version === versions.private){ // private
            hdkey.privateKey = new BN(Hex.reverseHex(keyBufferHex.substr(46 * 2, 32 * 2)), 16) // cut off first 0x0 byte
        } else {
            hdkey.publicKey =  Ed25519.decodePoint(keyBufferHex.substr(46 * 2, 32 * 2))
        }
        return hdkey
    }

    private static serialize(hdkey: any, version: number, key) {
        // => version(4) || depth(1) || fingerprint(4) || index(4) || chain(32) || key(33)
        // Mark: key(33) = 00 + priv(32)/pub(32)
        let buffer = Buffer.allocUnsafe(LEN)

        buffer.writeUInt32BE(version, 0)
        buffer.writeUInt8(hdkey.depth, 4)

        let fingerprint = hdkey.depth ? hdkey.parentFingerprint : 0x00000000
        buffer.writeUInt32BE(fingerprint, 5)
        buffer.writeUInt32BE(hdkey.index, 9)

        let chainCodeBuffer = Buffer.from(Hex.pad64(hdkey.chainCode.toString(16)), "hex")
        chainCodeBuffer.copy(buffer, 13)

        Buffer.from(key, 'hex').copy(buffer, 45)
        return buffer
    }
}
