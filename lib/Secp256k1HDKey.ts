import * as bs58check from 'bs58check'
import * as BN from 'bn.js'
import * as cryptoJS from "crypto-js"
import * as elliptic from 'elliptic'
const Secp256k1 = elliptic.ec('secp256k1')
import {Hex, CryptoJSBytes} from "@safeheron/crypto-utils"
import * as assert from "assert";

const MASTER_SECRET = cryptoJS.enc.Utf8.parse('Bitcoin seed')
const HARDENED_OFFSET = 0x80000000
const LEN = 78

const ZERO = new BN('0', 16)

// Bitcoin hardcoded by default, can use package `coininfo` for others
const BITCOIN_VERSIONS = {private: 0x0488ADE4, public: 0x0488B21E}

function Buffer2CryptoJSArray(buffer){
    const hexStr = buffer.toString('hex')
    return Hex.toCryptoJSBytes(Hex.pad64(hexStr))
}

export class Secp256k1HDKey {
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
            if (value.length !== 64) throw 'Private key must be 32 bytes.'
            var valueNum = new BN(value, 16)
            if (valueNum.gt(Secp256k1.n) || valueNum.eq(0)) throw 'Invalid private key'
            this._privateKey = valueNum
        } else {
            if (value.gt(Secp256k1.n) || value.eq(0)) throw 'Invalid private key'
            this._privateKey = value
        }

        this._publicKey = Secp256k1.g.mul(this._privateKey)
        this._identifier = Secp256k1HDKey.hash160(cryptoJS.enc.Hex.parse(this._publicKey.encodeCompressed('hex')))
        this._fingerprint = parseInt(cryptoJS.enc.Hex.stringify(this._identifier).substr(0, 4 * 2), 16)
    }


    public get publicKey(): any{
        return this._publicKey
    }

    public set publicKey(value: any) {
        if(typeof value === 'string'){
            if(value.length !== 33 * 2) throw 'Public key must be 33 bytes(compressed public key).'
            this._publicKey = Secp256k1.curve.decodePoint(value, 'hex')
        }else {
            if(!Secp256k1.curve.validate(value)) throw 'Invalid public key'
            this._publicKey = value
        }

        this._identifier = Secp256k1HDKey.hash160(cryptoJS.enc.Hex.parse(this._publicKey.encodeCompressed('hex')))
        this._fingerprint = parseInt(cryptoJS.enc.Hex.stringify(this._identifier).substr(0, 4*2), 16)
        this._privateKey = null
    }

    public get xprv(): string{
        if (this._privateKey) {
            // with prefix
            let keyBuff = '00' + Hex.pad64(this._privateKey.toString(16))
            return bs58check.encode(Secp256k1HDKey.serialize(this, this.versions.private, keyBuff))
        }
        else return null
    }

    public get xpub(): string{
        return bs58check.encode(Secp256k1HDKey.serialize(this, this.versions.public, this._publicKey.encodeCompressed('hex')))
    }

    public derive(path: string): Secp256k1HDKey{
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
                assert((childIndex < HARDENED_OFFSET), 'Invalid index')
                if (hardened) childIndex += HARDENED_OFFSET

                // @ts-ignore
                hdkey = hdkey.deriveChild(childIndex)
            } else {
                throw "Invalid index";
            }
        })

        return hdkey
    }

    public deriveChild(index: number): Secp256k1HDKey {
        let isHardened = index >= HARDENED_OFFSET

        let data = ""
        if (isHardened) { // Hardened child
            assert(this.privateKey, 'Could not derive hardened child key')
            // data = 0x00 || ser256(kpar) || ser32(index)
            data = '00' + Hex.pad64(this._privateKey.toString(16)) + Hex.pad8(index.toString(16))
        } else { // Normal child
            // data = serP(point(kpar)) || ser32(index)
            //      = serP(Kpar) || ser32(index)
            data = this._publicKey.encodeCompressed('hex') + Hex.pad8(index.toString(16))
        }

        let chainCodeWordArray = Buffer2CryptoJSArray(this.chainCode)
        let dataWordArray = cryptoJS.enc.Hex.parse(data)
        let I = cryptoJS.enc.Hex.stringify(cryptoJS.HmacSHA512(dataWordArray, chainCodeWordArray))
        let IL = new BN(I.substr(0, 64), 16)
        let IR = new BN(I.substr(64), 16)

        let hd = new Secp256k1HDKey(this.versions)

        // Private parent key -> private child key
        if (this.privateKey) {
            // ki = parse256(IL) + kpar (mod n)
            try {
                let _privateKey = this._privateKey.add(IL).umod(Secp256k1.n)
                // throw if IL >= n || (privateKey + IL) === 0
                if(IL.gt(Secp256k1.n) || _privateKey.eqn(0)) throw "Invalid child private key!"
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
                let _publicKey = this._publicKey.add(Secp256k1.g.mul(IL))
                // throw if IL >= n || (g**IL + publicKey) is infinity
                if(IL.gt(Secp256k1.n) || _publicKey.isInfinity()) throw "Invalid child public key!"
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


    public publicDerive(path: string): [Secp256k1HDKey, BN] {
        let delta = ZERO
        if (path === 'm' || path === 'M' || path === "m'" || path === "M'") {
            return [this, new BN(0)]
        }
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

        //   let hardened = (c.length > 1) && (c[c.length - 1] === "'")
            if (/^\d+$/.test(c)) {
                let childIndex = parseInt(c, 10) // & (HARDENED_OFFSET - 1)
                assert(childIndex < HARDENED_OFFSET, 'Invalid index')
            //    if (hardened) childIndex += HARDENED_OFFSET

                const [_hdkey, _delta] = hdkey.publicDeriveChild(childIndex)
                delta = delta.add(_delta).umod(Secp256k1.n)
                // @ts-ignore
                hdkey = _hdkey
            } else {
                throw "Invalid index"
            }
        })
        return [hdkey, delta]
    }

    public publicDeriveChild(index: number): [Secp256k1HDKey, BN]{
        //let isHardened = index >= HARDENED_OFFSET

        // Normal child
        // data = serP(point(kpar)) || ser32(index)
        //      = serP(Kpar) || ser32(index)
        let data = this._publicKey.encodeCompressed('hex') + Hex.pad8(index.toString(16))

        let chainCodeWordArray = Buffer2CryptoJSArray(this.chainCode)
        let dataWordArray = cryptoJS.enc.Hex.parse(data)
        let I = cryptoJS.enc.Hex.stringify(cryptoJS.HmacSHA512(dataWordArray, chainCodeWordArray))
        let IL = new BN(I.substr(0, 64), 16)
        let IR = new BN(I.substr(64), 16)

        let hd = new Secp256k1HDKey(this.versions)

        // Public parent key -> public child key
        // Ki = point(parse256(IL)) + Kpar
        //    = G*IL + Kpar
        try {
            let _publicKey = this._publicKey.add(Secp256k1.g.mul(IL))
            // throw if IL >= n || (g**IL + publicKey) is infinity
            if(IL.gt(Secp256k1.n) || _publicKey.isInfinity()) throw "Invalid child public key!"
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

    public sign(hash: number[]): number[]{
        throw "Not implemented!"
    }

    public verify(hash: number[], signature: []): boolean{
        throw "Not implemented!"
    }

    public static fromMasterSeed(seedWordArray: CryptoJSBytes): Secp256k1HDKey {
        let I = cryptoJS.enc.Hex.stringify(cryptoJS.HmacSHA512(seedWordArray, MASTER_SECRET))
        let IL = new BN(I.substr(0, 64), 16)
        let IR = new BN(I.substr(64), 16)

        if ((IL.gt(Secp256k1.n)) || (IL.eqn(0))) {
            throw "Invalid Master Key!"
        }

        let hdkey = new Secp256k1HDKey(BITCOIN_VERSIONS)
        hdkey.privateKey = IL
        hdkey.chainCode = IR

        return hdkey
    }

    public static fromMasterSeedHex(seedHex: string): Secp256k1HDKey {
        return Secp256k1HDKey.fromMasterSeed(cryptoJS.enc.Hex.parse(seedHex))
    }

    public static fromPublicKeyAndChainCode(publicKey: any, chainCode: any): Secp256k1HDKey {
        let hdkey = new Secp256k1HDKey(BITCOIN_VERSIONS)
        hdkey.publicKey = publicKey
        hdkey.chainCode = chainCode

        return hdkey
    }

    public static fromPrivateKeyAndChainCode(privateKey: BN, chainCode: any): Secp256k1HDKey{
        let hdkey = new Secp256k1HDKey(BITCOIN_VERSIONS)
        hdkey.privateKey = privateKey
        hdkey.chainCode = chainCode

        return hdkey
    }

    public static fromExtendedKey(base58key: string) {
        // => version(4) || depth(1) || fingerprint(4) || index(4) || chain(32) || key(33)
        let versions = BITCOIN_VERSIONS
        let hdkey = new Secp256k1HDKey(versions)

        let keyBuffer = bs58check.decode(base58key)
        let keyBufferHex = keyBuffer.toString('hex')

        let version = parseInt(keyBufferHex.substr(0, 4 * 2), 16)
        assert(version === versions.private || version === versions.public, 'Version mismatch: does not match private or public')

        hdkey.depth = parseInt(keyBufferHex.substr(4 * 2, 2), 16)

        hdkey.parentFingerprint = parseInt(keyBufferHex.substr(5 * 2, 4 * 2), 16)

        hdkey.index = parseInt(keyBufferHex.substr(9 * 2, 4 * 2), 16)

        hdkey.chainCode = new BN(keyBufferHex.substr(13 * 2, 32 * 2), 16)

        let prefix = parseInt(keyBufferHex.substr(45 * 2, 2), 16)
        if(prefix === 0){ // private
            assert(version === versions.private, 'Version mismatch: version does not match private')
            hdkey.privateKey = new BN(keyBufferHex.substr(46 * 2, 32 * 2), 16) // cut off first 0x0 byte
        } else {
            assert(version === versions.public, 'Version mismatch: version does not match public')
            hdkey.publicKey =  Secp256k1.curve.decodePoint(keyBufferHex.substr(45 * 2, 33 * 2), 'hex')
        }
        return hdkey
    }

    private static serialize (hdkey: any, version: number, key) {
        // => version(4) || depth(1) || fingerprint(4) || index(4) || chain(32) || key(33)
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

    private static hash160 (wordArray: CryptoJSBytes) {
        let sha = cryptoJS.SHA256(wordArray)
        return cryptoJS.RIPEMD160(sha)
    }
}