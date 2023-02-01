const assert = require('assert')
const bs58check = require('@rr/bs58check')
const BN = require('bn.js')
const CryptoJS = require("crypto-js")
const elliptic = require('elliptic')
const Ed25519 =new elliptic.eddsa('ed25519')
const utils = require("./common/utils")
const blakejs = require("blakejs")

const MASTER_SECRET = CryptoJS.enc.Utf8.parse('Ed25519 seed')
const HARDENED_OFFSET = 0x80000000
const LEN = 78

const ZERO = new BN('0', 16)
const POW2_256= new BN('1', 10).shln(256)

// Bitcoin hardcoded by default, can use package `coininfo` for others
//const BITCOIN_VERSIONS = {private: 0x0488ADE4, public: 0x0488B21E}
// For Ed25519
const BITCOIN_VERSIONS = {private: 0x03126f7c, public: 0x031273b7}

function Buffer2CryptoJSArray(buffer){
    const hexStr = buffer.toString('hex')
    return CryptoJS.enc.Hex.parse(utils.padToByte32(hexStr))
}

function HDKey (versions) {
    this.versions = versions || BITCOIN_VERSIONS
    this.depth = 0
    this.index = 0
    this._privateKeyL = null // BN
    this._privateKeyR = null // BN
    this._publicKey = null // elliptic point
    this.chainCode = null
    this._fingerprint = 0
    this.parentFingerprint = 0
}

Object.defineProperty(HDKey.prototype, 'fingerprint', { get: function () { return this._fingerprint } })
Object.defineProperty(HDKey.prototype, 'identifier', { get: function () { return this._identifier } })
Object.defineProperty(HDKey.prototype, 'pubKeyHash', { get: function () { return this.identifier } })

Object.defineProperty(HDKey.prototype, 'privateKeyL', {
    get: function () {
        return this._privateKeyL
    }
})

Object.defineProperty(HDKey.prototype, 'privateKeyR', {
    get: function () {
        return this._privateKeyR
    }
})

Object.defineProperty(HDKey.prototype, 'privateKey', {
    get: function () {
        return [this._privateKeyL, this._privateKeyR]
    },
    set: function (value) {
        this._privateKeyL = value[0]
        this._privateKeyR = value[1]

        // check
        let strL = this._privateKeyL.toString(16)
        let strR = this._privateKeyR.toString(16)
        assert(strL.length <= 64)
        assert(strR.length <= 64)

        this._publicKey = Ed25519.g.mul(this._privateKeyL)
        this._identifier = hash160(CryptoJS.enc.Hex.parse(this.publicKey.encodeCompressed('hex')))
        this._fingerprint = parseInt(CryptoJS.enc.Hex.stringify(this._identifier).substr(0, 4*2), 16)
    }
})

Object.defineProperty(HDKey.prototype, 'publicKey', {
    get: function () {
        return this._publicKey
    },
    set: function (value) {
        if(typeof value === 'string'){
            assert.equal(value.length, 33 * 2, 'Public key must be 33 bytes(compressed public key).')
            this._publicKey = Ed25519.curve.decodePoint(value, 'hex')
        }else {
            assert(Ed25519.curve.validate(value), 'Invalid public key')
            this._publicKey = value
        }

        this._identifier = hash160(CryptoJS.enc.Hex.parse(this.publicKey.encodeCompressed('hex')))
        this._fingerprint = parseInt(CryptoJS.enc.Hex.stringify(this._identifier).substr(0, 4*2), 16)
        this._privateKeyL = null
    }
})

Object.defineProperty(HDKey.prototype, 'privateExtendedKey', {
    get: function () {
        if (this._privateKeyL) {
            // with prefix
            let keyBuff = '00' + utils.BN2ByteStr(this._privateKeyL, 32)
            return bs58check.encode(serialize(this, this.versions.private, keyBuff))
        }
        else return null
    }
})

Object.defineProperty(HDKey.prototype, 'publicExtendedKey', {
    get: function () {
        return bs58check.encode(serialize(this, this.versions.public, this.publicKey.encodeCompressed('hex')))
    }
})

HDKey.prototype.derive = function (path) {
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
        let childIndex = parseInt(c, 10) // & (HARDENED_OFFSET - 1)
        assert(childIndex < HARDENED_OFFSET, 'Invalid index')
        if (hardened) childIndex += HARDENED_OFFSET

        hdkey = hdkey.deriveChild(childIndex)
    })

    return hdkey
}

HDKey.prototype.deriveChild = function (index) {
    let isHardened = index >= HARDENED_OFFSET

    let dataKey = ""
    let dataChain = ""
    if (isHardened) { // Hardened child
        assert(this.privateKey, 'Could not derive hardened child key')
        // data = 0x00 || ser256(kpar) || ser32(index)
        let part = utils.toHex(this._privateKeyL.toArray('le', 32)) +
                   utils.toHex(this._privateKeyR.toArray('le', 32)) +
                   utils.toHex(new BN(index).toArray('le', 4))
        dataKey   = '00' + part
        dataChain = '01' + part
    } else { // Normal child
        // data = serP(point(kpar)) || ser32(index)
        //      = serP(Kpar) || ser32(index)
        //data = this._publicKey.encodeCompressed('hex') + utils.padToByte4(index.toString(16))
        let part = utils.toHex(Ed25519.encodePoint(this._publicKey)) +
                   utils.toHex(new BN(index).toArray('le', 4))
        dataKey   = '02' + part
        dataChain = '03' + part
    }

    //let chainCodeWordArray = Buffer2CryptoJSArray(this.chainCode)
    let chainCodeWordArrayxxx = utils.toHex(this.chainCode.toArray('le', 32))
    let chainCodeWordArray = CryptoJS.enc.Hex.parse(chainCodeWordArrayxxx)
    let dataWordArray = CryptoJS.enc.Hex.parse(dataKey)
    let I = CryptoJS.enc.Hex.stringify(CryptoJS.HmacSHA512(dataWordArray, chainCodeWordArray))
    let IL = new BN(I.substr(0, 56), 16, 'le')
    IL = IL.muln(8)
    let IR = new BN(I.substr(64), 16, 'le')

    dataWordArray = CryptoJS.enc.Hex.parse(dataChain)
    let chainCode = new BN(CryptoJS.enc.Hex.stringify(CryptoJS.HmacSHA512(dataWordArray, chainCodeWordArray)).substr(64), 16, 'le')

    let hd = new HDKey(this.versions)

    // Private parent key -> private child key
    if (this._privateKeyL) {
        // ki = parse256(IL) + kpar (mod n)
        try {
            const _privateKeyL = this._privateKeyL.add(IL)//.umod(Ed25519.curve.n)
            const _privateKeyR = this._privateKeyR.add(IR).umod(POW2_256)
            hd.privateKey = [_privateKeyL, _privateKeyR]

            // throw if IL >= n || (privateKey + IL) === 0
            if(hd._privateKeyL.eqn(0)) throw "Invalid child private key!"
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
            hd._publicKey = _publicKey
        } catch (err) {
            // In case parse256(IL) >= n or Ki is the point at infinity, one should proceed with the next value for i
            return this.deriveChild(index + 1)
        }
    }

    hd.chainCode = chainCode
    hd.depth = this.depth + 1
    hd.parentFingerprint = this.fingerprint// .readUInt32BE(0)
    hd.index = index

    return hd
}


HDKey.prototype.publicDerive = function (path) {
    let delta = ZERO
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
        let childIndex = parseInt(c, 10) // & (HARDENED_OFFSET - 1)
        assert(childIndex < HARDENED_OFFSET, 'Invalid index')
        if (hardened) childIndex += HARDENED_OFFSET

        const [_hdkey, _delta] = hdkey.publicDeriveChild(childIndex)
        delta = delta.add(_delta).umod(Ed25519.curve.n)
        hdkey = _hdkey
    })

    return [hdkey, delta]
}

HDKey.prototype.publicDeriveChild = function (index) {
    let isHardened = index >= HARDENED_OFFSET

    // data = serP(point(kpar)) || ser32(index)
    //      = serP(Kpar) || ser32(index)
    //data = this._publicKey.encodeCompressed('hex') + utils.padToByte4(index.toString(16))
    let part = utils.toHex(Ed25519.encodePoint(this._publicKey)) +
        utils.toHex(new BN(index).toArray('le', 4))
    let dataKey   = '02' + part
    let dataChain = '03' + part

    let chainCodeWordArrayxxx = utils.toHex(this.chainCode.toArray('le', 32))
    let chainCodeWordArray = CryptoJS.enc.Hex.parse(chainCodeWordArrayxxx)
    let dataWordArray = CryptoJS.enc.Hex.parse(dataKey)
    let I = CryptoJS.enc.Hex.stringify(CryptoJS.HmacSHA512(dataWordArray, chainCodeWordArray))
    let IL = new BN(I.substr(0, 56), 16, 'le')
    IL = IL.muln(8)
    let IR = new BN(I.substr(64), 16, 'le')

    dataWordArray = CryptoJS.enc.Hex.parse(dataChain)
    let chainCode = new BN(CryptoJS.enc.Hex.stringify(CryptoJS.HmacSHA512(dataWordArray, chainCodeWordArray)).substr(64), 16, 'le')

    let hd = new HDKey(this.versions)

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

    hd.chainCode = chainCode
    hd.depth = this.depth + 1
    hd.parentFingerprint = this.fingerprint// .readUInt32BE(0)
    hd.index = index

    let delta = IL
    return [hd, delta]
}


HDKey.prototype.sign = function (hash) {
    return "Not implemented!"
}

HDKey.prototype.verify = function (hash, signature) {
    return "Not implemented!"
}

HDKey.fromMasterSeed = function (seedHex, versions) {
    //let formatSeedHex = utils.padToByteEven(seedHex)
    //let seedWordArray = CryptoJS.enc.Hex.parse(formatSeedHex)
    //let I = CryptoJS.enc.Hex.stringify(CryptoJS.SHA512(seedWordArray))

    let formatSeedHex = utils.padToByteEven(seedHex)
    let seedWordArray = utils.toArray(formatSeedHex, 'hex')
    seedWordArray = new Uint8Array(seedWordArray)
    let IHex = utils.encode(blakejs.blake2b(seedWordArray), 'hex')
    let IL = new BN(IHex.substr(0, 64), 16, 'le')
    //IL = IL.umod(Ed25519.curve.n)
    IL.setn(0, false)
    IL.setn(1, false)
    IL.setn(2, false)
    IL.setn(255, false)
    IL.setn(254, true)
    let IR = new BN(IHex.substr(64), 16, 'le')

    let seedWordArrayWithPrefix = CryptoJS.enc.Hex.parse("01" + formatSeedHex)
    let cHex = CryptoJS.enc.Hex.stringify(CryptoJS.SHA256(seedWordArrayWithPrefix))
    let chainCode = new BN(cHex, 16, 'le')

    let hdkey = new HDKey(versions)
    hdkey.privateKey = [IL, IR]
    hdkey.chainCode = chainCode

    return hdkey
}

HDKey.fromPublicKeyAndChainCode = function (publicKey, chainCode) {
    let hdkey = new HDKey(BITCOIN_VERSIONS)
    hdkey.publicKey = publicKey
    hdkey.chainCode = chainCode

    return hdkey
}

HDKey.fromPrivateKeyAndChainCode = function (privateKey, chainCode) {
    let hdkey = new HDKey(BITCOIN_VERSIONS)
    hdkey.privateKey = privateKey
    hdkey.chainCode = chainCode

    return hdkey
}

HDKey.fromExtendedKey = function (base58key, versions) {
    // => version(4) || depth(1) || fingerprint(4) || index(4) || chain(32) || key(33)
    versions = versions || BITCOIN_VERSIONS
    let hdkey = new HDKey(versions)

    let keyBuffer = bs58check.decode(base58key)
    let keyBufferHex = keyBuffer.toString('hex')

    //let version = keyBuffer.readUInt32BE(0)
    let version = parseInt(keyBufferHex.substr(0, 4 * 2), 16)
    assert(version === versions.private || version === versions.public, 'Version mismatch: does not match private or public')

    hdkey.depth = parseInt(keyBufferHex.substr(4 * 2, 2), 16)

    hdkey.parentFingerprint = parseInt(keyBufferHex.substr(5 * 2, 4 * 2), 16)

    hdkey.index = parseInt(keyBufferHex.substr(9 * 2, 4 * 2), 16)

    hdkey.chainCode = new BN(keyBufferHex.substr(13 * 2, 32 * 2), 16)

    hdkey.prefix = parseInt(keyBufferHex.substr(45 * 2, 2), 16)
    if(hdkey.prefix === 0){ // private
        assert(version === versions.private, 'Version mismatch: version does not match private')
        hdkey.privateKey = [new BN(keyBufferHex.substr(46 * 2, 32 * 2), 16), ZERO] // cut off first 0x0 byte
    } else {
        assert(version === versions.public, 'Version mismatch: version does not match public')
        hdkey.publicKey =  Ed25519.curve.decodePoint(keyBufferHex.substr(45 * 2, 33 * 2), 'hex')
    }
    return hdkey
}

function serialize (hdkey, version, key) {
    // => version(4) || depth(1) || fingerprint(4) || index(4) || chain(32) || key(33)
    let buffer = Buffer.allocUnsafe(LEN)

    buffer.writeUInt32BE(version, 0)
    buffer.writeUInt8(hdkey.depth, 4)

    let fingerprint = hdkey.depth ? hdkey.parentFingerprint : 0x00000000
    buffer.writeUInt32BE(fingerprint, 5)
    buffer.writeUInt32BE(hdkey.index, 9)

    let chainCodeBuffer = Buffer.from(utils.BN2ByteStr(hdkey.chainCode, 32), "hex")
    chainCodeBuffer.copy(buffer, 13)

    Buffer.from(key, 'hex').copy(buffer, 45)
    return buffer
}

function hash160 (wordArray) {
    let sha = CryptoJS.SHA256(wordArray)
    return CryptoJS.RIPEMD160(sha)
}

HDKey.HARDENED_OFFSET = HARDENED_OFFSET
module.exports = HDKey