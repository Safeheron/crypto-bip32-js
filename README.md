# crypto-bip32-js
# Installation

```shell
npm install @safeheron/crypto-bip32
```

# Import Library

```javascript
import {Secp256k1HDKey, Ed25519HDKey} from "@safeheron/crypto-bip32";
```

# Examples

- Bip32-Ed25519
 
```javascript
let hdkey = Ed25519HDKey.fromMasterSeedHex("0102030405060708090A0B0C0D0E0F10")
console.log('xprv : ', hdkey.xprv)
// => 'eprv423G5rKnJnGfkFkLNqjCetZ2AQdKMX1zM5TwmcnG3tKbuQzjjiu668ZC4zRtC4rXtQuz1e99cHr94DJ1augEmmXAbcCA1cVxkRgNtasdc1c'
console.log('xpub:  ', hdkey.xpub)
// => 'epub8YjJEGN2T9xLdin8GVPo4JD8jS9FWrCtvP4j48pZUA7zjuFWN7igGdB4F39s7umSx7CoiLF13yzPL8sUJWL14sPkVMdY9VHQjZVeVQSjWPZ')

let childHdKey = rootHDKey.derive('m/44/60/0')
console.log('childxprv : ', childHdKey.xprv)
// => 'eprv48jMzZSh71Sx5s2eDB5nGq8bEteV8xskhQZKsnxqBQu579KZW7wuCQ36urdzveVUA1ZRLkgNWve4YgRhY1yjq8PQpLaFyp2UMxooAHUmpJm'
console.log('child.xpub:  ', childHdKey.xpub)
// => 'epub8fRQ8yUwFP8cyL4S6pkNgEnhovARJJ4fGiA7AK18bghTwdaL8WmVNtey5uWHTYN8V63YFCD8L1xW9YCoKd6vwd7jtzLnBfeGqJ4De4Fe9wB')

```

- Bip32-Secp256k1

```javascript
let hdkey = Secp256k1HDKey.fromMasterSeedHex("000102030405060708090a0b0c0d0e0f")
console.log('xprv : ', hdkey.xprv)
// => 'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi'
console.log('xpub:  ', hdkey.xpub)
// => 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8')

let childHdKey = rootHDKey.derive("m/0'/1/2'/2")
console.log('childxprv : ', childHdKey.xprv)
// => 'xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334'
console.log('child.xpub:  ', childHdKey.xpub)
// => 'xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV')

```
