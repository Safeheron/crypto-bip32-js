import * as BN from 'bn.js'
import {STARK} from "..";
import {Hex} from "@safeheron/crypto-utils";
import { strict as assert } from 'assert';

describe('Elliptic Curve Encryption', function () {
    it('ConstantTest', async function () {
        // ref: https://docs.starkware.co/starkex/crypto/stark-curve.html
        const alpha = new BN('1')
        const beta = new BN('3141592653589793238462643383279502884197169399375105820974944592307816406665')
        const p = new BN('3618502788666131213697322783095070105623107215331596699973092056135872020481')
        const gX = new BN('874739451078007766457464989774322083649278607533249481151382481072868806602')
        const gY = new BN('152666792071518830868575557812948353041420400780739481342941381225525861407')

        assert.ok(STARK.curve.a.fromRed().eq(alpha), 'STARK.curve.a.fromRed().eq(alpha)')
        assert.ok(STARK.curve.b.fromRed().eq(beta), 'STARK.curve.b.fromRed().eq(beta)')
        assert.ok(STARK.curve.p.eq(p), 'STARK.p.eq(p)')
        assert.ok(STARK.g.getX().eq(gX), 'STARK.g.getX().eq(gX)')
        assert.ok(STARK.g.getY().eq(gY), 'STARK.g.getY().eq(gY)')
    });

    it('GetPublicKeyFromPrivateKey', async function () {
        // ref: https://github.com/starkware-libs/starkex-for-spot-trading/blob/master/src/starkware/crypto/starkware/crypto/signature/test/config/signature_test_data.json
        let keyPairs = [
            {
                privateKeyHex: "3c1e9550e66958296d11b60f8e8e7a7ad990d07fa65d5f7652c4a6c87d4e3cc",
                publicKeyXHex: "077a3b314db07c45076d11f62b6f9e748a39790441823307743cf00d6597ea43"
            },
            {
                privateKeyHex: "4c1e9550e66958296d11b60f8e8e7a7ad990d07fa65d5f7652c4a6c87d4e3cc",
                publicKeyXHex: "03d8a9687c613b2be32b55c5c0460e012b592e2fbbb4fc281fb87b0d8c441b3e"
            },
            {
                privateKeyHex: "7cc2767a160d4ea112b436dc6f79024db70b26b11ed7aa2cb6d7eef19ace703",
                publicKeyXHex: "059a543d42bcc9475917247fa7f136298bb385a6388c3df7309955fcb39b8dd4"
            },
            {
                privateKeyHex: "7cc2767a160d4ea112b436dc6f79024db70b26b11ed7aa2cb6d7eef19ace703",
                publicKeyXHex: "059a543d42bcc9475917247fa7f136298bb385a6388c3df7309955fcb39b8dd4"
            },
        ];
        for(let pair of keyPairs){
            let privateKey = new BN(pair.privateKeyHex, 16)
            let publicKey = STARK.g.mul(privateKey);
            let pubX = publicKey.getX();
            let expectedPubX = new BN(pair.publicKeyXHex, 16)
            assert.ok(pubX.eq(expectedPubX), "pubX.eq(expectedPubX)")
        }
    });

    it('Mul_1', async function () {
        let one = new BN(1)
        let ten = new BN(10)
        let oneHundred = new BN(100)

        let p1 = STARK.g.mul(one);
        let p10 = STARK.g.mul(ten);
        let p100 = STARK.g.mul(oneHundred);
        let p100Prime = p10.mul(ten)
        let p100DoublePrime = p1.mul(ten).mul(ten)

        assert.ok( p100.eq(p100Prime), 'p100.eq(p100Prime)')
        assert.ok( p100.eq(p100DoublePrime), 'p100.eq(p100DoublePrime)')
    });

    it('Mul_2', async function () {
        let one = new BN(1)
        let nine = new BN(9)
        let eightOne = new BN(81)

        let p1 = STARK.g.mul(one);
        let p9 = STARK.g.mul(nine);
        let p81 = STARK.g.mul(eightOne);
        let p81Prime = p9.mul(nine)
        let p81DoublePrime = p1.mul(nine).mul(nine)

        assert.ok( p81.eq(p81Prime), 'p81.eq(p81Prime)')
        assert.ok( p81.eq(p81DoublePrime), 'p81.eq(p81DoublePrime)')
    });

    it('Add_1', async function () {
        let one = new BN(1)
        let nine = new BN(9)
        let eightOne = new BN(81)

        let p1 = STARK.g.mul(one);
        let p9 = STARK.g.mul(nine);
        let p81 = STARK.g.mul(eightOne);

        assert.ok( p1.add(p1).add(p1).add(p1).add(p1).add(p1).add(p1).add(p1).add(p1).eq(p9), 'p1.add(p1).add(p1).add(p1).add(p1).add(p1).add(p1).add(p1).add(p1).eq(p9)')
        assert.ok( p9.add(p9).add(p9).add(p9).add(p9).add(p9).add(p9).add(p9).add(p9).eq(p81), 'p9.add(p9).add(p9).add(p9).add(p9).add(p9).add(p9).add(p9).add(p9).eq(p81)')
    });
})
