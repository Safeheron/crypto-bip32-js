import * as BN from 'bn.js'
import * as cryptoJS from "crypto-js"
import * as elliptic from 'elliptic'
import * as hash from 'hash.js'

// Create an EC curve with stark curve parameters.
export const STARK = new elliptic.ec(
    // ref: https://github.com/starkware-libs/starkware-crypto-utils/blob/dev/src/js/signature.ts
    new elliptic.curves.PresetCurve({
        type: 'short',
        prime: null,
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-ignore
        p: '08000000 00000011 00000000 00000000 00000000 00000000 00000000 00000001',
        a: '00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000001',
        b: '06f21413 efbe40de 150e596d 72f7a8c5 609ad26c 15c915c1 f4cdfcb9 9cee9e89',
        n: '08000000 00000010 ffffffff ffffffff b781126d cae7b232 1e66a241 adc64d2f',
        hash: hash.sha256,
        gRed: false,
        g:  [
            "01ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca",
            "005668060aa49730b7be4801df46ec62de53ecd11abe43a32873000c36e8dc1f"
        ],
    })
);