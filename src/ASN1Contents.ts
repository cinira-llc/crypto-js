import {freeze} from 'immer';
import * as _ from "lodash";

/**
 * Parse the raw contents of an ASN.1 buffer into separate arrays if numbers, OIDs, and byte strings. Borrows (very
 * heavily) from https://commandlinefanatic.com/cgi-bin/showarticle.cgi?article=art050
 *
 * @param buffer the ASN.1 buffer to parse.
 * @param numbers the output array to received parsed numbers.
 * @param oids the output array to receive parsed OIDs.
 * @param strings the output array to receive parsed byte strings.
 */
function parseASN1(buffer: Buffer, numbers: number[], oids: Buffer[], strings: Buffer[]) {
    /* tslint:disable:no-bitwise */
    for (let pos = 0; pos < buffer.length;) {
        const tag = buffer[pos++];
        let length = buffer[pos++];
        if (0 !== (length & 0x80)) {
            let extLen = 0;
            for (let i = 0; i < (length & 0x7f); i += 1) {
                extLen = (extLen << 8) | (buffer[pos++] & 0xff);
            }
            length = extLen;
        }
        const contents = buffer.subarray(pos, pos + length);
        pos += length;
        if (0x30 === tag) {
            parseASN1(contents, numbers, oids, strings);
        } else if (0x03 === tag || 0x04 === tag) {
            strings.push(contents);
        } else if (0x06 === tag) {
            oids.push(contents);
        } else if (0x02 === tag) {
            numbers.push(_.reduce(contents, (acc, next) => (acc << 8) | (next & 0xff), 0));
        } else if (0x05 !== tag) {
            throw Error(`Unexpected ASN.1 tag ${tag}.`);
        }
    }
    /* tslint:enable:no-bitwise */
}

/**
 * [ASN1Contents] holds the (naively) parsed contents of an ASN.1 buffer, separated into numbers (ints), OIDs, and byte
 * strings by index within the file.
 */
export class ASN1Contents {
    private constructor(
        public readonly numbers: number[],
        public readonly oids: Buffer[],
        public readonly strings: Buffer[],
    ) {
    }

    /**
     * Parse ASN.1 data from an existing buffer.
     *
     * @param buffer the ASN.1 buffer to parse.
     */
    static fromBuffer(buffer: Buffer) {
        const numbers: number[] = [];
        const oids: Buffer[] = [];
        const strings: Buffer[] = [];
        parseASN1(buffer, numbers, oids, strings);
        return freeze(new ASN1Contents(numbers, oids, strings));
    }
}
