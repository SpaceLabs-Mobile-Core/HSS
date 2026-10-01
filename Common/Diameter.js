import { parseAVPs } from "./AVP.js";

export function createDiameterMessage({
    flags,
    commandCode,
    applicationId,
    hopByHopId = null,
    endToEndId = null,
    avps = Buffer.alloc(0)
}) {
    const isRequestMessage = (flags & 0x80) !== 0;

    if (isRequestMessage) {
        if (hopByHopId === null) {
            hopByHopId = generateDiameterId();
        }

        if (endToEndId === null) {
            endToEndId = generateDiameterId();
        }
    }

    if (hopByHopId === null || endToEndId === null) {
        throw new Error(
            'Hop-by-Hop ID and End-to-End ID are required for Diameter Answers'
        );
    }

    const length = 20 + avps.length;
    const buffer = Buffer.alloc(length);
    buffer.writeUInt8(1, 0);
    buffer.writeUIntBE(length, 1, 3);
    buffer.writeUInt8(flags, 4);
    buffer.writeUIntBE(commandCode, 5, 3);
    buffer.writeUInt32BE(applicationId, 8);
    buffer.writeUInt32BE(hopByHopId >>> 0, 12);
    buffer.writeUInt32BE(endToEndId >>> 0, 16);

    avps.copy(buffer, 20);
    return buffer;
}

export function parseDiameterMessage(buffer) {
    if (buffer.length < 20) {
        throw new Error('Diameter message must have at least 20 bytes');
    }

    const version = buffer.readUInt8(0);
    const length = buffer.readUIntBE(1, 3);
    const flags = buffer.readUInt8(4);
    const commandCode = buffer.readUIntBE(5, 3);
    const applicationId = buffer.readUInt32BE(8);
    const hopByHopId = buffer.readUInt32BE(12);
    const endToEndId = buffer.readUInt32BE(16);

    if (buffer.length < length) {
        throw new Error(`Incomplete Diameter message: expected ${length} bytes, got ${buffer.length}`);
    }

    const avpBuffer = buffer.subarray(20, length);
    const avps = parseAVPs(avpBuffer, { decodeGrouped: true });

    return {
        version,
        length,
        flags,
        commandCode,
        applicationId,
        hopByHopId,
        endToEndId,
        avps
    };
}

function generateDiameterId() {
    return Math.floor(Math.random() * 0x100000000);
}