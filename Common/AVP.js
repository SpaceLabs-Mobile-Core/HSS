import { AVP_CODES, S6A_AVP_CODES, VENDOR_IDS } from "./Dictionary.js";

export function createStringAVP(code, value, flags = 0x40) {
    return createAVP({
        code,
        flags,
        data: Buffer.from(value, 'utf8')
    });
}

export function createIPv4AVP(code, ip, flags = 0x40) {
    const parts = ip.split('.').map(Number);

    if (parts.length !== 4 || parts.some(part => part < 0 || part > 255)) {
        throw new Error(`Invalid IPv4 address: ${ip}`);
    }

    const data = Buffer.alloc(6);
    data.writeUInt16BE(1, 0);
    
    for (let i = 0; i < 4; i++) {
        data.writeUInt8(parts[i], 2 + i);
    }

    return createAVP({
        code,
        flags,
        data
    });
}

export function createUInt32AVP(
    code,
    value,
    flags = 0x40,
    vendorId = null
) {
    const data = Buffer.alloc(4);

    data.writeUInt32BE(
        value,
        0
    );

    return createAVP({
        code,
        flags,
        data,
        vendorId
    });
}

export function parseAVPs(buffer, { decodeGrouped = false } = {}) {
    const avps = [];
    let offset = 0;

    while (offset < buffer.length) {
        if (buffer.length - offset < 8) {
            throw new Error('Incomplete AVP header');
        }

        const code = buffer.readUInt32BE(offset);
        const flags = buffer.readUInt8(offset + 4);
        const length = buffer.readUIntBE(offset + 5, 3);

        const hasVendorId = (flags & 0x80) !== 0;
        const headerLength = hasVendorId ? 12 : 8;

        if (length < headerLength) {
            throw new Error(`Invalid AVP length: ${length}`);
        }

        if (offset + length > buffer.length) {
            throw new Error('Incomplete AVP data');
        }

        let vendorId = null;

        if (hasVendorId) {
            vendorId = buffer.readUInt32BE(offset + 8);
        }

        const dataStart = offset + headerLength;
        const dataEnd = offset + length;

        const data = buffer.subarray(
            dataStart,
            dataEnd
        );

        const avp = {
            code,
            flags,
            length,
            vendorId,
            data
        };

        if (decodeGrouped && vendorId === VENDOR_IDS.THREE_GPP && (code === AVP_CODES.AUTHENTICATION_INFO || code === S6A_AVP_CODES.E_UTRAN_VECTOR)) {
            avp.children = parseAVPs(data, { decodeGrouped: true });
        }

        avps.push(avp);
        const padding = (4 - (length % 4)) % 4;
        offset += length + padding;
    }

    return avps;
}

export function decodeStringAVP(avp) {
    return avp.data.toString('utf8');
}

export function decodeUInt32AVP(avp) {
    if (avp.data.length !== 4) {
        throw new Error(`Invalid UInt32 AVP length: ${avp.data.length}`);
    }

    return avp.data.readUInt32BE(0);
}

export function decodeIPv4AVP(avp) {
    if (avp.data.length !== 6) {
        throw new Error(
            `Invalid IPv4 AVP length: ${avp.data.length}`
        );
    }

    const addressFamily = avp.data.readUInt16BE(0);

    if (addressFamily !== 1) {
        throw new Error(
            `Unsupported address family: ${addressFamily}`
        );
    }

    return [
        avp.data[2],
        avp.data[3],
        avp.data[4],
        avp.data[5]
    ].join('.');
}

export function decodeAVP(avp) {
    switch (avp.code) {
        case AVP_CODES.ORIGIN_HOST:
        case AVP_CODES.ORIGIN_REALM:
        case AVP_CODES.PRODUCT_NAME:
            return decodeStringAVP(avp);

        case AVP_CODES.AUTH_APPLICATION_ID:
        case AVP_CODES.VENDOR_ID:
        case AVP_CODES.RESULT_CODE:
        case AVP_CODES.RAT_TYPE:
        case AVP_CODES.ULR_FLAGS:
            return decodeUInt32AVP(avp);

        case AVP_CODES.HOST_IP_ADDRESS:
            return decodeIPv4AVP(avp);

        case AVP_CODES.USER_NAME:
            return decodeStringAVP(avp);

        case AVP_CODES.VISITED_PLMN_ID:
            return avp.data;

        default:
            return avp.data;
    }
}

export function createGroupedAVP(
    code,
    avps,
    flags = 0x40,
    vendorId = null
) {

    const data = Buffer.concat(avps);

    return createAVP({
        code,
        flags,
        data,
        vendorId
    });
}

export function createOctetStringAVP(code, data, flags = 0x40, vendorId = null) {
    if (!Buffer.isBuffer(data)) {
        throw new Error(
            'OctetString AVP data must be a Buffer'
        );
    }

    return createAVP({
        code,
        flags,
        data,
        vendorId
    });
}

export function createAVP({
    code,
    flags = 0,
    data,
    vendorId = null
}) {
    const hasVendorId = vendorId !== null;
    const headerLength = hasVendorId ? 12 : 8;
    const avpLength = headerLength + data.length;
    const padding = (4 - (avpLength % 4)) % 4;
    const avp = Buffer.alloc(avpLength + padding);
    avp.writeUInt32BE(code, 0);

    if (hasVendorId) {
        flags |= 0x80;
    }

    avp.writeUInt8(flags, 4);
    avp.writeUIntBE(avpLength, 5, 3);
    let offset = 8;

    if (hasVendorId) {
        avp.writeUInt32BE(vendorId, offset);
        offset += 4;
    }

    data.copy(avp, offset);
    return avp;
}