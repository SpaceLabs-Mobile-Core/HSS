import crypto from 'crypto';

const C2 = Buffer.from(
    '00000000000000000000000000000001',
    'hex'
);

const C3 = Buffer.from(
    '00000000000000000000000000000002',
    'hex'
);

const C4 = Buffer.from(
    '00000000000000000000000000000004',
    'hex'
);

const C5 = Buffer.from(
    '00000000000000000000000000000008',
    'hex'
);

function aes128(key, data) {
    const cipher = crypto.createCipheriv(
        'aes-128-ecb',
        key,
        null
    );

    cipher.setAutoPadding(false);

    return Buffer.concat([
        cipher.update(data),
        cipher.final()
    ]);
}

function xor(a, b) {
    const result = Buffer.alloc(a.length);

    for (let i = 0; i < a.length; i++) {
        result[i] = a[i] ^ b[i];
    }

    return result;
}

function rotateLeft(buffer, bits) {
    const result = Buffer.alloc(16);
    const bytes = Math.floor(bits / 8);

    for (let i = 0; i < 16; i++) {
        result[i] = buffer[(i + bytes) % 16];
    }

    return result;
}

function getTemp(ki, opc, rand) {
    return aes128(
        ki,
        xor(rand, opc)
    );
}

function computeF2345({
    ki,
    opc,
    temp,
    rotation,
    constant
}) {
    let input = xor(
        temp,
        opc
    );

    input = rotateLeft(
        input,
        rotation
    );

    input = xor(
        input,
        constant
    );

    return xor(
        aes128(ki, input),
        opc
    );
}

export function f1({
    ki,
    opc,
    rand,
    sqn,
    amf
}) {
    const temp = getTemp(
        ki,
        opc,
        rand
    );

    const in1 = Buffer.alloc(16);

    sqn.copy(in1, 0);
    amf.copy(in1, 6);
    sqn.copy(in1, 8);
    amf.copy(in1, 14);

    let input = xor(
        in1,
        opc
    );

    input = rotateLeft(
        input,
        64
    );

    input = xor(
        input,
        temp
    );

    const output = xor(
        aes128(ki, input),
        opc
    );

    return {
        macA: output.subarray(0, 8),
        macS: output.subarray(8, 16)
    };
}

export function f2345({
    ki,
    opc,
    rand
}) {
    const temp = getTemp(
        ki,
        opc,
        rand
    );

    const out2 = computeF2345({
        ki,
        opc,
        temp,
        rotation: 0,
        constant: C2
    });

    const out3 = computeF2345({
        ki,
        opc,
        temp,
        rotation: 32,
        constant: C3
    });

    const out4 = computeF2345({
        ki,
        opc,
        temp,
        rotation: 64,
        constant: C4
    });

    const out5 = computeF2345({
        ki,
        opc,
        temp,
        rotation: 96,
        constant: C5
    });

    return {
        res: out2.subarray(8, 16),
        ck: out3,
        ik: out4,
        ak: out5.subarray(0, 6)
    };
}

export function generateAuthenticationVector({
    ki,
    opc,
    rand,
    sqn,
    amf
}) {
    const { macA, macS } = f1({
        ki,
        opc,
        rand,
        sqn,
        amf
    });

    const {
        res,
        ck,
        ik,
        ak
    } = f2345({
        ki,
        opc,
        rand
    });

    const sqnXorAk = xor(
        sqn,
        ak
    );

    const autn = Buffer.concat([
        sqnXorAk,
        amf,
        macA
    ]);

    return {
        rand,
        xres: res,
        ck,
        ik,
        ak,
        macA,
        macS,
        autn
    };
}

export function deriveKasme({
    ck,
    ik,
    sqn,
    ak,
    plmn
}) {

    if (ck.length !== 16) {
        throw new Error('CK must be 16 bytes');
    }

    if (ik.length !== 16) {
        throw new Error('IK must be 16 bytes');
    }

    if (sqn.length !== 6) {
        throw new Error('SQN must be 6 bytes');
    }

    if (ak.length !== 6) {
        throw new Error('AK must be 6 bytes');
    }

    if (plmn.length !== 3) {
        throw new Error('PLMN must be 3 bytes');
    }

    const key = Buffer.concat([
        ck,
        ik
    ]);

    const sqnXorAk = xor(
        sqn,
        ak
    );

    const message = Buffer.concat([
        Buffer.from([0x10]),
        plmn,
        Buffer.from([
            0x00,
            0x03
        ]),
        sqnXorAk,
        Buffer.from([
            0x00,
            0x06
        ])
    ]);

    return crypto.createHmac('sha256', key).update(message).digest();
}

export function generateAuthenticationVectorForSubscriber({
    ki,
    opc,
    sqn,
    amf,
    plmn
}) {
    const rand = crypto.randomBytes(16);
    const vector = generateAuthenticationVector({
        ki,
        opc,
        rand,
        sqn,
        amf
    });
    const kasme = deriveKasme({
        ck: vector.ck,
        ik: vector.ik,
        sqn,
        ak: vector.ak,
        plmn
    });

    return {
        rand,
        xres: vector.xres,
        autn: vector.autn,
        kasme
    };
}

export function verifyAuthenticationVector({ // apagar no futuro pois isto é o UE que faz
    ki,
    opc,
    rand,
    autn,
    xres,
    amf
}) {
    if (autn.length !== 16) {
        throw new Error('AUTN must be 16 bytes');
    }

    if (xres.length !== 8) {
        throw new Error('XRES must be 8 bytes');
    }

    const sqnXorAk = autn.subarray(0, 6);
    const receivedAmf = autn.subarray(6, 8);
    const receivedMacA = autn.subarray(8, 16);

    const { ak, res } = f2345({
        ki,
        opc,
        rand
    });

    const sqn = xor(sqnXorAk, ak);

    const { macA } = f1({
        ki,
        opc,
        rand,
        sqn,
        amf: receivedAmf
    });

    const macValid = macA.equals(receivedMacA);
    const resValid = res.equals(xres);

    return {
        authenticated: macValid && resValid,
        macValid,
        resValid,
        sqn,
        ak,
        res,
        receivedMacA,
        calculatedMacA: macA,
        receivedAmf
    };
}

export function generateUEAuthentication({
    ki,
    opc,
    rand,
    autn
}) {
    const sqn = recoverSQN(autn, ak);
    const res = f2(ki, opc, rand);

    return {
        res,
        sqn
    };
}