import net from 'net';
import {
    APPLICATION_IDS,
    AVP_CODES,
    AVP_NAMES,
    COMMAND_CODES
} from '../../Common/Dictionary.js';

import {
    createULR,
    decodeAuthenticationInfo,
    isAnswer
} from '../../Common/Packet.js';

import {
    createIPv4AVP,
    createStringAVP,
    createUInt32AVP,
    decodeAVP,
} from '../../Common/AVP.js';

import {
    createDiameterMessage,
    parseDiameterMessage
} from '../../Common/Diameter.js';

import { verifyAuthenticationVector } from '../../Common/milenage.js';

let receiveBuffer = Buffer.alloc(0);

const client = net.createConnection({ port: 3868, host: 'localhost' }, () => {
    console.log('Connected to HSS!');

    const originHost = createStringAVP(
        AVP_CODES.ORIGIN_HOST,
        'mme.epc.mobile-core.spacelabs.pt'
    );

    const originRealm = createStringAVP(
        AVP_CODES.ORIGIN_REALM,
        'mobile-core.spacelabs.pt'
    );

    const hostIp = createIPv4AVP(
        AVP_CODES.HOST_IP_ADDRESS,
        '127.0.0.1'
    );

    const vendorId = createUInt32AVP(
        AVP_CODES.VENDOR_ID,
        99999
    );

    const productName = createStringAVP(
        AVP_CODES.PRODUCT_NAME,
        'SpaceLabs Mobile Core MME'
    );

    const authApplicationId = createUInt32AVP(
        AVP_CODES.AUTH_APPLICATION_ID,
        APPLICATION_IDS.S6A
    );

    const avps = Buffer.concat([
        originHost,
        originRealm,
        hostIp,
        vendorId,
        productName,
        authApplicationId
    ]);

    const cer = createDiameterMessage({
        flags: 0x80,
        commandCode: 257,
        applicationId: APPLICATION_IDS.BASE,
        avps
    });

    const parsed = parseDiameterMessage(cer);
    for (const avp of parsed.avps) {
        console.log(AVP_NAMES[avp.code] ?? `Unknown-${avp.code}`, avp.data);
    }

    client.write(cer);
});

client.on('error', (error) => {
    console.error('Client error:', error);
});

client.on('close', () => {
    console.log('Connection closed');
});

client.on('data', (data) => {
    receiveBuffer = Buffer.concat([
        receiveBuffer,
        data
    ]);

    while (receiveBuffer.length >= 20) {
        const messageLength = receiveBuffer.readUIntBE(1, 3);

        if (receiveBuffer.length < messageLength) {
            break;
        }

        const message = receiveBuffer.subarray(0, messageLength);

        receiveBuffer = receiveBuffer.subarray(messageLength);
        console.log('Received from HSS!');
        const response = parseDiameterMessage(message);

        if (response.commandCode === COMMAND_CODES.CAPABILITIES_EXCHANGE && isAnswer(response)) {
            console.log('CEA received!');
            console.log('Sending DWR...');

            const dwr = createDiameterMessage({
                flags: 0x80,
                commandCode: COMMAND_CODES.DEVICE_WATCHDOG,
                applicationId: APPLICATION_IDS.BASE,
                avps: Buffer.concat([
                    createStringAVP(AVP_CODES.ORIGIN_HOST, 'mme.epc.mobile-core.spacelabs.pt'),
                    createStringAVP(AVP_CODES.ORIGIN_REALM, 'mobile-core.spacelabs.pt')
                ])
            });

            client.write(dwr);
            console.log('Sending AIR...');

            const air = createDiameterMessage({
                flags: 0x80,
                commandCode: COMMAND_CODES.AUTHENTICATION_INFORMATION,
                applicationId: APPLICATION_IDS.S6A,
                avps: Buffer.concat([
                    createStringAVP(
                        AVP_CODES.USER_NAME,
                        '268991234567890'
                    ),
                    createStringAVP(
                        AVP_CODES.ORIGIN_HOST,
                        'mme.epc.mobile-core.spacelabs.pt'
                    ),
                    createStringAVP(
                        AVP_CODES.ORIGIN_REALM,
                        'mobile-core.spacelabs.pt'
                    )
                ])
            });

            console.log('AIR HEX:', air.toString('hex'));
            client.write(air);
        }

        if (response.commandCode === COMMAND_CODES.DEVICE_WATCHDOG && isAnswer(response)) {
            console.log('DWA received!');
        }

        if (response.commandCode === COMMAND_CODES.AUTHENTICATION_INFORMATION && isAnswer(response)) {
            console.log('\n========== AIA RECEIVED ==========');
            const authenticationInfo = response.avps.find(avp => avp.code === AVP_CODES.AUTHENTICATION_INFO);

            if (!authenticationInfo) {
                console.log('Authentication-Info não encontrado!');
                return;
            }

            const vector = decodeAuthenticationInfo(authenticationInfo);

            console.log(
                '\n========== LTE AUTHENTICATION =========='
            );

            console.log(
                'RAND:',
                vector.rand.toString('hex')
            );

            console.log(
                'XRES:',
                vector.xres.toString('hex')
            );

            console.log(
                'AUTN:',
                vector.autn.toString('hex')
            );

            console.log(
                'KASME:',
                vector.kasme.toString('hex')
            );

            const ki = Buffer.from(
                '00112233445566778899aabbccddeeff',
                'hex'
            );

            const opc = Buffer.from(
                '0102030405060708090a0b0c0d0e0f10',
                'hex'
            );

            const authentication = verifyAuthenticationVector({
                ki,
                opc,
                rand: vector.rand,
                autn: vector.autn,
                xres: vector.xres
            });

            console.log(
                '\nUE calculated values:'
            );

            console.log(
                'SQN:',
                authentication.sqn.toString('hex')
            );

            console.log(
                'AK:',
                authentication.ak.toString('hex')
            );

            console.log(
                'RES:',
                authentication.res.toString('hex')
            );

            console.log(
                'MAC-A received:',
                authentication.receivedMacA.toString('hex')
            );

            console.log(
                'MAC-A calculated:',
                authentication.calculatedMacA.toString('hex')
            );

            console.log(
                'MAC-A valid:',
                authentication.macValid
            );

            console.log(
                'RES == XRES:',
                authentication.resValid
            );

            console.log(
                'AUTHENTICATION:',
                authentication.authenticated
                    ? '✅ SUCCESS'
                    : '❌ FAILED'
            );

            if (authentication.authenticated) {
                const ulr = createULR(response);
                client.write(ulr, () => console.log('ULR sent!'));
            }

            console.log('========================================\n');
        }

        if (response.commandCode === COMMAND_CODES.UPDATE_LOCATION && isAnswer(response)) {
            console.log('\n========== ULA RECEIVED ==========');
            const resultCodeAVP = response.avps.find(avp => avp.code === AVP_CODES.RESULT_CODE);

            if (!resultCodeAVP) {
                console.log('ULA sem Result-Code!');
                return;
            }

            const resultCode = decodeAVP(resultCodeAVP);

            console.log('Result-Code:', resultCode);

            if (resultCode === 2001) {
                console.log('ULA SUCCESS!');
            } else {
                console.log('ULA failed!');
            }

            console.log('==================================\n');
        }

        console.log('\nAVPs:');

        for (const avp of response.avps) {
            const name = AVP_NAMES[avp.code] ?? `Unknown-${avp.code}`;
            const value = decodeAVP(avp);
            console.log(`${name}:`, value);
        }
    }
});