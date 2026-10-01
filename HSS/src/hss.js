import net from 'net';

import {
    createAIA,
    createAuthenticationInfo,
    createCEA,
    createDWA,
    createULA,
    isRequest
} from '../../Common/Packet.js';

import {
    decodeAVP
} from '../../Common/AVP.js';

import {
    parseDiameterMessage
} from '../../Common/Diameter.js';

import {
    AVP_CODES,
    COMMAND_CODES,
} from '../../Common/Dictionary.js';
import { getSubscriber, incrementSQN } from './subscriberDatabase.js';
import { generateAuthenticationVectorForSubscriber } from '../../Common/milenage.js';

const server = net.createServer((socket) => {
    let receiveBuffer = Buffer.alloc(0);
    socket.on('data', (data) => {
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

            try {
                const diameter = parseDiameterMessage(message);

                if (diameter.commandCode === COMMAND_CODES.CAPABILITIES_EXCHANGE && isRequest(diameter)) {
                    console.log('CER received!');
                    const cea = createCEA(diameter);
                    socket.write(cea, () => {
                        console.log('CEA sent!');
                    });
                }

                if (diameter.commandCode === COMMAND_CODES.DEVICE_WATCHDOG && isRequest(diameter)) {
                    console.log('DWR received!');
                    const dwa = createDWA(diameter);

                    socket.write(dwa, () => {
                        console.log('DWA sent!');
                    });
                }

                if (diameter.commandCode === COMMAND_CODES.AUTHENTICATION_INFORMATION && isRequest(diameter)) {
                    console.log('\n========== AIR RECEIVED ==========');

                    const userNameAVP = diameter.avps.find(
                        avp => avp.code === AVP_CODES.USER_NAME
                    );

                    if (!userNameAVP) {
                        console.log('AIR sem User-Name!');
                    } else {
                        const imsi = decodeAVP(userNameAVP);
                        const subscriber = getSubscriber(imsi);
                        if (!subscriber) {
                            console.log('Subscriber not found or disabled!');
                            return;
                        }

                        console.log('Subscriber found!');
                        console.log(
                            'Ki:',
                            subscriber.ki.toString('hex')
                        );
                        console.log(
                            'OPc:',
                            subscriber.opc.toString('hex')
                        );
                        console.log(
                            'SQN:',
                            subscriber.sqn.toString('hex')
                        );
                        console.log(
                            'AMF:',
                            subscriber.amf.toString('hex')
                        );

                        const vector = generateAuthenticationVectorForSubscriber({
                                ki: subscriber.ki,
                                opc: subscriber.opc,
                                sqn: subscriber.sqn,
                                amf: subscriber.amf,
                                plmn: Buffer.from(
                                    '62f899',
                                    'hex'
                                )
                            });

                        console.log('\nGenerated LTE Authentication Vector:');

                        console.log(
                            'RAND :',
                            vector.rand.toString('hex')
                        );

                        console.log(
                            'XRES :',
                            vector.xres.toString('hex')
                        );

                        console.log(
                            'AUTN :',
                            vector.autn.toString('hex')
                        );

                        console.log(
                            'KASME:',
                            vector.kasme.toString('hex')
                        );

                        const newSQN = incrementSQN(imsi);

                        console.log(
                            'New SQN:',
                            newSQN.toString('hex')
                        );

                        const authenticationInfo = createAuthenticationInfo(vector);
                        const aia = createAIA(diameter, authenticationInfo);
                        socket.write(aia);

                        console.log('AIA sent!');
                    }

                    console.log('==================================\n');
                }

                if (diameter.commandCode === COMMAND_CODES.UPDATE_LOCATION && isRequest(diameter)) {
                    console.log('\n========== ULR RECEIVED ==========');
                    const userNameAVP = diameter.avps.find(avp => avp.code === AVP_CODES.USER_NAME);

                    if (!userNameAVP) {
                        console.log('ULR sem IMSI');
                        return;
                    }

                    const imsi = decodeAVP(userNameAVP);
                    console.log('IMSI:', imsi);
                    const subscriber = getSubscriber(imsi);
                    const ula = createULA(diameter, subscriber);
                    socket.write(ula, () => console.log('ULA sent!'));

                    console.log('=================================\n');
                }

                
            } catch (error) {
                console.error('Failed to parse Diameter:', error);
            }
        }
    });

    socket.on('error', (error) => {
        console.error('Socket error:', error);
    });

    socket.on('close', () => {
        console.log('Client disconnected');
    });
});


server.listen({ host: 'localhost', port: 3868}, () => {
    console.log('HSS Server is running at port 3868');
});