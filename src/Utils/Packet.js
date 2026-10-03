import { createGroupedAVP, createOctetStringAVP, createStringAVP, createUInt32AVP } from "./AVP.js";
import { createDiameterMessage } from "./diameter.js";
import { APPLICATION_IDS, AVP_CODES, COMMAND_CODES, RAT_TYPES, S6A_AVP_CODES, VENDOR_IDS } from "./Dictionary.js";

export function createCEA(request) {
    const originHost = createStringAVP(
        AVP_CODES.ORIGIN_HOST,
        'hss.epc.mobile-core.spacelabs.pt'
    );

    const originRealm = createStringAVP(
        AVP_CODES.ORIGIN_REALM,
        'mobile-core.spacelabs.pt'
    );

    const resultCode = createUInt32AVP(
        AVP_CODES.RESULT_CODE,
        2001
    );

    const avps = Buffer.concat([
        resultCode,
        originHost,
        originRealm
    ]);

    return createDiameterMessage({
        flags: 0x00,
        commandCode: request.commandCode,
        applicationId: request.applicationId,
        hopByHopId: request.hopByHopId,
        endToEndId: request.endToEndId,
        avps
    });
}

export function isRequest(message) {
    return (message.flags & 0x80) !== 0;
}

export function isAnswer(message) {
    return !isRequest(message);
}

export function createDWA(request) {
    const resultCode = createUInt32AVP(
        AVP_CODES.RESULT_CODE,
        2001
    );

    const originHost = createStringAVP(
        AVP_CODES.ORIGIN_HOST,
        'hss.epc.mobile-core.spacelabs.pt'
    );

    const originRealm = createStringAVP(
        AVP_CODES.ORIGIN_REALM,
        'mobile-core.spacelabs.pt'
    );

    const avps = Buffer.concat([
        resultCode,
        originHost,
        originRealm
    ]);

    return createDiameterMessage({
        flags: 0x00,

        commandCode:
            COMMAND_CODES.DEVICE_WATCHDOG,

        applicationId:
            request.applicationId,

        hopByHopId:
            request.hopByHopId,

        endToEndId:
            request.endToEndId,

        avps
    });
}

export function createAIA(request, authenticationInfo) {
    const resultCode = createUInt32AVP(
        AVP_CODES.RESULT_CODE,
        2001
    );

    const originHost = createStringAVP(
        AVP_CODES.ORIGIN_HOST,
        'hss.epc.mobile-core.spacelabs.pt'
    );

    const originRealm = createStringAVP(
        AVP_CODES.ORIGIN_REALM,
        'mobile-core.spacelabs.pt'
    );

    const avps = Buffer.concat([
        resultCode,
        originHost,
        originRealm,
        authenticationInfo
    ]);

    return createDiameterMessage({
        flags: 0x00,
        commandCode: COMMAND_CODES.AUTHENTICATION_INFORMATION,
        applicationId: request.applicationId,
        hopByHopId: request.hopByHopId,
        endToEndId: request.endToEndId,
        avps
    });
}

export function createULR() { // apagar no futuro pois isto é o MME que faz
    const userName = createStringAVP(
        AVP_CODES.USER_NAME,
        '268991234567890'
    );

    const originHost = createStringAVP(
        AVP_CODES.ORIGIN_HOST,
        'mme.epc.mobile-core.spacelabs.pt'
    );

    const originRealm = createStringAVP(
        AVP_CODES.ORIGIN_REALM,
        'mobile-core.spacelabs.pt'
    );

    const ratType = createUInt32AVP(
        AVP_CODES.RAT_TYPE,
        RAT_TYPES.EUTRAN,
        0x40,
        VENDOR_IDS.THREE_GPP
    );

    const ulrFlags = createUInt32AVP(
        AVP_CODES.ULR_FLAGS,
        0,
        0x40,
        VENDOR_IDS.THREE_GPP
    );

    const visitedPlmnId = createOctetStringAVP(
        AVP_CODES.VISITED_PLMN_ID,
        Buffer.from('62f899', 'hex'),
        0x40,
        VENDOR_IDS.THREE_GPP
    );
    
    const avps = Buffer.concat([
        userName,
        originHost,
        originRealm,
        ratType,
        ulrFlags,
        visitedPlmnId
    ]);

    return createDiameterMessage({
        flags: 0xC0,
        commandCode:
            COMMAND_CODES.UPDATE_LOCATION,
        applicationId:
            APPLICATION_IDS.S6A,
        avps
    });
}

export function decodeAuthenticationInfo(avp) {
    if (avp.code !== AVP_CODES.AUTHENTICATION_INFO || avp.vendorId !== VENDOR_IDS.THREE_GPP) {
        throw new Error('AVP is not Authentication-Info');
    }

    const vectorAVP = avp.children?.find(child => child.code === S6A_AVP_CODES.E_UTRAN_VECTOR && child.vendorId === VENDOR_IDS.THREE_GPP);

    if (!vectorAVP) {
        throw new Error('E-UTRAN-Vector not found');
    }

    const getChild = (code) => {
        const child = vectorAVP.children?.find(avp => avp.code === code && avp.vendorId === VENDOR_IDS.THREE_GPP);

        if (!child) {
            throw new Error(`S6a AVP ${code} not found`);
        }

        return child.data;
    };

    return {
        rand: getChild(S6A_AVP_CODES.RAND),
        xres: getChild(S6A_AVP_CODES.XRES),
        autn: getChild(S6A_AVP_CODES.AUTN),
        kasme: getChild(S6A_AVP_CODES.KASME)
    };
}

export function createAuthenticationInfo({
    rand,
    xres,
    autn,
    kasme
}) {
    const eUtranVector = createGroupedAVP(
        S6A_AVP_CODES.E_UTRAN_VECTOR,
        [
            createOctetStringAVP(
                S6A_AVP_CODES.RAND,
                rand,
                0x40,
                VENDOR_IDS.THREE_GPP
            ),
            createOctetStringAVP(
                S6A_AVP_CODES.XRES,
                xres,
                0x40,
                VENDOR_IDS.THREE_GPP
            ),
            createOctetStringAVP(
                S6A_AVP_CODES.AUTN,
                autn,
                0x40,
                VENDOR_IDS.THREE_GPP
            ),
            createOctetStringAVP(
                S6A_AVP_CODES.KASME,
                kasme,
                0x40,
                VENDOR_IDS.THREE_GPP
            )
        ],
        0x40,
        VENDOR_IDS.THREE_GPP
    );

    return createGroupedAVP(
        AVP_CODES.AUTHENTICATION_INFO,
        [eUtranVector],
        0x40,
        VENDOR_IDS.THREE_GPP
    );
}

export function createULA(request, subscriber) {
    const resultCode = createUInt32AVP(
        AVP_CODES.RESULT_CODE,
        2001
    );

    const originHost = createStringAVP(
        AVP_CODES.ORIGIN_HOST,
        'hss.epc.mobile-core.spacelabs.pt'
    );

    const originRealm = createStringAVP(
        AVP_CODES.ORIGIN_REALM,
        'mobile-core.spacelabs.pt'
    );

    const subscriptionData = createSubscriptionData(subscriber);

    const avps = Buffer.concat([
        resultCode,
        originHost,
        originRealm,
        subscriptionData
    ]);

    return createDiameterMessage({
        flags: 0x00,
        commandCode: COMMAND_CODES.UPDATE_LOCATION,
        applicationId: request.applicationId,
        hopByHopId: request.hopByHopId,
        endToEndId:request.endToEndId,
        avps
    });
}

export function createSubscriptionData(subscriber) {
    const apn = createGroupedAVP(
        S6A_AVP_CODES.APN_CONFIGURATION,
        [
            createStringAVP(
                S6A_AVP_CODES.SERVICE_SELECTION,
                subscriber.profile.defaultApn
            )
        ],
        0x40,
        VENDOR_IDS.THREE_GPP
    );


    return createGroupedAVP(
        AVP_CODES.SUBSCRIPTION_DATA,
        [
            apn
        ],
        0x40,
        VENDOR_IDS.THREE_GPP
    );
}