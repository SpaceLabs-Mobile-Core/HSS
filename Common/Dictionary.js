export const AVP_CODES = {
    USER_NAME: 1,
    HOST_IP_ADDRESS: 257,
    AUTH_APPLICATION_ID: 258,
    ORIGIN_HOST: 264,
    VENDOR_ID: 266,
    RESULT_CODE: 268,
    PRODUCT_NAME: 269,
    ORIGIN_STATE_ID: 278,
    ORIGIN_REALM: 296,
    RAT_TYPE: 1032,
    ULR_FLAGS: 1405,
    ULA_FLAGS: 1406,
    VISITED_PLMN_ID: 1407,
    AUTHENTICATION_INFO: 1413,
    SUBSCRIPTION_DATA: 1400,
    MME_LOCATION_INFORMATION: 1600
};

export const AVP_NAMES = {
    1: 'User-Name',
    257: 'Host-IP-Address',
    258: 'Auth-Application-Id',
    264: 'Origin-Host',
    266: 'Vendor-Id',
    268: 'Result-Code',
    269: 'Product-Name',
    278: 'Origin-State-Id',
    296: 'Origin-Realm',
    1032: 'RAT-Type',
    1405: 'ULR-Flags',
    1406: 'ULA-Flags',
    1407: 'Visited-PLMN-Id',
    1413: 'Authentication-Info',
    1414: 'E-UTRAN-Vector',
    1400: 'Subscription-Data',
    1600: 'MME-Location-Information'
};

export const APPLICATION_IDS = {
    BASE: 0,
    S6A: 16777251
};

export const VENDOR_IDS = {
    THREE_GPP: 10415
};

export const COMMAND_CODES = {
    CAPABILITIES_EXCHANGE: 257,
    DEVICE_WATCHDOG: 280,
    AUTHENTICATION_INFORMATION: 318,
    UPDATE_LOCATION: 316
};

export const S6A_AVP_CODES = {
    E_UTRAN_VECTOR: 1414,
    RAND: 1447,
    XRES: 1448,
    AUTN: 1449,
    KASME: 1450,
    APN_CONFIGURATION: 1430,
    SERVICE_SELECTION: 493,
    EPS_SUBSCRIBED_QOS_PROFILE: 1431
};

export const RAT_TYPES = {
    EUTRAN: 1004
};