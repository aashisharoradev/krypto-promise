'use strict';
const { calculateHMAC, verifyHMAC } = require('./lib/operations/hmac');
const { generateRSAKeyPair } = require('./lib/operations/key-pair');

module.exports = {
    integrity: {
        calculateHMAC,
        verifyHMAC
    },
    keygen: {
        generateRSAKeyPair
    }
}

