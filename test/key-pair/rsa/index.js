'use strict';
const assert = require('assert');
const { generateRSAKeyPair } = require('../../../index').keygen;

describe('#generateRSAKeyPair', () => {
    it('Should be able to create key pair generation for 1024', async () => {
        const keyPair = await generateRSAKeyPair({
            modulusBits: 1024
        });

        Object.keys(keyPair).forEach(key => {
            assert.ok(keyPair[key].length > 0);
        });
    });

    it('Should be able to create key pair generation for 2048', async () => {
        const keyPair = await generateRSAKeyPair({
            modulusBits: 2048
        });
        
        Object.keys(keyPair).forEach(key => {
            assert.ok(keyPair[key].length > 0);
        });
    });

    it('Should be able to create key pair generation for 4096', async () => {
        const keyPair = await generateRSAKeyPair({
            modulusBits: 4096
        });
        
        Object.keys(keyPair).forEach(key => {
            assert.ok(keyPair[key].length > 0);
        });
    });

    it('Should be able to create key pair generation for 8192', async () => {
        const keyPair = await generateRSAKeyPair({
            modulusBits: 8192
        });
        
        Object.keys(keyPair).forEach(key => {
            assert.ok(keyPair[key].length > 0);
        });
    });
});