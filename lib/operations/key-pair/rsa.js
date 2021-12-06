'use strict';

const yup = require('yup');
const natives = require('../../../build/Release/kryptonative');

const rsaSchema = yup.object().shape({
    modulusBits: yup.number().required().positive().oneOf([1024, 2048, 4096, 8192]).default(1024)
});

exports.generateRSAKeyPair = async function (opts) {
    const payload = await rsaSchema.validate(opts);

    return natives.generateRSAKeyPair({
        modulusBits: payload.modulusBits
    });
};