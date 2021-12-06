'use strict';
const yup = require('yup');
const natives = require('../../build/Release/kryptonative');

const hmacSchema = yup.object().shape({
    alg: yup.string().matches(/(sha256|sha384|sha512)/).required(),
    key: yup.string().required(),
    message: yup.string().required(),
    encoding: yup.string().matches(/(base64|hex|ascii|utf8)/).default('ascii') 
});

const hmacVerifySchema = hmacSchema.shape({
    signature: yup.string().required(),
    signatureEncoding: yup.string().matches(/(base64|hex)/).default('base64')
});

exports.calculateHMAC = async function(opts) {
    const payload = await hmacSchema.validate(opts);
    
    return natives.calculateHMAC({
        message: Buffer.from(payload.message, payload.encoding),
        key: Buffer.from(payload.key, payload.encoding),
        alg: payload.alg
    });
};

exports.verifyHMAC = async function (opts) {
    const payload = await hmacVerifySchema.validate(opts);

    const signature = await natives.calculateHMAC({
        message: Buffer.from(payload.message, payload.encoding),
        key: Buffer.from(payload.key, payload.encoding),
        alg: payload.alg
    });

    const inputSignature = Buffer.from(payload.signature, payload.signatureEncoding);
    return Buffer.compare(signature, inputSignature) === 0;
};