'use strict';
const yup = require('yup');
const natives = require('../../build/Release/kryptonative');

const schema = yup.object().shape({
    alg: yup.string().matches(/(sha256|sha384|sha512)/).required(),
    key: yup.string().required(),
    message: yup.string().required(),
    encoding: yup.string().matches(/(base64|hex|ascii|utf8)/).default('ascii'), 
});

exports.calculateHMAC = async function(opts) {
    await schema.validate(opts);
    
    return natives.calculateHMAC({
        message: Buffer.from(opts.message, opts.encoding),
        key: Buffer.from(opts.key, opts.encoding),
        alg: opts.alg
    });

};