'use strict';
const { calculateHMAC } = require('./index');

const startTime = Date.now();
const promises = [];

 for(let i =0; i < 1; i++) {
    promises.push(calculateHMAC({
        key: 'this-test-key',
        message: 'sign this message',
        alg: 'sha256'
    }));
}

(async () => {
    try {
        await Promise.all(promises);
   
    console.log((Date.now() - startTime) + 'ms');
    } catch (error) {
        console.log(error);
    }
    
})();





