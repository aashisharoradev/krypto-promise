'use strict';
const { workerData, parentPort } = require('worker_threads');
const path = require('path');

(async () => {
    try {
        const cryptoModule = require(path.join(__dirname, '..', 'operations', workerData.moduleName));
        const data = await cryptoModule[workerData.operation](workerData.payload);
        console.log(data.toString('base64'));
        parentPort.postMessage(data, ArrayBuffer);
    } catch (error) {
        parentPort.postMessage(error);
    }
})();
