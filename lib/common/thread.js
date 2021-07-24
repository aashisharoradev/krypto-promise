'use strict';
const { workerData, parentPort } = require('worker_threads');
const path = require('path');

(async () => {
    try {
        const cryptoModule = require(path.join(__dirname, '..', 'operations', workerData.moduleName));
        const data = await cryptoModule[workerData.operation](workerData.payload);
        parentPort.postMessage(data, ArrayBuffer);
    } catch (error) {
        parentPort.postMessage(error);
    }
})();
