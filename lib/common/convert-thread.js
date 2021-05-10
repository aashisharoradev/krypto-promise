'use strict';
const { Worker, workerData } = require('worker_threads');
const path = require('path');

module.exports = function (moduleName, operation, payload) {
    return function() {
        return new Promise((resolve, reject) => {
            const worker = new Worker(path.join(__dirname, 'thread.js'), {
                workerData: {
                    moduleName,
                    operation,
                    payload
                }
            });
            worker.on('message', (message) => {
                console.log('message >> ', message.buffer);
                resolve(Buffer.from(message.buffer, 0, message.length));
            });
            worker.on('error', reject);
        });
        
    }
};