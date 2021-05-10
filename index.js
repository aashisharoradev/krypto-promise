const threadedFunction = require('./lib/common/convert-thread');
const { calculateHMAC } = require('./lib/operations/hmac');

module.exports = {
    promised: {
        calculateHMAC: calculateHMAC
    },
    threaded: {
        calculateHMAC: function (opts) {
            return threadedFunction('hmac', arguments.callee.name , opts)();
        } 
    }
}

