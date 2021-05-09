'use strict';
const assert = require('assert');
const { calculateHMAC } = require('../index');

describe('#calculateHMAC', () => {
  it('Should be able to create signature', async () => {
      const data = await calculateHMAC({
          key: 'this-test-key',
          message: 'sign this message',
          alg: 'sha256'
      });
      assert.ok('wbOhj2FJMdtB8kmjp88U+RPQz/T9cMTlXTpygVvctYE=' === data.toString('base64'));
  });
});