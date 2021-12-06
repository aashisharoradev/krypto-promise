'use strict';
const assert = require('assert');
const { calculateHMAC, verifyHMAC } = require('../../../index').integrity;

describe('#calculateHMAC', () => {
  it('Should be able to create signature for algorithm sha256', async () => {
      const data = await calculateHMAC({
          key: 'this-test-key',
          message: 'sign this message',
          alg: 'sha256'
      });
    assert.ok('wbOhj2FJMdtB8kmjp88U+RPQz/T9cMTlXTpygVvctYE=' === data.toString('base64'));
    assert.ok(data.length === 32);
  });

  it('Should be able to create signature for algorithm sha384', async () => {
    const data = await calculateHMAC({
        key: 'this-test-key',
        message: 'sign this message',
        alg: 'sha384'
    });
    
    assert.ok('X+tHFNE8yJcACRNy0T7vwZ90ImZDajMabK84CUZM0TTF8nxNsgOqY02l+T7pSy7w' === data.toString('base64'));
    assert.ok(data.length === 48);
  });

  it('Should be able to create signature for algorithm sha512', async () => {
    const data = await calculateHMAC({
        key: 'this-test-key',
        message: 'sign this message',
        alg: 'sha512'
    });
    
    assert.ok('L/fzEnvSWqcA15kBcjuiA+MZAo9CGucSPXG1qln5AhloiToxUo42TsgE3zY2+/G8Hntb1fk0WUZDRaSPLXFnjw==' === data.toString('base64'));
    assert.ok(data.length === 64);
  });
});

describe('#verifyHMAC', () => {
  it('Should be able to verify signature for algorithm sha256', async () => {
      const data = await calculateHMAC({
          key: 'this-test-key',
          message: 'sign this message',
          alg: 'sha256'
      });
    
      const verify = await verifyHMAC({
          key: 'this-test-key',
          message: 'sign this message',
          alg: 'sha256',
          signature: data.toString('base64')
      });
    
    assert.ok(verify === true);
    
  });

  it('Should be able to verify signature for algorithm sha384', async () => {
    const data = await calculateHMAC({
        key: 'this-test-key',
        message: 'sign this message',
        alg: 'sha384'
    });
  
    const verify = await verifyHMAC({
        key: 'this-test-key',
        message: 'sign this message',
        alg: 'sha384',
        signature: data.toString('base64')
    });
  
    assert.ok(verify === true);
  
  });
  
  it('Should be able to verify signature for algorithm sha512', async () => {
    const data = await calculateHMAC({
        key: 'this-test-key',
        message: 'sign this message',
        alg: 'sha512'
    });
  
    const verify = await verifyHMAC({
        key: 'this-test-key',
        message: 'sign this message',
        alg: 'sha512',
        signature: data.toString('base64')
    });
  
    assert.ok(verify === true);
  
  });
});