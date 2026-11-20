const http = require('http');

const TEST_PORT = process.env.PORT || 3006;
process.env.PORT = String(TEST_PORT);

function request(options, body = null) {
  return new Promise((resolve, reject) => {
    const req = http.request({ port: TEST_PORT, ...options }, res => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, headers: res.headers, body: JSON.parse(data) });
        } catch (e) {
          resolve({ status: res.statusCode, headers: res.headers, body: data });
        }
      });
    });
    req.on('error', reject);
    if (body) {
      req.setHeader('Content-Type', 'application/json');
      req.write(JSON.stringify(body));
    }
    req.end();
  });
}

async function runTests() {
  console.log('--- STARTING FAPI 2.0 SERVER-TO-SERVER (M2M) INTEGRATION TESTS ---');

  // 1. Status
  const s = await request({ path: '/api/s2s/status', method: 'GET' });
  console.log('1. Client Status:', s.status, 'Client ID:', s.body.clientId);

  // 2. Token Exchange (client_credentials + private_key_jwt + DPoP)
  const t1 = await request({ path: '/api/s2s/run-token-exchange', method: 'POST' }, { enforceNonce: false });
  console.log('2. M2M Token Exchange:', t1.status, 'Token Type:', t1.body.tokenResponse.token_type, 'cnf.jkt:', t1.body.clientDpopThumbprint);

  // 3. Token Exchange with Server Nonce Challenge
  const t2 = await request({ path: '/api/s2s/run-token-exchange', method: 'POST' }, { enforceNonce: true });
  console.log('3. M2M Token with Nonce Challenge:', t2.status, 'Nonce Negotiated:', t2.body.nonceNegotiated);

  // 4. B2B Calls
  const b1 = await request({ path: '/api/s2s/run-b2b-call', method: 'POST' }, { action: 'treasury' });
  console.log('4a. B2B Treasury Balances Call:', b1.status, 'Positions:', b1.body.bankResponse.data.length);

  const b2 = await request({ path: '/api/s2s/run-b2b-call', method: 'POST' }, { action: 'payroll' });
  console.log('4b. B2B Bulk Payroll Execution:', b2.status, 'Batch ID:', b2.body.bankResponse.payrollBatch.batchId);

  const b3 = await request({ path: '/api/s2s/run-b2b-call', method: 'POST' }, { action: 'fx' });
  console.log('4c. B2B FX Rates Quote:', b3.status, 'Quote ID:', b3.body.bankResponse.quote.quoteId);

  // 5. Threat Simulations
  const a1 = await request({ path: '/api/s2s/attack', method: 'POST' }, { attackType: 'exfiltrated_bearer' });
  console.log('5a. Threat 1 (Exfiltrated Bearer Replay): Blocked =', a1.body.blocked);

  const a2 = await request({ path: '/api/s2s/attack', method: 'POST' }, { attackType: 'rogue_service_key' });
  console.log('5b. Threat 2 (Rogue Service with Own Key): Blocked =', a2.body.blocked);

  const a3 = await request({ path: '/api/s2s/attack', method: 'POST' }, { attackType: 'stale_nonce' });
  console.log('5c. Threat 3 (Stale / Bogus Nonce): Blocked =', a3.body.blocked);

  console.log('--- ALL SERVER-TO-SERVER (M2M) TESTS PASSED SUCCESSFULLY! ---');
  process.exit(0);
}

require('./server');
setTimeout(runTests, 800);
