const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const {
  decodeJwt,
  sha256Base64Url,
  generateECKeyPair,
  computeJwkThumbprint,
  createDPoPProof
} = require('./lib/crypto-utils');

const ServerToServerIdP = require('./lib/s2s-idp');
const B2BBankResourceServer = require('./lib/b2b-bank-api');
const M2MClient = require('./lib/m2m-client');

const PORT = process.env.PORT || 3001;
const BASE_URL = `http://localhost:${PORT}`;

// Initialize instances
const as = new ServerToServerIdP(BASE_URL);
const bank = new B2BBankResourceServer(as, BASE_URL);
const client = new M2MClient(BASE_URL);

// Register client with AS
as.registerClient({
  clientId: client.clientId,
  clientName: client.clientName,
  clientPublicJwk: client.authKey.jwkPublic,
  allowedScopes: client.scopes.split(' ')
});

// Register dedicated Bruno M2M client (supports both X.509 client certificate and JWK)
let brunoJwk = null;
try {
  const brunoKeys = require('./bruno/m2m-bruno-keys.json');
  if (brunoKeys && brunoKeys.authKey && brunoKeys.authKey.jwk) {
    brunoJwk = brunoKeys.authKey.jwk;
  }
} catch (e) {
  // Optional bruno keys file
}

as.registerClient({
  clientId: 'erp-acme-corp-bruno',
  clientName: 'Acme Corp Bruno M2M Client',
  clientPublicJwk: brunoJwk,
  allowedScopes: ['corporate:treasury', 'corporate:payments', 'corporate:fx-rates']
});

// Helper for parsing JSON or form-urlencoded request bodies
function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => body += chunk.toString());
    req.on('end', () => {
      if (!body) return resolve({});
      try {
        resolve(JSON.parse(body));
      } catch (e) {
        try {
          const params = new URLSearchParams(body);
          const obj = {};
          for (const [k, v] of params.entries()) obj[k] = v;
          resolve(obj);
        } catch (err) {
          reject(new Error('Invalid body payload'));
        }
      }
    });
    req.on('error', reject);
  });
}

function sendJson(res, statusCode, data, headers = {}) {
  const jsonStr = JSON.stringify(data, null, 2);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, DPoP, DPoP-Nonce',
    'Access-Control-Expose-Headers': 'DPoP-Nonce, WWW-Authenticate',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    ...headers
  });
  res.end(jsonStr);
}

function serveStatic(res, filePath, contentType) {
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('404 Not Found');
    } else {
      res.writeHead(200, {
        'Content-Type': contentType,
        'Access-Control-Allow-Origin': '*'
      });
      res.end(data);
    }
  });
}

const server = http.createServer(async (req, res) => {
  const parsedUrl = new URL(req.url, BASE_URL);
  const pathname = parsedUrl.pathname;
  const method = req.method;

  if (method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, DPoP, DPoP-Nonce',
      'Access-Control-Expose-Headers': 'DPoP-Nonce, WWW-Authenticate',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
    });
    res.end();
    return;
  }

  try {
    // -------------------------------------------------------------
    // STATIC ASSETS
    // -------------------------------------------------------------
    if (method === 'GET' && pathname === '/') {
      return serveStatic(res, path.join(__dirname, 'webapp', 'index.html'), 'text/html; charset=utf-8');
    }
    if (method === 'GET' && pathname === '/style.css') {
      return serveStatic(res, path.join(__dirname, 'webapp', 'style.css'), 'text/css; charset=utf-8');
    }
    if (method === 'GET' && pathname === '/app.js') {
      return serveStatic(res, path.join(__dirname, 'webapp', 'app.js'), 'application/javascript; charset=utf-8');
    }

    // -------------------------------------------------------------
    // FAPI AUTHORIZATION SERVER (M2M / S2S)
    // -------------------------------------------------------------
    if (method === 'GET' && pathname === '/.well-known/openid-configuration') {
      return sendJson(res, 200, as.getDiscoveryMetadata());
    }

    if (method === 'GET' && pathname === '/oauth/jwks.json') {
      return sendJson(res, 200, as.getJwks());
    }

    // Token Endpoint for client_credentials
    if (method === 'POST' && pathname === '/oauth/token') {
      const body = await parseBody(req);
      const dpopHeader = req.headers['dpop'];
      const enforceNonce = parsedUrl.searchParams.get('enforce_nonce') === 'true';

      try {
        const result = as.handleToken(body, dpopHeader, { enforceNonce });
        return sendJson(res, 200, result);
      } catch (err) {
        if (err.code === 'use_dpop_nonce') {
          return sendJson(res, 400, {
            error: 'use_dpop_nonce',
            error_description: 'Authorization Server requires a fresh DPoP-Nonce challenge.'
          }, { 'DPoP-Nonce': err.dpopNonce });
        }
        return sendJson(res, err.status || 400, {
          error: err.code || 'invalid_request',
          error_description: err.message
        });
      }
    }

    // -------------------------------------------------------------
    // B2B BANK RESOURCE SERVER (WHOLESALE / CORPORATE API)
    // -------------------------------------------------------------
    if (pathname.startsWith('/b2b-api/')) {
      const enforceNonce = parsedUrl.searchParams.get('enforce_nonce') === 'true';

      let authContext;
      try {
        authContext = bank.authenticateRequest(req, { enforceNonce });
      } catch (authErr) {
        if (authErr.code === 'use_dpop_nonce') {
          return sendJson(res, 401, {
            error: 'use_dpop_nonce',
            message: authErr.message,
            fapiSecurityAudit: authErr.audit
          }, {
            'WWW-Authenticate': 'DPoP error="use_dpop_nonce"',
            'DPoP-Nonce': authErr.dpopNonce
          });
        }
        return sendJson(res, authErr.status || 401, {
          error: 'unauthorized',
          message: authErr.message,
          fapiSecurityAudit: authErr.audit || null
        }, {
          'WWW-Authenticate': 'DPoP error="invalid_dpop_proof"'
        });
      }

      // Treasury Positions
      if (method === 'GET' && pathname === '/b2b-api/treasury/positions') {
        const data = bank.getTreasuryPositions(authContext);
        return sendJson(res, 200, data);
      }

      // Automated Payroll Execution
      if (method === 'POST' && pathname === '/b2b-api/payroll/execute-batch') {
        const body = await parseBody(req);
        const data = bank.executePayrollBatch(body, authContext);
        return sendJson(res, 200, data);
      }

      // FX Rates Quote
      if (method === 'GET' && pathname === '/b2b-api/fx/quote') {
        const pair = parsedUrl.searchParams.get('pair') || 'EUR/USD';
        const amount = parseFloat(parsedUrl.searchParams.get('amount') || '1000000');
        const data = bank.getFxQuote(pair, amount, authContext);
        return sendJson(res, 200, data);
      }
    }

    // -------------------------------------------------------------
    // AUTOMATED S2S WORKFLOW RUNNER (Drives the UI Dashboard)
    // -------------------------------------------------------------
    if (method === 'GET' && pathname === '/api/s2s/status') {
      return sendJson(res, 200, {
        clientId: client.clientId,
        clientName: client.clientName,
        scopes: client.scopes,
        keys: {
          authKey: {
            publicJwk: client.authKey.jwkPublic,
            thumbprint: client.authThumbprint,
            purpose: 'Used for private_key_jwt M2M client authentication'
          },
          dpopKey: {
            publicJwk: client.dpopKey.jwkPublic,
            thumbprint: client.dpopThumbprint,
            purpose: 'Used for DPoP sender-constraining proof signatures'
          }
        },
        hasActiveToken: !!client.activeToken,
        activeTokenSummary: client.activeToken ? {
          expires_in: client.activeToken.expires_in,
          dpop_jkt: client.activeToken.dpop_jkt,
          scope: client.activeToken.scope
        } : null
      });
    }

    if (method === 'POST' && pathname === '/api/s2s/reset-keys') {
      client.initKeys();
      as.registerClient({
        clientId: client.clientId,
        clientName: client.clientName,
        clientPublicJwk: client.authKey.jwkPublic,
        allowedScopes: client.scopes.split(' ')
      });
      return sendJson(res, 200, { message: 'M2M Keys Regenerated' });
    }

    // Helper endpoint to generate valid client_assertion and DPoP proofs for Postman/Bruno/curl clients
    if (method === 'POST' && pathname === '/api/s2s/create-proofs') {
      const body = await parseBody(req);
      const targetUrl = body.targetUrl || `${BASE_URL}/oauth/token`;
      const httpMethod = (body.httpMethod || 'POST').toUpperCase();
      let ath = body.ath || null;
      if (body.accessToken && !ath) {
        ath = sha256Base64Url(body.accessToken);
      }
      const nonce = body.nonce || null;

      const clientAssertion = client.createClientAssertion(targetUrl);
      const dpopProof = client.createDPoPProof(httpMethod, targetUrl, ath, nonce);

      return sendJson(res, 200, {
        client_id: client.clientId,
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        client_assertion: clientAssertion,
        dpop_proof: dpopProof,
        dpop_jkt: client.dpopThumbprint,
        ath,
        targetUrl,
        httpMethod
      });
    }

    // Step 1: Automated Token Acquisition (M2M Client Credentials)
    if (method === 'POST' && pathname === '/api/s2s/run-token-exchange') {
      const body = await parseBody(req);
      const withNonce = !!body.enforceNonce;

      const tokenUrl = `${BASE_URL}/oauth/token`;
      const clientAssertion = client.createClientAssertion(tokenUrl);

      // Create initial DPoP Proof
      let dpopNonce = client.lastAsNonce || null;
      let dpopProof = client.createDPoPProof('POST', tokenUrl, null, dpopNonce);

      const requestPayload = {
        grant_type: 'client_credentials',
        client_id: client.clientId,
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        client_assertion: clientAssertion,
        scope: client.scopes
      };

      let nonceRetryHappened = false;
      let tokenResult;

      try {
        tokenResult = as.handleToken(requestPayload, dpopProof, { enforceNonce: withNonce });
      } catch (err) {
        if (err.code === 'use_dpop_nonce') {
          // Automatic Client Nonce Negotiation: client extracts nonce and retries immediately!
          nonceRetryHappened = true;
          client.lastAsNonce = err.dpopNonce;
          dpopNonce = err.dpopNonce;
          dpopProof = client.createDPoPProof('POST', tokenUrl, null, dpopNonce);
          tokenResult = as.handleToken(requestPayload, dpopProof, { enforceNonce: false });
        } else {
          throw err;
        }
      }

      client.activeToken = tokenResult;

      return sendJson(res, 200, {
        success: true,
        title: 'M2M Token Acquisition (Client Credentials + DPoP)',
        explanation: 'The backend ERP service authenticated directly to the Authorization Server using private_key_jwt and requested a sender-constrained DPoP access token without any human interaction.',
        nonceNegotiated: nonceRetryHappened,
        serverNonceUsed: dpopNonce,
        clientAssertionDecoded: decodeJwt(clientAssertion),
        dpopProofDecoded: decodeJwt(dpopProof),
        clientDpopThumbprint: client.dpopThumbprint,
        tokenResponse: {
          ...tokenResult,
          decodedAccessToken: decodeJwt(tokenResult.access_token)
        }
      });
    }

    // Step 2: Automated B2B Bank API Call
    if (method === 'POST' && pathname === '/api/s2s/run-b2b-call') {
      if (!client.activeToken) {
        return sendJson(res, 400, { error: 'Please acquire a M2M token first.' });
      }

      const body = await parseBody(req);
      const action = body.action || 'treasury';
      const withNonce = !!body.enforceNonce;

      let endpoint, httpMethod, requestPayload = null;

      if (action === 'treasury') {
        endpoint = '/b2b-api/treasury/positions';
        httpMethod = 'GET';
      } else if (action === 'payroll') {
        endpoint = '/b2b-api/payroll/execute-batch';
        httpMethod = 'POST';
        requestPayload = { totalAmount: 184500.00, employeeCount: 45 };
      } else if (action === 'fx') {
        endpoint = '/b2b-api/fx/quote?pair=EUR/USD&amount=2500000';
        httpMethod = 'GET';
      }

      const targetUrl = `${BASE_URL}${endpoint}`;
      const ath = sha256Base64Url(client.activeToken.access_token);

      // Create DPoP Proof
      let resourceNonce = client.lastRsNonce || null;
      let dpopProof = client.createDPoPProof(httpMethod, targetUrl, ath, resourceNonce);

      const mockReq = {
        method: httpMethod,
        path: endpoint.split('?')[0],
        protocol: 'http',
        headers: {
          authorization: `DPoP ${client.activeToken.access_token}`,
          dpop: dpopProof
        },
        get: () => `localhost:${PORT}`,
        originalUrl: endpoint
      };

      let nonceRetryHappened = false;
      let authContext;

      try {
        authContext = bank.authenticateRequest(mockReq, { enforceNonce: withNonce });
      } catch (authErr) {
        if (authErr.code === 'use_dpop_nonce') {
          // Automatic Client Nonce Negotiation
          nonceRetryHappened = true;
          client.lastRsNonce = authErr.dpopNonce;
          resourceNonce = authErr.dpopNonce;
          dpopProof = client.createDPoPProof(httpMethod, targetUrl, ath, resourceNonce);
          mockReq.headers.dpop = dpopProof;
          authContext = bank.authenticateRequest(mockReq, { enforceNonce: false });
        } else {
          throw authErr;
        }
      }

      let bankResult;
      if (action === 'treasury') {
        bankResult = bank.getTreasuryPositions(authContext);
      } else if (action === 'payroll') {
        bankResult = bank.executePayrollBatch(requestPayload, authContext);
      } else if (action === 'fx') {
        bankResult = bank.getFxQuote('EUR/USD', 2500000, authContext);
      }

      return sendJson(res, 200, {
        success: true,
        action,
        endpoint,
        method: httpMethod,
        nonceNegotiated: nonceRetryHappened,
        resourceNonceUsed: resourceNonce,
        dpopProofDecoded: decodeJwt(dpopProof),
        ath,
        bankResponse: bankResult
      });
    }

    // Step 3: Server-to-Server Threat Simulation
    if (method === 'POST' && pathname === '/api/s2s/attack') {
      if (!client.activeToken) {
        return sendJson(res, 400, { error: 'Please acquire an M2M token first to test attacks.' });
      }

      const body = await parseBody(req);
      const attackType = body.attackType; // 'exfiltrated_bearer' | 'rogue_service_key' | 'stale_nonce'

      if (attackType === 'exfiltrated_bearer') {
        // Attacker dumps server memory / logs, finds the M2M access token, and calls the treasury API with Bearer
        try {
          const mockReq = {
            method: 'GET',
            path: '/b2b-api/treasury/positions',
            protocol: 'http',
            headers: {
              authorization: `Bearer ${client.activeToken.access_token}`
            },
            get: () => `localhost:${PORT}`,
            originalUrl: '/b2b-api/treasury/positions'
          };
          bank.authenticateRequest(mockReq);
          return sendJson(res, 200, { attackSucceeded: true, message: 'Vulnerability: Bank accepted Bearer token!' });
        } catch (e) {
          return sendJson(res, 200, {
            attackSucceeded: false,
            blocked: true,
            attackType: 'Exfiltrated Token Replayed as Bearer',
            error: e.message,
            audit: e.audit,
            explanation: '🛡️ FAPI DEFENSE: Even though the M2M access token was leaked from server logs, the Bank B2B Gateway completely rejects Bearer authentication. Only DPoP sender-constrained requests are accepted.'
          });
        }
      }

      if (attackType === 'rogue_service_key') {
        // Attacker generates their own keypair, creates a DPoP proof, and presents the stolen high-privilege M2M token
        const attackerKey = generateECKeyPair();
        const attackerThumbprint = computeJwkThumbprint(attackerKey.jwkPublic);
        const ath = sha256Base64Url(client.activeToken.access_token);

        const attackerProof = createDPoPProof({
          htm: 'POST',
          htu: `${BASE_URL}/b2b-api/payroll/execute-batch`,
          ath,
          privateKey: attackerKey.privateKey,
          jwkPublic: attackerKey.jwkPublic
        });

        try {
          const mockReq = {
            method: 'POST',
            path: '/b2b-api/payroll/execute-batch',
            protocol: 'http',
            headers: {
              authorization: `DPoP ${client.activeToken.access_token}`,
              dpop: attackerProof
            },
            get: () => `localhost:${PORT}`,
            originalUrl: '/b2b-api/payroll/execute-batch'
          };
          bank.authenticateRequest(mockReq);
          return sendJson(res, 200, { attackSucceeded: true, message: 'Vulnerability: Rogue service bypassed key binding!' });
        } catch (e) {
          return sendJson(res, 200, {
            attackSucceeded: false,
            blocked: true,
            attackType: 'Rogue Service with Stolen High-Privilege Token',
            attackerThumbprint,
            legitimateThumbprint: client.dpopThumbprint,
            error: e.message,
            audit: e.audit,
            explanation: '🛡️ SENDER-CONSTRAINING DEFENSE: The corporate payroll batch call was rejected because the presenter\'s key thumbprint does not match the token\'s bound "cnf.jkt". The stolen high-privilege corporate token is unusable without the ERP\'s secure hardware private key.'
          });
        }
      }

      if (attackType === 'stale_nonce') {
        // Attacker attempts to replay an old pre-computed DPoP proof with an expired or missing server nonce
        const ath = sha256Base64Url(client.activeToken.access_token);
        const proofWithBogusNonce = client.createDPoPProof(
          'POST',
          `${BASE_URL}/b2b-api/payroll/execute-batch`,
          ath,
          'as_nonce_stale_or_forged_9999'
        );

        try {
          const mockReq = {
            method: 'POST',
            path: '/b2b-api/payroll/execute-batch',
            protocol: 'http',
            headers: {
              authorization: `DPoP ${client.activeToken.access_token}`,
              dpop: proofWithBogusNonce
            },
            get: () => `localhost:${PORT}`,
            originalUrl: '/b2b-api/payroll/execute-batch'
          };
          bank.authenticateRequest(mockReq, { enforceNonce: true });
          return sendJson(res, 200, { attackSucceeded: true, message: 'Vulnerability: Bogus nonce accepted!' });
        } catch (e) {
          return sendJson(res, 200, {
            attackSucceeded: false,
            blocked: true,
            attackType: 'Pre-computed Proof with Stale / Forged Nonce',
            error: e.message,
            audit: e.audit,
            explanation: '🛡️ DPoP NONCE CHALLENGE DEFENSE: The bank enforced server-side fresh nonces. Pre-computed proofs or delayed replays are rejected, forcing real-time proof generation.'
          });
        }
      }

      return sendJson(res, 400, { error: 'Unknown attack type' });
    }

    sendJson(res, 404, { error: 'Not found', path: pathname });
  } catch (err) {
    console.error('S2S Server Error:', err);
    sendJson(res, 500, { error: 'server_error', message: err.message });
  }
});

server.listen(PORT, () => {
  console.log(`====================================================`);
  console.log(`  FAPI 2.0 Server-to-Server (M2M) Showcase`);
  console.log(`  Running at: ${BASE_URL}`);
  console.log(`  Open in browser: ${BASE_URL}`);
  console.log(`====================================================`);
});
