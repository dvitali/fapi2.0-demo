const crypto = require('crypto');
const {
  verifyJwt,
  verifyDPoPProof,
  sha256Base64Url
} = require('./crypto-utils');

/**
 * Corporate Wholesale Banking Resource Server (B2B API)
 * Demonstrates FAPI sender-constrained protection for automated server-to-server workloads
 */
class B2BBankResourceServer {
  constructor(asInstance, baseUrl) {
    this.as = asInstance;
    this.baseUrl = baseUrl;
    this.seenDpopJti = new Set();
    this.activeNonces = new Map();

    // Corporate Treasury Mock Data
    this.treasuryPositions = [
      {
        accountNumber: 'CORP-EUR-88301',
        name: 'Acme Operations Treasury EUR',
        currency: 'EUR',
        availableLiquidity: 4250000.00,
        reservedForPayroll: 200000.00,
        interestYield: '3.65% p.a.',
        status: 'OPEN'
      },
      {
        accountNumber: 'CORP-USD-99214',
        name: 'Acme US Treasury Reserve',
        currency: 'USD',
        availableLiquidity: 3100000.00,
        reservedForPayroll: 0.00,
        interestYield: '5.10% p.a.',
        status: 'OPEN'
      }
    ];

    this.payrollBatches = [];
  }

  generateResourceNonce() {
    const nonce = 'rs_nonce_' + crypto.randomBytes(16).toString('hex');
    this.activeNonces.set(nonce, Date.now() + 60 * 1000);
    return nonce;
  }

  validateResourceNonce(nonce) {
    if (!nonce) return false;
    const exp = this.activeNonces.get(nonce);
    if (!exp || Date.now() > exp) {
      this.activeNonces.delete(nonce);
      return false;
    }
    this.activeNonces.delete(nonce);
    return true;
  }

  /**
   * B2B DPoP Authentication & Audit Middleware
   */
  authenticateRequest(req, options = {}) {
    const authHeader = req.headers['authorization'];
    const dpopHeader = req.headers['dpop'];

    const host = (typeof req.get === 'function' ? req.get('host') : (req.headers && req.headers['host'])) || 'localhost:3001';
    const protocol = req.protocol || (req.socket && req.socket.encrypted ? 'https' : 'http');
    const pathOnly = (req.path || req.originalUrl || req.url || '').split('?')[0].split('#')[0];
    const fullUrl = `${protocol}://${host}${pathOnly}`;

    const auditTrail = {
      timestamp: new Date().toISOString(),
      method: req.method,
      url: `${protocol}://${host}${req.originalUrl || req.url || pathOnly}`,
      checks: []
    };

    if (!authHeader) {
      const err = new Error('Missing Authorization header');
      err.status = 401;
      err.audit = auditTrail;
      throw err;
    }

    const [scheme, token] = authHeader.trim().split(/\s+/);
    if (scheme !== 'DPoP') {
      const err = new Error(`Invalid token scheme '${scheme}'. FAPI 2.0 requires 'DPoP <access_token>'. Bearer tokens are prohibited in financial S2S APIs.`);
      err.status = 401;
      err.audit = auditTrail;
      throw err;
    }
    auditTrail.checks.push({ name: 'DPoP Scheme', status: 'PASS', details: 'Used DPoP authorization scheme' });

    if (!dpopHeader) {
      const err = new Error('Missing DPoP proof header. Financial-grade S2S APIs mandate proof-of-possession.');
      err.status = 401;
      err.audit = auditTrail;
      throw err;
    }
    auditTrail.checks.push({ name: 'DPoP Proof Header', status: 'PASS', details: 'DPoP header present' });

    // Verify Access Token signature
    let tokenPayload;
    try {
      const verifiedToken = verifyJwt(token, this.as.asKey.publicKey);
      tokenPayload = verifiedToken.payload;
      auditTrail.checks.push({ name: 'Token Signature', status: 'PASS', details: 'Signed by AS: ' + tokenPayload.iss });
    } catch (e) {
      const err = new Error('Invalid token signature: ' + e.message);
      err.status = 401;
      err.audit = auditTrail;
      throw err;
    }

    // Verify token expiration
    const now = Math.floor(Date.now() / 1000);
    if (tokenPayload.exp && tokenPayload.exp < now) {
      const err = new Error('Access token has expired');
      err.status = 401;
      err.audit = auditTrail;
      throw err;
    }

    // Verify cnf.jkt exists
    if (!tokenPayload.cnf || !tokenPayload.cnf.jkt) {
      const err = new Error('Access token missing sender-constraint "cnf.jkt" claim');
      err.status = 401;
      err.audit = auditTrail;
      throw err;
    }
    auditTrail.checks.push({ name: 'Token cnf.jkt', status: 'PASS', details: 'Bound to thumbprint: ' + tokenPayload.cnf.jkt });

    // Verify DPoP Proof
    const expectedHtm = req.method;
    let dpopVerification;
    try {
      dpopVerification = verifyDPoPProof(dpopHeader, expectedHtm, fullUrl, token);
      auditTrail.checks.push({ name: 'DPoP Proof Signature', status: 'PASS', details: 'ES256 signature verified' });
      auditTrail.checks.push({ name: 'DPoP ath Hash', status: 'PASS', details: 'Matched sha256(access_token)' });
      auditTrail.checks.push({ name: 'DPoP htm/htu Binding', status: 'PASS', details: `${expectedHtm} ${fullUrl}` });
    } catch (e) {
      const err = new Error('DPoP proof verification failed: ' + e.message);
      err.status = 401;
      auditTrail.checks.push({ name: 'DPoP Proof Verification', status: 'FAIL', error: e.message });
      err.audit = auditTrail;
      throw err;
    }

    // Check DPoP Nonce if required
    if (options.enforceNonce) {
      const proofNonce = dpopVerification.payload.nonce;
      if (!proofNonce || !this.validateResourceNonce(proofNonce)) {
        const freshNonce = this.generateResourceNonce();
        const err = new Error('Server nonce required for this sensitive operation');
        err.status = 401;
        err.code = 'use_dpop_nonce';
        err.dpopNonce = freshNonce;
        auditTrail.checks.push({ name: 'DPoP Nonce Challenge', status: 'RETRY_REQUIRED', details: 'Challenged client with fresh nonce' });
        err.audit = auditTrail;
        throw err;
      }
      auditTrail.checks.push({ name: 'DPoP Nonce Verification', status: 'PASS', details: 'Fresh single-use nonce verified' });
    }

    // Anti-replay
    if (this.seenDpopJti.has(dpopVerification.payload.jti)) {
      const err = new Error(`DPoP Replay detected: jti '${dpopVerification.payload.jti}' already consumed`);
      err.status = 401;
      auditTrail.checks.push({ name: 'Anti-Replay JTI', status: 'FAIL', error: err.message });
      err.audit = auditTrail;
      throw err;
    }
    this.seenDpopJti.add(dpopVerification.payload.jti);
    auditTrail.checks.push({ name: 'Anti-Replay JTI', status: 'PASS', details: 'Single-use JTI accepted' });

    // CRITICAL: Presenter key thumbprint must match token cnf.jkt
    if (dpopVerification.jkt !== tokenPayload.cnf.jkt) {
      const err = new Error(`SENDER-CONSTRAINT VIOLATION: Presenter key thumbprint (${dpopVerification.jkt}) does not match token bound cnf.jkt (${tokenPayload.cnf.jkt})!`);
      err.status = 401;
      auditTrail.checks.push({ name: 'Sender-Constraining Match', status: 'FAIL', error: 'Thumbprint mismatch' });
      err.audit = auditTrail;
      throw err;
    }
    auditTrail.checks.push({ name: 'Sender-Constraining Match', status: 'PASS', details: 'Presenter proves possession of private key' });

    return {
      clientId: tokenPayload.client_id,
      clientName: tokenPayload.client_name,
      scope: tokenPayload.scope,
      tokenPayload,
      dpopJkt: dpopVerification.jkt,
      audit: auditTrail
    };
  }

  getTreasuryPositions(authContext) {
    return {
      status: 'success',
      data: this.treasuryPositions,
      authorizedClient: authContext.clientName,
      fapiSecurityAudit: authContext.audit
    };
  }

  executePayrollBatch(batchData, authContext) {
    const totalAmount = batchData.totalAmount || 184500.00;
    const employeeCount = batchData.employeeCount || 45;

    const record = {
      batchId: 'BATCH-PAYROLL-' + Date.now().toString(36).toUpperCase(),
      executedBy: authContext.clientName,
      sourceAccount: 'CORP-EUR-88301',
      totalAmount,
      currency: 'EUR',
      employeeCount,
      timestamp: new Date().toISOString(),
      clearingNetwork: 'SEPA Instant Credit Transfer (SCT Inst)',
      status: 'SETTLED'
    };

    this.payrollBatches.unshift(record);

    return {
      status: 'success',
      payrollBatch: record,
      fapiSecurityAudit: authContext.audit
    };
  }

  getFxQuote(pair = 'EUR/USD', amount = 1000000, authContext) {
    const rate = pair === 'EUR/USD' ? 1.0850 : 0.8520;
    return {
      status: 'success',
      quote: {
        quoteId: 'FXQ-' + crypto.randomUUID().slice(0, 8).toUpperCase(),
        pair,
        baseAmount: amount,
        rate,
        targetAmount: amount * rate,
        expiresInSeconds: 30,
        validUntil: new Date(Date.now() + 30000).toISOString()
      },
      authorizedClient: authContext.clientName,
      fapiSecurityAudit: authContext.audit
    };
  }
}

module.exports = B2BBankResourceServer;
