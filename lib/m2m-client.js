const crypto = require('crypto');
const {
  generateECKeyPair,
  computeJwkThumbprint,
  signJwt,
  createDPoPProof,
  sha256Base64Url,
  decodeJwt
} = require('./crypto-utils');

/**
 * Enterprise B2B / M2M Client (Corporate ERP System)
 * Fully automated: Signs assertions, handles DPoP proofs, and auto-negotiates DPoP-Nonce
 */
class M2MClient {
  constructor(baseUrl) {
    this.baseUrl = baseUrl;
    this.clientId = 'erp-acme-corp-001';
    this.clientName = 'Acme Corp Automated Treasury ERP';
    this.scopes = 'corporate:treasury corporate:payments corporate:fx-rates';

    this.initKeys();
    this.activeToken = null;
    this.lastAsNonce = null;
    this.lastRsNonce = null;
  }

  initKeys() {
    // 1. Client Private Key for private_key_jwt authentication (RFC 7523)
    this.authKey = generateECKeyPair();
    this.authThumbprint = computeJwkThumbprint(this.authKey.jwkPublic);

    // 2. Client DPoP Key Pair for sender-constrained token proofs (RFC 9449)
    this.dpopKey = generateECKeyPair();
    this.dpopThumbprint = computeJwkThumbprint(this.dpopKey.jwkPublic);

    this.activeToken = null;
  }

  createClientAssertion(endpointUrl) {
    const now = Math.floor(Date.now() / 1000);
    const header = { typ: 'JWT', alg: 'ES256' };
    const payload = {
      iss: this.clientId,
      sub: this.clientId,
      aud: endpointUrl,
      jti: crypto.randomUUID(),
      iat: now,
      exp: now + 300
    };
    return signJwt(header, payload, this.authKey.privateKey);
  }

  createDPoPProof(method, url, ath = null, nonce = null) {
    return createDPoPProof({
      htm: method,
      htu: url,
      ath,
      nonce,
      privateKey: this.dpopKey.privateKey,
      jwkPublic: this.dpopKey.jwkPublic
    });
  }
}

module.exports = M2MClient;
