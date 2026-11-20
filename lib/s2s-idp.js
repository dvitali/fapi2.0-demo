const crypto = require('crypto');
const {
  generateECKeyPair,
  computeJwkThumbprint,
  signJwt,
  verifyJwt,
  decodeJwt,
  verifyDPoPProof
} = require('./crypto-utils');

/**
 * FAPI 2.0 Authorization Server for Machine-to-Machine (M2M) / Server-to-Server
 * Implements:
 * - RFC 6749 Section 4.4 (Client Credentials Grant)
 * - RFC 7523 (private_key_jwt client authentication - NO SHARED SECRETS)
 * - RFC 9449 (DPoP sender-constrained tokens for M2M)
 * - RFC 9449 Section 8 (DPoP-Nonce server challenges)
 */
class ServerToServerIdP {
  constructor(baseUrl) {
    this.baseUrl = baseUrl;
    this.issuer = baseUrl;

    // AS ES256 Signing Keypair
    this.asKey = generateECKeyPair();
    this.asKeyId = 'as-s2s-key-' + Date.now().toString(36);

    // Active server nonces (for DPoP-Nonce challenge enforcement)
    this.activeNonces = new Map(); // nonce -> expiry timestamp
    this.seenDpopJti = new Set();  // anti-replay

    // Registered B2B Corporate Clients
    this.registeredClients = new Map();
  }

  registerClient({ clientId, clientName, clientPublicJwk, allowedScopes }) {
    this.registeredClients.set(clientId, {
      clientId,
      clientName,
      clientPublicJwk,
      allowedScopes: allowedScopes || ['corporate:treasury', 'corporate:payments', 'corporate:fx-rates']
    });
  }

  getClient(clientId) {
    return this.registeredClients.get(clientId);
  }

  generateServerNonce() {
    const nonce = 'as_nonce_' + crypto.randomBytes(16).toString('hex');
    this.activeNonces.set(nonce, Date.now() + 60 * 1000); // 60s validity
    return nonce;
  }

  validateServerNonce(nonce) {
    if (!nonce) return false;
    const exp = this.activeNonces.get(nonce);
    if (!exp || Date.now() > exp) {
      this.activeNonces.delete(nonce);
      return false;
    }
    this.activeNonces.delete(nonce); // Single-use challenge
    return true;
  }

  getDiscoveryMetadata() {
    return {
      issuer: this.issuer,
      token_endpoint: `${this.baseUrl}/oauth/token`,
      jwks_uri: `${this.baseUrl}/oauth/jwks.json`,
      grant_types_supported: ['client_credentials'],
      token_endpoint_auth_methods_supported: ['private_key_jwt'],
      token_endpoint_auth_signing_alg_values_supported: ['ES256'],
      dpop_signing_alg_values_supported: ['ES256'],
      scopes_supported: ['corporate:treasury', 'corporate:payments', 'corporate:fx-rates']
    };
  }

  getJwks() {
    return {
      keys: [
        {
          ...this.asKey.jwkPublic,
          kid: this.asKeyId,
          use: 'sig',
          alg: 'ES256'
        }
      ]
    };
  }

  /**
   * Validate private_key_jwt assertion (RFC 7523)
   */
  validateClientAssertion(clientId, clientAssertionType, clientAssertion, endpoint) {
    if (clientAssertionType !== 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer') {
      throw new Error(`Unsupported client_assertion_type: ${clientAssertionType}. FAPI strictly requires 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'`);
    }

    if (!clientAssertion) {
      throw new Error('Missing client_assertion');
    }

    const client = this.getClient(clientId);
    if (!client) {
      throw new Error(`Unregistered B2B client_id: ${clientId}`);
    }

    // If client has a registered public key, verify against it
    // Alternatively, if the JWT includes an X.509 certificate in 'x5c' (RFC 7515), verify the certificate chain
    let verificationKey = client.clientPublicJwk;

    const unverified = decodeJwt(clientAssertion);
    if (unverified && unverified.header && Array.isArray(unverified.header.x5c) && unverified.header.x5c.length > 0) {
      try {
        const leafDer = Buffer.from(unverified.header.x5c[0], 'base64');
        const cert = new crypto.X509Certificate(leafDer);
        
        // In production FAPI: check CA trust root, expiration, revocation (OCSP/CRL), and subject CN
        const nowMs = Date.now();
        if (new Date(cert.validTo).getTime() < nowMs || new Date(cert.validFrom).getTime() > nowMs) {
          throw new Error('Client X.509 certificate has expired or is not yet valid');
        }

        // Use public key extracted directly from the X.509 certificate
        verificationKey = cert.publicKey;
      } catch (certErr) {
        throw new Error(`Failed to validate X.509 certificate from assertion header: ${certErr.message}`);
      }
    }

    const { header, payload } = verifyJwt(clientAssertion, verificationKey);

    if (header.alg !== 'ES256') {
      throw new Error(`Invalid assertion alg: expected ES256, received ${header.alg}`);
    }

    if (payload.iss !== clientId || payload.sub !== clientId) {
      throw new Error(`Client assertion iss/sub must match client_id '${clientId}'`);
    }

    const validAuds = [this.issuer, endpoint];
    const audMatches = Array.isArray(payload.aud)
      ? payload.aud.some(a => validAuds.includes(a))
      : validAuds.includes(payload.aud);

    if (!audMatches) {
      throw new Error(`Client assertion audience mismatch. Expected ${validAuds.join(' or ')}`);
    }

    const now = Math.floor(Date.now() / 1000);
    if (!payload.exp || payload.exp < now) {
      throw new Error('Client assertion has expired');
    }

    return client;
  }

  /**
   * Token endpoint for client_credentials with DPoP & Nonce enforcement
   */
  handleToken(body, dpopHeader, options = {}) {
    const {
      grant_type,
      client_id,
      client_assertion_type,
      client_assertion,
      scope
    } = body;

    const tokenUrl = `${this.baseUrl}/oauth/token`;

    // 1. Validate grant_type
    if (grant_type !== 'client_credentials') {
      const err = new Error(`Unsupported grant_type: '${grant_type}'. Only 'client_credentials' is used in this S2S profile.`);
      err.status = 400;
      throw err;
    }

    // 2. Authenticate B2B Client via private_key_jwt
    const client = this.validateClientAssertion(
      client_id,
      client_assertion_type,
      client_assertion,
      tokenUrl
    );

    // 3. Enforce DPoP proof
    if (!dpopHeader) {
      const err = new Error('Missing required DPoP header. FAPI 2.0 mandates sender-constrained tokens even for server-to-server client_credentials.');
      err.status = 400;
      err.code = 'invalid_dpop_proof';
      throw err;
    }

    // 4. Verify DPoP Proof
    const dpopVerification = verifyDPoPProof(dpopHeader, 'POST', tokenUrl);

    // 5. Enforce DPoP Nonce challenge if enabled
    if (options.enforceNonce) {
      const proofNonce = dpopVerification.payload.nonce;
      if (!proofNonce || !this.validateServerNonce(proofNonce)) {
        const freshNonce = this.generateServerNonce();
        const err = new Error('DPoP proof missing fresh server nonce');
        err.status = 400;
        err.code = 'use_dpop_nonce';
        err.dpopNonce = freshNonce;
        throw err;
      }
    }

    // 6. Anti-replay check
    if (this.seenDpopJti.has(dpopVerification.payload.jti)) {
      const err = new Error(`DPoP JTI replay detected: '${dpopVerification.payload.jti}'`);
      err.status = 400;
      throw err;
    }
    this.seenDpopJti.add(dpopVerification.payload.jti);

    const clientDpopThumbprint = dpopVerification.jkt;

    // 7. Determine authorized scopes
    const requestedScopes = scope ? scope.split(' ') : client.allowedScopes;
    const grantedScopes = requestedScopes.filter(s => client.allowedScopes.includes(s));

    // 8. Issue Sender-Constrained B2B Access Token
    const now = Math.floor(Date.now() / 1000);
    const accessTokenPayload = {
      iss: this.issuer,
      sub: client.clientId,
      aud: `${this.baseUrl}/b2b-api`,
      client_id: client.clientId,
      client_name: client.clientName,
      scope: grantedScopes.join(' '),
      token_usage: 'server_to_server_m2m',
      iat: now,
      exp: now + 1800, // 30 mins
      jti: crypto.randomUUID(),
      // FAPI Sender-Constraining:
      cnf: {
        jkt: clientDpopThumbprint
      }
    };

    const accessTokenHeader = {
      typ: 'at+jwt',
      alg: 'ES256',
      kid: this.asKeyId
    };

    const accessToken = signJwt(accessTokenHeader, accessTokenPayload, this.asKey.privateKey);

    return {
      access_token: accessToken,
      token_type: 'DPoP',
      expires_in: 1800,
      scope: grantedScopes.join(' '),
      dpop_jkt: clientDpopThumbprint
    };
  }
}

module.exports = ServerToServerIdP;
