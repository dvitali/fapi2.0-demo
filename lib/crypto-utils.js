const crypto = require('crypto');

/**
 * Base64URL encode a buffer or string
 */
function base64urlEncode(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(input, typeof input === 'string' ? 'utf8' : undefined);
  return buf.toString('base64url');
}

/**
 * Base64URL decode to string or Buffer
 */
function base64urlDecode(str, asBuffer = false) {
  const buf = Buffer.from(str, 'base64url');
  return asBuffer ? buf : buf.toString('utf8');
}

/**
 * Compute SHA-256 hash
 */
function sha256(data) {
  return crypto.createHash('sha256').update(data).digest();
}

/**
 * Compute base64url(sha256(data))
 */
function sha256Base64Url(data) {
  return base64urlEncode(sha256(data));
}

/**
 * Generate an EC P-256 Key Pair (ES256)
 */
function generateECKeyPair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1'
  });

  const jwkPublic = publicKey.export({ format: 'jwk' });
  const jwkPrivate = privateKey.export({ format: 'jwk' });

  return {
    privateKey,
    publicKey,
    jwkPublic: {
      kty: jwkPublic.kty,
      crv: jwkPublic.crv,
      x: jwkPublic.x,
      y: jwkPublic.y
    },
    jwkPrivate
  };
}

/**
 * Compute RFC 7638 JWK Thumbprint (jkt)
 * For EC key, canonical JSON has sorted keys: crv, kty, x, y
 */
function computeJwkThumbprint(jwk) {
  let canonicalJson;
  if (jwk.kty === 'EC') {
    canonicalJson = JSON.stringify({
      crv: jwk.crv,
      kty: jwk.kty,
      x: jwk.x,
      y: jwk.y
    });
  } else if (jwk.kty === 'RSA') {
    canonicalJson = JSON.stringify({
      e: jwk.e,
      kty: jwk.kty,
      n: jwk.n
    });
  } else {
    throw new Error('Unsupported key type for thumbprint: ' + jwk.kty);
  }
  return sha256Base64Url(canonicalJson);
}

/**
 * Create a signed JWT using ES256
 */
function signJwt(header, payload, privateKey) {
  const encHeader = base64urlEncode(JSON.stringify(header));
  const encPayload = base64urlEncode(JSON.stringify(payload));
  const signingInput = `${encHeader}.${encPayload}`;

  const keyObj = privateKey.export ? privateKey : crypto.createPrivateKey({ key: privateKey, format: 'jwk' });
  const signature = crypto.sign('SHA256', Buffer.from(signingInput), {
    key: keyObj,
    dsaEncoding: 'ieee-p1363'
  });

  const encSignature = base64urlEncode(signature);
  return `${signingInput}.${encSignature}`;
}

/**
 * Decode a JWT without verification (for inspection)
 */
function decodeJwt(jwt) {
  if (!jwt || typeof jwt !== 'string') return null;
  const parts = jwt.split('.');
  if (parts.length !== 3) return null;

  try {
    const header = JSON.parse(base64urlDecode(parts[0]));
    const payload = JSON.parse(base64urlDecode(parts[1]));
    return {
      header,
      payload,
      signature: parts[2],
      raw: { header: parts[0], payload: parts[1], signature: parts[2] }
    };
  } catch (e) {
    return null;
  }
}

/**
 * Verify a JWT using ES256 and a public key (KeyObject or JWK)
 */
function verifyJwt(jwt, publicKey) {
  const parts = jwt.split('.');
  if (parts.length !== 3) {
    throw new Error('Malformed JWT: must have 3 segments');
  }

  const signingInput = `${parts[0]}.${parts[1]}`;
  const signature = base64urlDecode(parts[2], true);

  const keyObj = publicKey.export ? publicKey : crypto.createPublicKey({ key: publicKey, format: 'jwk' });
  const isValid = crypto.verify('SHA256', Buffer.from(signingInput), {
    key: keyObj,
    dsaEncoding: 'ieee-p1363'
  }, signature);

  if (!isValid) {
    throw new Error('Invalid JWT signature');
  }

  const header = JSON.parse(base64urlDecode(parts[0]));
  const payload = JSON.parse(base64urlDecode(parts[1]));

  return { header, payload };
}

/**
 * Generate PKCE Code Verifier and Code Challenge (RFC 7636)
 */
function generatePKCE() {
  const code_verifier = base64urlEncode(crypto.randomBytes(32));
  const code_challenge = sha256Base64Url(code_verifier);
  return {
    code_verifier,
    code_challenge,
    code_challenge_method: 'S256'
  };
}

/**
 * Create a DPoP Proof JWT (RFC 9449)
 * @param {Object} options
 * @param {string} options.htm HTTP Method (e.g. 'POST', 'GET')
 * @param {string} options.htu HTTP Target URI without query or fragment
 * @param {string} [options.ath] Access Token Hash base64url(sha256(accessToken))
 * @param {string} [options.nonce] Server-provided DPoP nonce
 * @param {Object} options.privateKey DPoP private key
 * @param {Object} options.jwkPublic DPoP public JWK
 */
function createDPoPProof({ htm, htu, ath, nonce, privateKey, jwkPublic }) {
  const header = {
    typ: 'dpop+jwt',
    alg: 'ES256',
    jwk: {
      kty: jwkPublic.kty,
      crv: jwkPublic.crv,
      x: jwkPublic.x,
      y: jwkPublic.y
    }
  };

  const payload = {
    jti: crypto.randomUUID(),
    htm: htm.toUpperCase(),
    htu: htu.split('?')[0].split('#')[0],
    iat: Math.floor(Date.now() / 1000)
  };

  if (ath) payload.ath = ath;
  if (nonce) payload.nonce = nonce;

  return signJwt(header, payload, privateKey);
}

/**
 * Verify a DPoP Proof JWT (RFC 9449)
 */
function verifyDPoPProof(dpopJwt, expectedHtm, expectedHtu, expectedAccessToken = null) {
  const decoded = decodeJwt(dpopJwt);
  if (!decoded) {
    throw new Error('Malformed DPoP header: not a valid JWT');
  }

  const { header, payload } = decoded;

  // 1. Validate header typ and alg
  if (header.typ !== 'dpop+jwt') {
    throw new Error(`Invalid DPoP header typ: expected 'dpop+jwt', received '${header.typ}'`);
  }
  if (header.alg !== 'ES256') {
    throw new Error(`Unsupported DPoP alg: expected 'ES256', received '${header.alg}'`);
  }
  if (!header.jwk || header.jwk.kty !== 'EC') {
    throw new Error('DPoP header missing valid EC JWK');
  }

  // 2. Verify signature using embedded JWK
  verifyJwt(dpopJwt, header.jwk);

  // 3. Compute JWK thumbprint
  const jkt = computeJwkThumbprint(header.jwk);

  // 4. Validate payload claims
  if (!payload.jti) {
    throw new Error('DPoP proof missing "jti" claim');
  }
  if (!payload.iat) {
    throw new Error('DPoP proof missing "iat" claim');
  }

  // Freshness check: within 5 minutes
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - payload.iat) > 300) {
    throw new Error('DPoP proof has expired or iat is skewed (> 300s)');
  }

  // Validate HTTP method (case-insensitive)
  if (!payload.htm || payload.htm.toUpperCase() !== expectedHtm.toUpperCase()) {
    throw new Error(`DPoP htm mismatch: expected '${expectedHtm.toUpperCase()}', received '${payload.htm}'`);
  }

  // Validate HTTP URI (ignoring query/hash)
  const cleanExpectedHtu = expectedHtu.split('?')[0].split('#')[0];
  const cleanPayloadHtu = (payload.htu || '').split('?')[0].split('#')[0];
  if (cleanPayloadHtu !== cleanExpectedHtu) {
    throw new Error(`DPoP htu mismatch: expected '${cleanExpectedHtu}', received '${cleanPayloadHtu}'`);
  }

  // If token is bound, validate ath (Access Token Hash)
  if (expectedAccessToken) {
    const expectedAth = sha256Base64Url(expectedAccessToken);
    if (!payload.ath) {
      throw new Error('DPoP proof missing required "ath" (access token hash) claim for resource request');
    }
    if (payload.ath !== expectedAth) {
      throw new Error(`DPoP ath mismatch: expected '${expectedAth}', received '${payload.ath}'`);
    }
  }

  return {
    header,
    payload,
    jwk: header.jwk,
    jkt
  };
}

module.exports = {
  base64urlEncode,
  base64urlDecode,
  sha256,
  sha256Base64Url,
  generateECKeyPair,
  computeJwkThumbprint,
  signJwt,
  decodeJwt,
  verifyJwt,
  generatePKCE,
  createDPoPProof,
  verifyDPoPProof
};
