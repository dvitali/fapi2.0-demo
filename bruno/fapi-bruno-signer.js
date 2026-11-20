const crypto = require('crypto');
const keys = require('./m2m-bruno-keys.json');

function b64url(input) {
  return Buffer.from(input).toString('base64url');
}

function signJwt(header, payload, privPem) {
  const encHeader = b64url(JSON.stringify(header));
  const encPayload = b64url(JSON.stringify(payload));
  const data = encHeader + '.' + encPayload;
  const sig = crypto.sign('SHA256', Buffer.from(data), {
    key: privPem,
    dsaEncoding: 'ieee-p1363'
  });
  return data + '.' + b64url(sig);
}

function createClientAssertion(clientId, endpointUrl) {
  const now = Math.floor(Date.now() / 1000);
  return signJwt(
    { typ: 'JWT', alg: 'ES256' },
    {
      iss: clientId,
      sub: clientId,
      aud: endpointUrl,
      jti: crypto.randomUUID(),
      iat: now,
      exp: now + 300
    },
    keys.authKey.privPem
  );
}

function createDPoPProof(method, endpointUrl, accessToken = null, nonce = null) {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    jti: crypto.randomUUID(),
    htm: method.toUpperCase(),
    htu: endpointUrl,
    iat: now
  };

  if (accessToken) {
    payload.ath = crypto.createHash('sha256').update(accessToken).digest('base64url');
  }

  if (nonce) {
    payload.nonce = nonce;
  }

  return signJwt(
    {
      typ: 'dpop+jwt',
      alg: 'ES256',
      jwk: {
        kty: 'EC',
        crv: 'P-256',
        x: keys.dpopKey.jwk.x,
        y: keys.dpopKey.jwk.y
      }
    },
    payload,
    keys.dpopKey.privPem
  );
}

module.exports = {
  createClientAssertion,
  createDPoPProof
};
