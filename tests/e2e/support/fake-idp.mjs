import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { createServer } from 'node:http';

const issuer = 'http://id.localhost:9400';
const organizationA = '9f79d9ee-d735-4673-a80d-c11339f252be';
const organizationB = '3efb1df0-1814-480c-9566-42d339758da8';
const clients = new Map([
  ['consumer-a-client', { secret: 'consumer-a-secret', slug: 'consumer-a', redirect: 'http://downstream-a.localhost:9401/auth/callback' }],
  ['consumer-b-client', { secret: 'consumer-b-secret', slug: 'consumer-b', redirect: 'http://downstream-b.localhost:9402/auth/callback' }],
]);
const transactions = new Map();
const codes = new Map();
const activeSessions = new Map();
const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = publicKey.export({ format: 'jwk' });
jwk.alg = 'RS256';
jwk.use = 'sig';
jwk.kid = 'e2e-key';

const base64url = (value) => Buffer.from(value).toString('base64url');
const jwt = (claims, typ = 'at+jwt') => {
  const header = base64url(JSON.stringify({ alg: 'RS256', kid: 'e2e-key', typ }));
  const payload = base64url(JSON.stringify(claims));
  const signature = sign('RSA-SHA256', Buffer.from(`${header}.${payload}`), privateKey).toString('base64url');
  return `${header}.${payload}.${signature}`;
};
const body = async (request) => {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  return Buffer.concat(chunks).toString();
};
const sendJson = (response, status, value) => {
  response.writeHead(status, { 'content-type': 'application/json' });
  response.end(JSON.stringify(value));
};

export async function startFakeIdp() {
  const server = createServer(async (request, response) => {
    const url = new URL(request.url, issuer);
    if (url.pathname === '/.well-known/openid-configuration') {
      return sendJson(response, 200, {
        issuer,
        authorization_endpoint: `${issuer}/sso/authorize`,
        token_endpoint: `${issuer}/api/sso/token`,
        jwks_uri: `${issuer}/.well-known/jwks.json`,
      });
    }
    if (url.pathname === '/.well-known/jwks.json') return sendJson(response, 200, { keys: [jwk] });
    if (url.pathname === '/sso/authorize') {
      const client = clients.get(url.searchParams.get('client_id'));
      const org = url.searchParams.get('organization_context_id');
      if (!client || url.searchParams.get('redirect_uri') !== client.redirect || ![organizationA, organizationB].includes(org)) {
        response.writeHead(403, { 'content-type': 'text/plain' });
        return response.end('authorization rejected');
      }
      const transactionId = randomBytes(16).toString('hex');
      transactions.set(transactionId, Object.fromEntries(url.searchParams));
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      return response.end(`<!doctype html><title>Test IdP</title><h1>Authorize ${client.slug}</h1>
        <p data-testid="organization">${org}</p>
        <form method="post" action="/continue"><input type="hidden" name="transaction" value="${transactionId}"><button>Continue as E2E User</button></form>
        <form method="post" action="/continue"><input type="hidden" name="transaction" value="${transactionId}"><input type="hidden" name="tamper" value="organization"><button>Tamper organization claim</button></form>`);
    }
    if (url.pathname === '/continue' && request.method === 'POST') {
      const form = new URLSearchParams(await body(request));
      const tx = transactions.get(form.get('transaction'));
      if (!tx) return sendJson(response, 400, { error: 'invalid_transaction' });
      transactions.delete(form.get('transaction'));
      const code = randomBytes(24).toString('hex');
      codes.set(code, { ...tx, tokenOrganization: form.get('tamper') === 'organization' ? organizationB : tx.organization_context_id });
      const callback = new URL(tx.redirect_uri);
      callback.searchParams.set('code', code);
      callback.searchParams.set('state', tx.state);
      callback.searchParams.set('iss', issuer);
      response.writeHead(302, { location: callback.toString() });
      return response.end();
    }
    if (url.pathname === '/api/sso/token' && request.method === 'POST') {
      const form = new URLSearchParams(await body(request));
      const grant = codes.get(form.get('code'));
      const client = clients.get(form.get('client_id'));
      const challenge = createHash('sha256').update(form.get('code_verifier') ?? '').digest('base64url');
      if (!grant || !client || client.secret !== form.get('client_secret') || grant.redirect_uri !== form.get('redirect_uri') || challenge !== grant.code_challenge) {
        return sendJson(response, 400, { error: 'invalid_grant' });
      }
      codes.delete(form.get('code'));
      const now = Math.floor(Date.now() / 1000);
      const sid = `e2e-${client.slug}-${randomBytes(12).toString('hex')}`;
      activeSessions.set(client.slug, sid);
      return sendJson(response, 200, {
        access_token: jwt({ iss: issuer, aud: client.slug, sub: 'e2e-user', sid, iat: now, exp: now + 900, organization_context_id: grant.tokenOrganization }),
        id_token: jwt({ iss: issuer, aud: grant.client_id, sub: 'e2e-user', iat: now, exp: now + 900, nonce: grant.nonce }, 'JWT'),
        token_type: 'Bearer',
        expires_in: 900,
      });
    }
    if (url.pathname === '/api/sso/me/permissions') {
      const token = (request.headers.authorization ?? '').replace(/^Bearer /, '');
      const payload = token.split('.')[1];
      if (!payload) return sendJson(response, 401, { message: 'Unauthenticated.' });
      const claims = JSON.parse(Buffer.from(payload, 'base64url').toString());
      if (url.searchParams.get('organization_id') !== claims.organization_context_id) {
        return sendJson(response, 403, { code: 'CONTEXT_UNAVAILABLE' });
      }
      return sendJson(response, 200, {
        permissions: [`${claims.aud}.dashboard.view`],
        roles: ['member'],
        service_access: { [claims.aud]: { enabled: true } },
        authoritative: true,
      });
    }
    response.writeHead(404).end();
  });
  await new Promise((resolve) => server.listen(9400, '127.0.0.1', resolve));
  return {
    close: () => new Promise((resolve) => server.close(resolve)),
    organizationA,
    organizationB,
    async deliverBackChannelLogout() {
      const now = Math.floor(Date.now() / 1000);
      const targets = [
        ['consumer-a', 'consumer-a-client', 'http://downstream-a.localhost:9401/auth/backchannel-logout'],
        ['consumer-b', 'consumer-b-client', 'http://downstream-b.localhost:9402/auth/backchannel-logout'],
      ];

      return Promise.all(targets.map(async ([service, audience, endpoint]) => {
        const logoutToken = jwt({
          iss: issuer,
          aud: audience,
          sub: 'e2e-user',
          sid: activeSessions.get(service),
          jti: randomBytes(16).toString('hex'),
          iat: now,
          exp: now + 120,
          events: { 'http://schemas.openid.net/event/backchannel-logout': {} },
        });
        const response = await fetch(endpoint, {
          method: 'POST',
          headers: { 'content-type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ logout_token: logoutToken }),
        });
        return { audience: service, status: response.status };
      }));
    },
  };
}
