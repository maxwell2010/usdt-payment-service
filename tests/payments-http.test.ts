import {IPV4_LOOPBACK} from '../src/payments/config.ts';
import assert from 'node:assert/strict';
import {once} from 'node:events';
import {type Server} from 'node:http';
import test from 'node:test';
import {createPaymentsApp, type PaymentHttpStore, type PaymentsHttpOptions} from '../src/payments/http.ts';
import {PaymentStore} from '../src/payments/store.ts';
import {PaymentError, type Invoice} from '../src/payments/types.ts';

const keyA = 'synthetic-project-a-http-api-key';
const keyB = 'synthetic-project-b-http-api-key';
const credentials = (key = keyA) => ({Authorization: `Bearer ${key}`, 'Content-Type': 'application/json'});
const requestBody = (overrides: Record<string, unknown> = {}) => ({userId: 'alice', orderId: 'order-1', chain: 'bsc', amount: '10.5', ...overrides});
const post = (body: unknown = requestBody(), idem = 'request-1', key = keyA): RequestInit => ({method: 'POST', headers: {...credentials(key), 'Idempotency-Key': idem}, body: JSON.stringify(body)});

async function running(store: PaymentHttpStore, options: PaymentsHttpOptions = {}) {
  const server: Server = createPaymentsApp(store, options).listen(0, IPV4_LOOPBACK);
  await once(server, 'listening');
  const base = `http://${IPV4_LOOPBACK}:${(server.address() as {port: number}).port}`;
  return {base, stop: async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  }};
}

async function fixture(options: PaymentsHttpOptions = {}) {
  const store = new PaymentStore(':memory:', Buffer.alloc(32, 11));
  store.createProject({id: 'project-a', apiKey: keyA, webhookUrl: 'https://example.com/payment-a', webhookSecret: 'synthetic-project-a-webhook-secret'});
  store.createProject({id: 'project-b', apiKey: keyB, webhookUrl: 'https://example.com/payment-b', webhookSecret: 'synthetic-project-b-webhook-secret'});
  let clock = 1_800_000_000_000;
  for (const [project, start] of [['project-a', 1], ['project-b', 101]] as const) {
    store.addAddresses(project, 'bsc', Array.from({length: 8}, (_, index) => '0x' + (start + index).toString(16).padStart(40, '0')), clock);
    store.addAddresses(project, 'tron', ['41' + start.toString(16).padStart(40, '0')], clock);
  }
  for (const chain of ['bsc', 'tron'] as const) store.initializeCursor(chain, 100, 'a'.repeat(64), clock);
  const server = await running(store, {now: () => clock, ...options});
  return {...server, store, advance: (ms: number) => {clock += ms;}, stop: async () => {await server.stop(); store.close();}};
}

test('payment HTTP authenticates project backends and scopes invoice reads to project plus user', async () => {
  const f = await fixture();
  try {
    const invalidCredentials: Record<string, string>[] = [{}, {Authorization: 'Basic abc'}, {Authorization: 'Bearer unknown'}, {Authorization: `Bearer ${keyA}, Bearer ${keyB}`}];
    for (const headers of invalidCredentials) {
      const response = await fetch(f.base + '/v1/invoices/missing?userId=alice', {headers});
      assert.equal(response.status, 401);
      assert.equal(response.headers.get('WWW-Authenticate'), 'Bearer');
    }
    assert.equal((await fetch(f.base + `/v1/invoices/missing?userId=alice&apiKey=${keyA}`)).status, 401);
    const created = await fetch(f.base + '/v1/invoices', post());
    assert.equal(created.status, 201);
    const invoice = (await created.json()).invoice as Invoice;
    assert.equal(invoice.projectId, 'project-a');
    assert.equal(invoice.userId, 'alice');
    assert.equal(invoice.amountAtomic, '10500000000000000000');
    const own = await fetch(f.base + `/v1/invoices/${invoice.id}?userId=alice`, {headers: credentials()});
    assert.equal(own.status, 200);
    assert.deepEqual((await own.json()).invoice, invoice);
    for (const [user, key] of [['bob', keyA], ['alice', keyB], ['bob', keyB]]) {
      const foreign = await fetch(f.base + `/v1/invoices/${invoice.id}?userId=${user}`, {headers: credentials(key)});
      assert.equal(foreign.status, 404);
      assert.deepEqual(await foreign.json(), {error: {code: 'INVOICE_NOT_FOUND'}});
    }
    for (const query of ['', '?userId=alice&userId=bob', '?userId=alice&projectId=project-b', '?userId=alice&apiKey=hidden', '?userId[]=alice', '?userId=alice%27%20OR%201=1']) {
      assert.equal((await fetch(f.base + `/v1/invoices/${invoice.id}${query}`, {headers: credentials()})).status, 400, query);
    }
    assert.equal((await fetch(f.base + '/v1/invoices/%ZZ?userId=alice', {headers: credentials()})).status, 400);
    for (const extra of [{projectId: 'project-b'}, {apiKey: keyB}, {idempotencyKey: 'in-body'}, {address: invoice.address}]) {
      assert.equal((await fetch(f.base + '/v1/invoices', post(requestBody(extra), 'forged'))).status, 400);
    }
    assert.equal((await fetch(f.base + '/v1/invoices?apiKey=hidden', post())).status, 400);
    f.store.db.prepare('UPDATE projects SET enabled=0 WHERE id=?').run('project-a');
    assert.equal((await fetch(f.base + `/v1/invoices/${invoice.id}?userId=alice`, {headers: credentials()})).status, 401);
  } finally {await f.stop();}
});

test('payment HTTP preserves idempotency conflicts and rolling user quotas through real store', async () => {
  const f = await fixture();
  try {
    const first = await fetch(f.base + '/v1/invoices', post());
    const original = (await first.json()).invoice;
    const repeat = await fetch(f.base + '/v1/invoices', post());
    assert.equal(repeat.status, 200);
    assert.equal((await repeat.json()).invoice.id, original.id);
    const conflict = await fetch(f.base + '/v1/invoices', post(requestBody({amount: '20'})));
    assert.equal(conflict.status, 409);
    assert.deepEqual(await conflict.json(), {error: {code: 'idempotency_conflict'}});
    assert.equal((await fetch(f.base + '/v1/invoices', post(requestBody(), 'another-key'))).status, 409);
    for (let index = 2; index <= 3; index++) {
      assert.equal((await fetch(f.base + '/v1/invoices', post(requestBody({orderId: `order-${index}`}), `request-${index}`))).status, 201);
    }
    const limited = await fetch(f.base + '/v1/invoices', post(requestBody({orderId: 'order-4'}), 'request-4'));
    assert.equal(limited.status, 429);
    assert.equal(limited.headers.get('Retry-After'), '1800');
    assert.deepEqual(await limited.json(), {error: {code: 'invoice_rate_limit'}});
    assert.equal((await fetch(f.base + '/v1/invoices', post())).status, 200, 'idempotent retry remains usable at quota');
    assert.equal((await fetch(f.base + '/v1/invoices', post(requestBody({userId: 'bob', orderId: 'bob-1'}), 'bob-1'))).status, 201);
    assert.equal((await fetch(f.base + '/v1/invoices', post(requestBody(), 'request-1', keyB))).status, 201);
    f.advance(30 * 60_000);
    assert.equal((await fetch(f.base + '/v1/invoices', post(requestBody({orderId: 'order-4'}), 'request-4'))).status, 201);
    const expired = await fetch(f.base + `/v1/invoices/${original.id}?userId=alice`, {headers: credentials()});
    assert.equal((await expired.json()).invoice.status, 'expired');
  } finally {await f.stop();}
});

test('payment HTTP rejects malformed, oversized and unbounded invoice input before allocation', async () => {
  const f = await fixture();
  try {
    for (const amount of [1, 1.2, null, '0', '0.000000', '-1', 'NaN', 'Infinity', '1e2', '01', '.1', '1.', '1.0000001', '1000000.000001', '1000001', '9'.repeat(100)]) {
      assert.equal((await fetch(f.base + '/v1/invoices', post(requestBody({amount})))).status, 400, String(amount));
    }
    for (const body of [[], null, {}, requestBody({userId: 'алиса'}), requestBody({userId: 'x'.repeat(129)}), requestBody({orderId: '../order'}), requestBody({chain: 'ethereum'}), requestBody({amount: undefined})]) {
      assert.equal((await fetch(f.base + '/v1/invoices', post(body))).status, 400);
    }
    for (const idem of ['', 'bad key', 'x'.repeat(129)]) {
      assert.equal((await fetch(f.base + '/v1/invoices', post(requestBody(), idem))).status, 400);
    }
    const noIdem = await fetch(f.base + '/v1/invoices', {method: 'POST', headers: credentials(), body: JSON.stringify(requestBody())});
    assert.equal(noIdem.status, 400);
    const malformed = await fetch(f.base + '/v1/invoices', {method: 'POST', headers: credentials(), body: '{"private-value":'});
    assert.equal(malformed.status, 400);
    assert.deepEqual(await malformed.json(), {error: {code: 'INVALID_JSON'}});
    const huge = await fetch(f.base + '/v1/invoices', post(requestBody({extra: 'private'.repeat(2_000)})));
    assert.equal(huge.status, 413);
    assert.deepEqual(await huge.json(), {error: {code: 'REQUEST_TOO_LARGE'}});
    const wrongType = await fetch(f.base + '/v1/invoices', {method: 'POST', headers: {...credentials(), 'Content-Type': 'text/plain'}, body: '{}'});
    assert.equal(wrongType.status, 415);
    const compressed = await fetch(f.base + '/v1/invoices', {method: 'POST', headers: {...credentials(), 'Content-Encoding': 'gzip'}, body: '{}'});
    assert.equal(compressed.status, 415);
    assert.equal(Number(f.store.db.prepare('SELECT COUNT(*) AS count FROM invoices').get()!.count), 0);
    assert.equal((await fetch(f.base + '/v1/invoices', post(requestBody({amount: '1000000'}), 'max'))).status, 201);
    const smallest = await fetch(f.base + '/v1/invoices', post(requestBody({chain: 'tron', amount: '0.000001', orderId: 'small'}), 'min'));
    assert.equal(smallest.status, 201);
    assert.equal((await smallest.json()).invoice.amountAtomic, '1');
  } finally {await f.stop();}
});

test('payment HTTP refuses browser Origin including preflight and emits private API headers', async () => {
  const f = await fixture();
  try {
    for (const origin of ['https://example.com', 'null']) {
      for (const method of ['GET', 'OPTIONS']) {
        const response = await fetch(f.base + '/v1/invoices/missing?userId=alice', {method, headers: {...credentials(), Origin: origin, 'Access-Control-Request-Method': 'POST'}});
        assert.equal(response.status, 403);
        assert.equal(response.headers.get('Access-Control-Allow-Origin'), null);
        assert.equal(response.headers.get('Access-Control-Allow-Credentials'), null);
      }
    }
    const response = await fetch(f.base + '/health');
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('X-Powered-By'), null);
    assert.equal(response.headers.get('ETag'), null);
    assert.equal(response.headers.get('Cache-Control'), 'no-store');
    assert.equal(response.headers.get('X-Content-Type-Options'), 'nosniff');
    assert.deepEqual(await response.json(), {ok: true});
  } finally {await f.stop();}
});

test('payment HTTP rate-limits reads by actual socket IP despite spoofed forwarded headers', async () => {
  const f = await fixture({rateLimit: {ipMax: 2, projectMax: 100, windowMs: 10_000, maxEntries: 4}});
  try {
    for (const ip of [1, 2].map(index => [192, 0, 2, index].join('.'))) {
      assert.equal((await fetch(f.base + '/v1/invoices/missing?userId=alice', {headers: {...credentials(), 'X-Forwarded-For': ip, Forwarded: `for=${ip}`}})).status, 404);
    }
    const blocked = await fetch(f.base + '/v1/invoices/missing?userId=alice', {headers: {...credentials(keyB), 'X-Forwarded-For': [192, 0, 2, 3].join('.')}});
    assert.equal(blocked.status, 429);
    assert.equal(blocked.headers.get('Retry-After'), '10');
    assert.deepEqual(await blocked.json(), {error: {code: 'IP_RATE_LIMITED'}});
    assert.equal((await fetch(f.base + '/health')).status, 200);
    f.advance(10_000);
    assert.equal((await fetch(f.base + '/v1/invoices/missing?userId=alice', {headers: credentials()})).status, 404);
  } finally {await f.stop();}
});

test('payment HTTP rejects repeated unauthorized reads and caps each authenticated project', async () => {
  const noAuth = await fixture({rateLimit: {ipMax: 1}});
  try {
    assert.equal((await fetch(noAuth.base + '/v1/invoices/missing?userId=alice')).status, 401);
    assert.equal((await fetch(noAuth.base + '/v1/invoices/missing?userId=alice')).status, 429);
  } finally {await noAuth.stop();}
  const f = await fixture({rateLimit: {ipMax: 100, projectMax: 1}});
  try {
    assert.equal((await fetch(f.base + '/v1/invoices/missing?userId=alice', {headers: credentials()})).status, 404);
    const blocked = await fetch(f.base + '/v1/invoices/missing?userId=alice', {headers: credentials()});
    assert.equal(blocked.status, 429);
    assert.deepEqual(await blocked.json(), {error: {code: 'PROJECT_RATE_LIMITED'}});
    assert.equal(blocked.headers.get('Retry-After'), '60');
    assert.equal((await fetch(f.base + '/v1/invoices/missing?userId=alice', {headers: credentials(keyB)})).status, 404);
  } finally {await f.stop();}
});

test('payment probes distinguish liveness/readiness and HTTP errors never expose private exceptions', async () => {
  let ready = false, brokenReadiness = false;
  const store: PaymentHttpStore = {
    authenticate: () => ({id: 'project', enabled: true, webhookUrl: 'https://example.com/private'}),
    createInvoice: () => {throw new Error('private database path and secret');},
    getInvoice: () => {throw new PaymentError('address_pool_empty', 503, 1.2);},
  };
  const f = await running(store, {readiness: async () => {if (brokenReadiness) throw new Error('private readiness detail'); return ready;}});
  try {
    assert.equal((await fetch(f.base + '/health')).status, 200);
    const pending = await fetch(f.base + '/ready');
    assert.equal(pending.status, 503);
    assert.deepEqual(await pending.json(), {ready: false});
    ready = true;
    assert.equal((await fetch(f.base + '/ready')).status, 200);
    brokenReadiness = true;
    assert.deepEqual(await (await fetch(f.base + '/ready')).json(), {ready: false});
    const failed = await fetch(f.base + '/v1/invoices', post());
    assert.equal(failed.status, 500);
    assert.deepEqual(await failed.json(), {error: {code: 'INTERNAL_ERROR'}});
    const retry = await fetch(f.base + '/v1/invoices/any?userId=alice', {headers: credentials()});
    assert.equal(retry.status, 503);
    assert.equal(retry.headers.get('Retry-After'), '2');
    assert.deepEqual(await retry.json(), {error: {code: 'address_pool_empty'}});
    for (const path of ['/admin', '/v1/refunds', '/v1/claim', '/v1/transactions']) {
      assert.equal((await fetch(f.base + path, {headers: credentials()})).status, 404);
    }
  } finally {await f.stop();}
  const unavailable = await running(store);
  try {assert.equal((await fetch(unavailable.base + '/ready')).status, 503);} finally {await unavailable.stop();}
});
