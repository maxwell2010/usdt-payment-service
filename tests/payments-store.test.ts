import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {PaymentStore} from '../src/payments/store.ts';
import {backup, DatabaseSync} from 'node:sqlite';
import {ASSETS, normalizeAddress, parseAmount} from '../src/payments/assets.ts';
import {PaymentError, type Chain, type ConfirmedBlock, type CreateInvoice, type Invoice} from '../src/payments/types.ts';

const T = 1_800_000_000_000, WINDOW = 1_800_000, MASTER = Buffer.alloc(32, 123);
const address = (n: number) => `0x${n.toString(16).padStart(40, '0')}`;
const hash = (n: number, chain: Chain = 'bsc') => `${chain === 'bsc' ? '0x' : ''}${n.toString(16).padStart(64, '0')}`;
const tron = (n: number) => normalizeAddress('tron', `41${n.toString(16).padStart(40, '0')}`);
function addProject(store: PaymentStore, id = 'alpha'): void {
  store.createProject({id, apiKey: `${id}-api-key-${'k'.repeat(30)}`, webhookUrl: `https://${id}.example.com/payments`, webhookSecret: `${id}-webhook-${'s'.repeat(30)}`});
}
function fixture(count = 12): PaymentStore {
  const store = new PaymentStore(':memory:', MASTER); addProject(store);
  store.initializeCursor('bsc', 100, hash(100), T);
  store.initializeCursor('tron', 100, hash(100, 'tron'), T);
  store.addAddresses('alpha', 'bsc', Array.from({length: count}, (_, i) => address(i + 1)), T);
  store.addAddresses('alpha', 'tron', Array.from({length: count}, (_, i) => tron(i + 1)), T);
  return store;
}
function input(n = 1, extra: Partial<CreateInvoice> = {}): CreateInvoice {
  return {userId: 'user-1', orderId: `order-${n}`, chain: 'bsc', amount: '10', idempotencyKey: `request-${n}`, ...extra};
}
function code(expected: string) {return (error: unknown) => error instanceof PaymentError && error.code === expected;}
function block(invoice: Invoice, options: {height?: number; timestamp?: number; amount?: string; logIndex?: number; tx?: number; parent?: number} = {}): ConfirmedBlock {
  const chain = invoice.chain, height = options.height ?? 101, timestamp = options.timestamp ?? T + 10_000;
  return {chain, height, hash: hash(height, chain), parentHash: hash(options.parent ?? height - 1, chain), timestamp,
    transfers: [{txHash: hash(options.tx ?? height, chain), logIndex: options.logIndex ?? 0, tokenContract: ASSETS[chain].contract,
      from: chain === 'bsc' ? address(999) : tron(999), to: invoice.address, amountAtomic: options.amount ?? invoice.amountAtomic,
      blockNumber: height, blockHash: hash(height, chain), timestamp}]};
}
const rowCount = (store: PaymentStore, table: string) => Number(store.db.prepare(`SELECT COUNT(*) AS count FROM ${table}`).get()!.count);

test('payment projects hash API credentials, seal webhook secret and isolate keys', () => {
  const store = fixture();
  try {
    addProject(store, 'beta');
    assert.equal(store.authenticate(`alpha-api-key-${'k'.repeat(30)}`)?.id, 'alpha');
    assert.equal(store.authenticate(`beta-api-key-${'k'.repeat(30)}`)?.id, 'beta');
    assert.equal(store.authenticate('wrong'), null);
    const persisted = JSON.stringify(store.db.prepare('SELECT * FROM projects').all());
    assert.ok(!persisted.includes(`alpha-api-key-${'k'.repeat(30)}`));
    assert.ok(!persisted.includes(`alpha-webhook-${'s'.repeat(30)}`));
    store.db.prepare('UPDATE projects SET enabled=0 WHERE id=?').run('alpha');
    assert.equal(store.authenticate(`alpha-api-key-${'k'.repeat(30)}`), null);
    assert.throws(() => store.createInvoice('alpha', input(), T), code('project_not_found'));
    assert.throws(() => addProject(store, 'beta'), code('project_conflict'));
  } finally {store.close();}
});

test('invoice creation cannot precede initial chain cursor and failures consume no quota or address', () => {
  const store = new PaymentStore(':memory:', MASTER); addProject(store);
  try {
    store.addAddresses('alpha', 'bsc', [address(1)], T);
    assert.throws(() => store.createInvoice('alpha', input(), T), code('chain_not_ready'));
    assert.equal(rowCount(store, 'invoices'), 0);
    assert.deepEqual(store.getAddresses('bsc'), [address(1)]);
    assert.equal(store.db.prepare('SELECT assigned_invoice_id FROM addresses').get()!.assigned_invoice_id, null);
    store.initializeCursor('bsc', 100, hash(100), T);
    const invoice = store.createInvoice('alpha', input(), T).invoice;
    assert.equal(invoice.address, address(1));
  } finally {store.close();}
});

test('three new invoices per user/project rolling30min, exact boundary release and retries', () => {
  const store = fixture();
  try {
    addProject(store, 'beta'); store.addAddresses('beta', 'bsc', [address(1000)], T);
    const first = store.createInvoice('alpha', input(), T);
    assert.equal(store.createInvoice('alpha', input(1, {amount: '10.000000'}), T + 200).created, false);
    assert.equal(store.createInvoice('alpha', input(1), T + 200).invoice.id, first.invoice.id);
    store.createInvoice('alpha', input(2), T + 1); store.createInvoice('alpha', input(3), T + 2);
    assert.throws(() => store.createInvoice('alpha', input(4), T + 3), (error: unknown) => {
      assert.ok(error instanceof PaymentError); assert.equal(error.status, 429); assert.equal(error.retryAfter, 1800); return true;
    });
    assert.equal(store.createInvoice('alpha', input(1), T + 3).created, false);
    assert.equal(store.createInvoice('beta', input(4), T + 3).created, true);
    assert.equal(store.createInvoice('alpha', input(5, {userId: 'user-2'}), T + 3).created, true);
    assert.throws(() => store.createInvoice('alpha', input(4), T + WINDOW - 1), code('invoice_rate_limit'));
    assert.equal(store.createInvoice('alpha', input(4), T + WINDOW).created, true);
    assert.equal(rowCount(store, 'invoices'), 6);
  } finally {store.close();}
});

test('idempotency and order ownership conflicts cannot change immutable binding', () => {
  const store = fixture();
  try {
    const invoice = store.createInvoice('alpha', input(), T).invoice;
    for (const extra of [{amount: '11'}, {userId: 'other-user'}, {orderId: 'different'}, {chain: 'tron' as const}]) {
      assert.throws(() => store.createInvoice('alpha', input(1, extra), T + 1), code('idempotency_conflict'));
    }
    assert.throws(() => store.createInvoice('alpha', input(2, {orderId: 'order-1', userId: 'attacker'}), T + 1), code('order_conflict'));
    assert.equal(store.getInvoice('alpha', 'attacker', invoice.id, T + WINDOW), null);
    assert.equal(store.getInvoice('other-project', 'user-1', invoice.id, T), null);
    assert.equal(store.db.prepare('SELECT status FROM invoices WHERE id=?').get(invoice.id)!.status, 'pending');
    assert.equal(store.getInvoice('alpha', 'user-1', invoice.id, T)!.address, invoice.address);
    assert.equal(rowCount(store, 'invoices'), 1);
  } finally {store.close();}
});

test('address batches are canonical, globally scoped, atomic and permanently reserved', () => {
  const store = fixture(1);
  try {
    addProject(store, 'beta');
    assert.throws(() => store.addAddresses('beta', 'bsc', [address(77), address(1)], T), code('address_conflict'));
    assert.equal(store.db.prepare('SELECT COUNT(*) AS count FROM addresses WHERE project_id=?').get('beta')!.count, 0);
    assert.equal(store.addAddresses('alpha', 'bsc', [address(1), address(1)], T), 0);
    const original = store.createInvoice('alpha', input(), T).invoice;
    assert.equal(store.expireInvoices(T + WINDOW), 1);
    assert.equal(store.getInvoice('alpha', 'user-1', original.id, T + WINDOW)!.status, 'expired');
    assert.throws(() => store.createInvoice('alpha', input(2), T + WINDOW), code('address_pool_empty'));
    assert.equal(rowCount(store, 'invoices'), 1);
    assert.deepEqual(store.getAddresses('bsc'), [address(1)]);
    store.addAddresses('alpha', 'bsc', [address(2)], T + WINDOW);
    assert.equal(store.createInvoice('alpha', input(2), T + WINDOW).invoice.address, address(2));
  } finally {store.close();}
});

test('scanner recipient snapshot already includes every unassigned address', () => {
  const store = fixture();
  try {
    const snapshot = store.getAddresses('bsc');
    assert.equal(snapshot.length, 12);
    const invoice = store.createInvoice('alpha', input(), T).invoice;
    assert.ok(snapshot.includes(invoice.address));
    assert.deepEqual(store.getAddresses('bsc'), snapshot);
  } finally {store.close();}
});

test('exact decimal amount survives receipt, paid update/outbox/audit/cursor commit together', () => {
  const store = fixture();
  try {
    const invoice = store.createInvoice('alpha', input(1, {amount: '999999.123456'}), T).invoice;
    assert.equal(invoice.amountAtomic, '999999123456000000000000');
    store.ingestBlock(block(invoice), T + 20_000);
    const paid = store.getInvoice('alpha', 'user-1', invoice.id, T + 20_000)!;
    assert.equal(paid.status, 'paid'); assert.equal(paid.receivedAtomic, invoice.amountAtomic);
    assert.deepEqual(store.getCursor('bsc'), {height: 101, hash: hash(101)});
    assert.equal(rowCount(store, 'chain_events'), 1); assert.equal(rowCount(store, 'outbox'), 1);
    assert.equal(store.db.prepare("SELECT COUNT(*) AS count FROM audit WHERE action='invoice.paid'").get()!.count, 1);
    const delivery = store.claimDelivery(T + 20_001)!;
    assert.equal(delivery.projectId, 'alpha'); assert.equal(delivery.secret, `alpha-webhook-${'s'.repeat(30)}`);
    assert.equal(JSON.parse(delivery.body).type, 'payment.paid');
    assert.ok(!delivery.body.includes(delivery.secret));
  } finally {store.close();}
});

test('TRON USDT uses six decimals and a base58-check receiving address', () => {
  const store = fixture();
  try {
    const invoice = store.createInvoice('alpha', input(1, {chain: 'tron', amount: '0.123456'}), T).invoice;
    assert.equal(invoice.amountAtomic, '123456'); assert.equal(invoice.address, tron(1));
    store.ingestBlock(block(invoice), T + 20_000);
    assert.equal(store.getInvoice('alpha', 'user-1', invoice.id, T + 20_000)!.status, 'paid');
  } finally {store.close();}
});

test('mint events allow zero sender without allowing zero receiving wallets or stalling next block', () => {
  const store = fixture();
  try {
    for (const chain of ['bsc', 'tron'] as const) {
      const zero = chain === 'bsc' ? `0x${'0'.repeat(40)}` : 'T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb';
      assert.throws(() => store.addAddresses('alpha', chain, [zero], T));
      const invoice = store.createInvoice('alpha', input(chain === 'bsc' ? 1 : 2, {chain}), T).invoice;
      const incoming = block(invoice); incoming.transfers[0].from = zero;
      store.ingestBlock(incoming, T + 20_000);
      assert.equal(store.getInvoice('alpha', 'user-1', invoice.id, T + 20_000)!.status, 'paid');
      const next = block(invoice, {height: 102}); next.transfers = [];
      store.ingestBlock(next, T + 21_000);
      assert.equal(store.getCursor(chain)!.height, 102);
    }
  } finally {store.close();}
});

test('underpayment can complete before expiry; later deposits never fulfill twice', () => {
  const store = fixture();
  try {
    const invoice = store.createInvoice('alpha', input(), T).invoice;
    const partial = parseAmount('bsc', '4').atomic, remaining = parseAmount('bsc', '6').atomic;
    store.ingestBlock(block(invoice, {amount: partial}), T + 20_000);
    assert.equal(store.getInvoice('alpha', 'user-1', invoice.id, T + 20_000)!.status, 'underpaid');
    store.ingestBlock(block(invoice, {height: 102, amount: remaining}), T + 21_000);
    assert.equal(store.getInvoice('alpha', 'user-1', invoice.id, T + 21_000)!.status, 'paid');
    store.ingestBlock(block(invoice, {height: 103, amount: partial}), T + 22_000);
    const paid = store.getInvoice('alpha', 'user-1', invoice.id, T + 22_000)!;
    assert.equal(paid.status, 'paid'); assert.equal(paid.receivedAtomic, parseAmount('bsc', '14').atomic);
    const events = store.db.prepare('SELECT body FROM outbox').all().map(row => JSON.parse(String(row.body)));
    assert.equal(events.filter(event => event.type === 'payment.paid').length, 1);
    assert.equal(events.filter(event => event.type === 'payment.review').length, 2);
  } finally {store.close();}
});

test('initial overpayment emits paid once and remains overpaid', () => {
  const store = fixture();
  try {
    const invoice = store.createInvoice('alpha', input(), T).invoice;
    store.ingestBlock(block(invoice, {amount: parseAmount('bsc', '11').atomic}), T + 20_000);
    assert.equal(store.getInvoice('alpha', 'user-1', invoice.id, T + 20_000)!.status, 'overpaid');
    assert.equal(JSON.parse(String(store.db.prepare('SELECT body FROM outbox').get()!.body)).type, 'payment.paid');
  } finally {store.close();}
});

test('late/expiry boundary deposits never auto-fulfill even if earlier partially paid', () => {
  const store = fixture();
  try {
    const invoice = store.createInvoice('alpha', input(), T).invoice;
    store.ingestBlock(block(invoice, {amount: parseAmount('bsc', '4').atomic}), T + 20_000);
    store.ingestBlock(block(invoice, {height: 102, timestamp: T + WINDOW, amount: parseAmount('bsc', '6').atomic}), T + WINDOW + 10_000);
    assert.equal(store.getInvoice('alpha', 'user-1', invoice.id, T + WINDOW + 10_000)!.status, 'late_payment');
    assert.equal(store.db.prepare("SELECT COUNT(*) AS count FROM outbox WHERE json_extract(body,'$.type')='payment.paid'").get()!.count, 0);
  } finally {store.close();}
});

test('timely block confirmed after wall clock expiry still credits original invoice', () => {
  const store = fixture();
  try {
    const invoice = store.createInvoice('alpha', input(), T).invoice;
    assert.equal(store.expireInvoices(T + WINDOW), 1);
    store.ingestBlock(block(invoice, {timestamp: T + WINDOW - 1}), T + WINDOW + 10_000);
    assert.equal(store.getInvoice('alpha', 'user-1', invoice.id, T + WINDOW + 10_000)!.status, 'paid');
  } finally {store.close();}
});

test('same-second network timestamp credits post-creation block without losing milliseconds', () => {
  const store = fixture();
  try {
    const invoice = store.createInvoice('alpha', input(), T + 500).invoice;
    store.ingestBlock(block(invoice, {timestamp: T}), T + 20_000);
    assert.equal(store.getInvoice('alpha', 'user-1', invoice.id, T + 20_000)!.status, 'paid');
  } finally {store.close();}
});

test('wrong contract, unknown recipient and pre-invoice timestamp do not credit payments', () => {
  const store = fixture();
  try {
    const invoice = store.createInvoice('alpha', input(), T).invoice;
    const wrong = block(invoice); wrong.transfers[0].tokenContract = address(777);
    store.ingestBlock(wrong, T + 20_000);
    const unknown = block(invoice, {height: 102}); unknown.transfers[0].to = address(888);
    store.ingestBlock(unknown, T + 20_000);
    store.ingestBlock(block(invoice, {height: 103, timestamp: T - 1}), T + 20_000);
    assert.equal(rowCount(store, 'chain_events'), 0); assert.equal(rowCount(store, 'outbox'), 0);
    assert.equal(store.getInvoice('alpha', 'user-1', invoice.id, T + 20_000)!.status, 'pending');
    assert.equal(store.getCursor('bsc')!.height, 103);
  } finally {store.close();}
});

test('cursor continuity and malformed multi-transfer blocks roll back every write', () => {
  const store = fixture();
  try {
    const invoice = store.createInvoice('alpha', input(), T).invoice;
    assert.throws(() => store.ingestBlock(block(invoice, {height: 102}), T), code('cursor_gap'));
    assert.throws(() => store.ingestBlock(block(invoice, {parent: 99}), T), code('cursor_reorg'));
    const malformed = block(invoice);
    malformed.transfers.push({...malformed.transfers[0], logIndex: 1, amountAtomic: '-1'});
    const auditBefore = rowCount(store, 'audit');
    assert.throws(() => store.ingestBlock(malformed, T + 20_000), code('invalid_transfer'));
    assert.equal(rowCount(store, 'chain_events'), 0); assert.equal(rowCount(store, 'outbox'), 0);
    assert.equal(rowCount(store, 'audit'), auditBefore); assert.equal(store.getCursor('bsc')!.height, 100);
    assert.equal(store.getInvoice('alpha', 'user-1', invoice.id, T)!.status, 'pending');
    store.ingestBlock(block(invoice), T + 20_000);
    const changedHash = {...block(invoice), hash: hash(999)};
    assert.throws(() => store.ingestBlock(changedHash, T), code('cursor_reorg'));
  } finally {store.close();}
});

test('outbox write failure atomically rolls back payment, audit and cursor', () => {
  const store = fixture();
  try {
    const invoice = store.createInvoice('alpha', input(), T).invoice;
    store.db.exec("CREATE TRIGGER fail_outbox BEFORE INSERT ON outbox BEGIN SELECT RAISE(ABORT,'synthetic outbox failure'); END");
    const auditBefore = rowCount(store, 'audit');
    assert.throws(() => store.ingestBlock(block(invoice), T + 20_000), /synthetic outbox failure/);
    assert.equal(rowCount(store, 'chain_events'), 0); assert.equal(rowCount(store, 'audit'), auditBefore);
    assert.equal(store.getCursor('bsc')!.height, 100);
    assert.equal(store.getInvoice('alpha', 'user-1', invoice.id, T)!.receivedAtomic, '0');
  } finally {store.close();}
});

test('global tx/log dedup prevents duplicate delivery, preserves different logs in same transaction', () => {
  const store = fixture();
  try {
    addProject(store, 'beta'); store.addAddresses('beta', 'bsc', [address(1000)], T);
    const a = store.createInvoice('alpha', input(), T).invoice, b = store.createInvoice('beta', input(), T).invoice;
    const incoming = block(a), second = {...incoming.transfers[0], to: b.address, logIndex: 1};
    incoming.transfers.push({...incoming.transfers[0]}, second);
    store.ingestBlock(incoming, T + 20_000); store.ingestBlock(incoming, T + 20_001);
    assert.equal(rowCount(store, 'chain_events'), 2); assert.equal(rowCount(store, 'outbox'), 2);
    assert.equal(store.getInvoice('alpha', 'user-1', a.id, T + 20_000)!.receivedAtomic, a.amountAtomic);
    assert.equal(store.getInvoice('beta', 'user-1', b.id, T + 20_000)!.receivedAtomic, b.amountAtomic);
    const replay = block(b, {height: 102, tx: 101, logIndex: 0});
    assert.throws(() => store.ingestBlock(replay, T + 20_002), code('transfer_conflict'));
    assert.equal(store.getCursor('bsc')!.height, 101);
  } finally {store.close();}
});

test('restoring a SQLite snapshot before payment reproduces webhook IDs for both logs of one transaction', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'payments-replay-'));
  const snapshotPath = join(directory, 'before-payment.sqlite');
  const original = fixture();
  try {
    const invoice = original.createInvoice('alpha', input(), T).invoice;
    await backup(original.db, snapshotPath);
    const incoming = block(invoice, {amount: (BigInt(invoice.amountAtomic) / 2n).toString()});
    incoming.transfers.push({...incoming.transfers[0], logIndex: 1});
    original.ingestBlock(incoming, T + 20_000);

    function eventIds(store: PaymentStore) {
      return store.db.prepare('SELECT id,body FROM outbox ORDER BY id').all().map(row => {
        const event = JSON.parse(String(row.body));
        assert.equal(event.eventId, row.id);
        return {id: row.id, index: event.transfer.logIndex, type: event.type};
      });
    }
    const delivered = eventIds(original);
    assert.equal(new Set(delivered.map(event => event.id)).size, 2);
    assert.equal(delivered.filter(event => event.type === 'payment.paid').length, 1);

    const restored = new PaymentStore(snapshotPath, MASTER);
    try {
      assert.equal(rowCount(restored, 'outbox'), 0);
      assert.equal(restored.getInvoice('alpha', 'user-1', invoice.id, T)!.status, 'pending');
      // The reader can supply equivalent tx hash spelling and a different delivery time.
      const replay = {...incoming, transfers: incoming.transfers.map(transfer => ({
        ...transfer, txHash: transfer.txHash.slice(2).toUpperCase(),
      }))};
      restored.ingestBlock(replay, T + 30_000);
      assert.deepEqual(eventIds(restored), delivered);
      assert.equal(restored.getInvoice('alpha', 'user-1', invoice.id, T + 30_000)!.receivedAtomic, invoice.amountAtomic);
    } finally {restored.close();}
  } finally {original.close(); rmSync(directory, {recursive: true, force: true});}
});

test('restart preserves receipts, quota, cursor and outbox leases/retries', () => {
  const directory = mkdtempSync(join(tmpdir(), 'payments-store-')), path = join(directory, 'isolated.sqlite');
  let store = new PaymentStore(path, MASTER);
  try {
    addProject(store); store.initializeCursor('bsc', 100, hash(100), T);
    store.addAddresses('alpha', 'bsc', [address(1), address(2), address(3), address(4)], T);
    const invoice = store.createInvoice('alpha', input(), T).invoice;
    store.createInvoice('alpha', input(2), T); store.createInvoice('alpha', input(3), T);
    store.ingestBlock(block(invoice), T + 20_000);
    const first = store.claimDelivery(T + 20_000, 1000)!;
    assert.equal(first.attempts, 1); assert.equal(store.claimDelivery(T + 20_999), null);
    store.close(); store = new PaymentStore(path, MASTER);
    assert.equal(store.getCursor('bsc')!.height, 101);
    assert.equal(store.getInvoice('alpha', 'user-1', invoice.id, T + 20_000)!.status, 'paid');
    assert.throws(() => store.createInvoice('alpha', input(4), T + 20_001), code('invoice_rate_limit'));
    store.ingestBlock(block(invoice), T + 20_001); assert.equal(rowCount(store, 'outbox'), 1);
    const recovered = store.claimDelivery(T + 21_000)!;
    assert.equal(recovered.id, first.id); assert.equal(recovered.body, first.body); assert.equal(recovered.attempts, 2);
    store.completeDelivery(recovered.id, false, T + 21_000, 5000);
    assert.equal(store.claimDelivery(T + 25_999), null);
    const retry = store.claimDelivery(T + 26_000)!; assert.equal(retry.attempts, 3);
    store.completeDelivery(retry.id, true, T + 26_100); assert.equal(store.claimDelivery(T + WINDOW), null);
  } finally {store.close(); rmSync(directory, {recursive: true, force: true});}
});

test('wrong master key fails at startup and preserves readable original encrypted data', () => {
  const directory = mkdtempSync(join(tmpdir(), 'payments-key-')), path = join(directory, 'isolated.sqlite');
  const original = new PaymentStore(path, MASTER); addProject(original); original.close();
  try {
    assert.throws(() => new PaymentStore(path, Buffer.alloc(32, 124)), /Incorrect payment master key/);
    const reopened = new PaymentStore(path, MASTER);
    try {assert.equal(reopened.authenticate(`alpha-api-key-${'k'.repeat(30)}`)?.id, 'alpha');}
    finally {reopened.close();}
  } finally {rmSync(directory, {recursive: true, force: true});}
});

test('refuses unrelated application DB rather than adding payment tables', () => {
  const directory = mkdtempSync(join(tmpdir(), 'payments-unrelated-')), path = join(directory, 'application.sqlite');
  const original = new DatabaseSync(path); original.exec('CREATE TABLE users(id INTEGER PRIMARY KEY)'); original.close();
  try {
    assert.throws(() => new PaymentStore(path, MASTER), /must be separate/);
    const reopened = new DatabaseSync(path);
    try {
      assert.deepEqual(reopened.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().map(row => row.name), ['users']);
      assert.equal(reopened.prepare('PRAGMA user_version').get()!.user_version, 0);
    } finally {reopened.close();}
  } finally {rmSync(directory, {recursive: true, force: true});}
});
