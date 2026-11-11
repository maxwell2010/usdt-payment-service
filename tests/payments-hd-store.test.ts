import test from 'node:test';
import assert from 'node:assert/strict';
import {ECDH} from 'node:crypto';
import {mkdtempSync, realpathSync, rmSync} from 'node:fs';
import {basename, dirname, join} from 'node:path';
import {tmpdir} from 'node:os';
import {HDKey} from '@scure/bip32';
import {keccak_256} from '@noble/hashes/sha3.js';
import {PaymentStore} from '../src/payments/store.ts';
import {normalizeAddress} from '../src/payments/assets.ts';
import {PaymentError, type Chain, type CreateInvoice} from '../src/payments/types.ts';

// Public BIP32 test vector seed. It is deliberately not a real wallet secret.
const TEST_SEED_HEX = '000102030405060708090a0b0c0d0e0f';
const T = 1_800_000_000_000, MASTER = Buffer.alloc(32, 91), LIMIT = 2 ** 31;
const hash = (chain: Chain) => `${chain === 'bsc' ? '0x' : ''}${'1'.repeat(64)}`;
const manual = (n: number) => `0x${n.toString(16).padStart(40, '0')}`;
function publicInput(chain: Chain, account = 0) {
  const derivationPath = `m/44'/${chain === 'bsc' ? 60 : 195}'/${account}'/0`;
  const key = HDKey.fromMasterSeed(Buffer.from(TEST_SEED_HEX, 'hex')).derive(derivationPath);
  return {key, xpub: key.publicExtendedKey, firstAddress: expectedAddress(chain, key, 0), derivationPath};
}
function expectedAddress(chain: Chain, key: HDKey, index: number): string {
  const child = key.deriveChild(index);
  const bytes = ECDH.convertKey(Buffer.from(child.publicKey!), 'secp256k1', undefined, undefined, 'uncompressed');
  if (typeof bytes === 'string') throw new Error('Unexpected test key conversion');
  const payload = Buffer.from(keccak_256(bytes.subarray(1))).subarray(-20).toString('hex');
  return normalizeAddress(chain, `${chain === 'bsc' ? '0x' : '41'}${payload}`);
}
function project(store: PaymentStore, id = 'alpha'): void {
  store.createProject({id, apiKey: `test-api-${id}-${'k'.repeat(32)}`, webhookUrl: `https://${id}.example.com/payments`, webhookSecret: `test-webhook-${id}-${'s'.repeat(32)}`});
}
function fixture(): PaymentStore {
  const store = new PaymentStore(':memory:', MASTER); project(store);
  for (const chain of ['bsc', 'tron'] as const) store.initializeCursor(chain, 100, hash(chain), T);
  return store;
}
function invoice(n: number, extra: Partial<CreateInvoice> = {}): CreateInvoice {
  return {userId: `user-${n}`, orderId: `order-${n}`, chain: 'bsc', amount: '10', idempotencyKey: `request-${n}`, ...extra};
}
function code(expected: string) {return (error: unknown) => error instanceof PaymentError && error.code === expected;}
const count = (store: PaymentStore, table: string) => Number(store.db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get()!.n);
const nextIndex = (store: PaymentStore, chain: Chain = 'bsc', id = 'alpha') => Number(store.db.prepare('SELECT next_index FROM hd_branches WHERE project_id=? AND chain=?').get(id, chain)!.next_index);
const unused = (store: PaymentStore, chain: Chain = 'bsc') => Number(store.db.prepare('SELECT COUNT(*) AS n FROM addresses WHERE project_id=? AND chain=? AND assigned_invoice_id IS NULL').get('alpha', chain)!.n);
function cleanup(directory: string): void {
  const resolved = realpathSync(directory), parent = realpathSync(tmpdir());
  assert.equal(dirname(resolved).toLowerCase(), parent.toLowerCase());
  assert.ok(basename(resolved).startsWith('payments-hd-'));
  rmSync(resolved, {recursive: true, force: true});
}

test('HD registration stores only public branch material and creates20 recoverable addresses per chain', () => {
  const store = fixture();
  try {
    const bsc = publicInput('bsc'), tron = publicInput('tron');
    store.registerPublicBranch('alpha', 'bsc', bsc, T);
    store.registerPublicBranch('alpha', 'tron', tron, T);
    assert.equal(store.db.prepare('PRAGMA user_version').get()!.user_version, 2);
    assert.equal(count(store, 'hd_branches'), 2); assert.equal(count(store, 'hd_addresses'), 40);
    assert.equal(count(store, 'addresses'), 40);
    for (const [chain, branch] of [['bsc', bsc], ['tron', tron]] as const) {
      const manifest = store.addressManifest('alpha', chain);
      assert.equal(nextIndex(store, chain), 20); assert.equal(unused(store, chain), 20);
      assert.deepEqual(manifest.map(row => row.childIndex), Array.from({length: 20}, (_, i) => i));
      assert.equal(new Set(manifest.map(row => row.fingerprint)).size, 1);
      assert.ok(manifest.every(row => row.derivationPath === branch.derivationPath && row.invoiceId === null));
      assert.deepEqual(manifest.map(row => row.address), Array.from({length: 20}, (_, i) => expectedAddress(chain, branch.key, i)));
      assert.deepEqual(new Set(store.getAddresses(chain)), new Set(manifest.map(row => String(row.address))));
    }
    const persisted = JSON.stringify(store.db.prepare('SELECT * FROM hd_branches').all()) + JSON.stringify(store.db.prepare('SELECT * FROM audit').all());
    assert.ok(persisted.includes(bsc.xpub)); assert.ok(persisted.includes(tron.xpub));
    assert.equal(persisted.includes('xprv'), false);
    assert.equal(persisted.includes(bsc.key.privateExtendedKey), false);
    assert.equal(persisted.includes(tron.key.privateExtendedKey), false);
    assert.equal(persisted.includes(TEST_SEED_HEX), false);
    assert.equal(persisted.includes(Buffer.from(bsc.key.privateKey!).toString('hex')), false);
  } finally {store.close();}
});

test('idempotent branch registration preserves allocated addresses, child indexes and next_index', () => {
  const store = fixture();
  try {
    const branch = publicInput('bsc'); store.registerPublicBranch('alpha', 'bsc', branch, T);
    const created = store.createInvoice('alpha', invoice(1), T + 1).invoice;
    const before = store.addressManifest('alpha', 'bsc'), auditBefore = count(store, 'audit');
    store.registerPublicBranch('alpha', 'bsc', branch, T + 2000);
    assert.deepEqual(store.addressManifest('alpha', 'bsc'), before);
    assert.equal(nextIndex(store), 20); assert.equal(count(store, 'audit'), auditBefore);
    assert.equal(before.find(row => row.invoiceId === created.id)!.address, created.address);
    assert.throws(() => store.registerPublicBranch('alpha', 'bsc', publicInput('bsc', 1), T + 2000), code('public_branch_conflict'));
    assert.throws(() => store.registerPublicBranch('alpha', 'bsc', {...branch, derivationPath: "m/44'/60'/1'/0"}, T + 2000), code('public_branch_conflict'));
    assert.deepEqual(store.addressManifest('alpha', 'bsc'), before);
  } finally {store.close();}
});

test('quota failures and invoice retries do not allocate child indexes or refill a low pool', () => {
  const store = fixture();
  try {
    const branch = publicInput('bsc'); store.registerPublicBranch('alpha', 'bsc', branch, T);
    for (let i = 1; i <= 3; i++) store.createInvoice('alpha', invoice(i, {userId: 'limited-user'}), T + i);
    for (let i = 4; i <= 16; i++) store.createInvoice('alpha', invoice(i), T + i);
    assert.equal(unused(store), 4); assert.equal(nextIndex(store), 20);
    const before = store.addressManifest('alpha', 'bsc'), audits = count(store, 'audit');
    const retried = store.createInvoice('alpha', invoice(3, {userId: 'limited-user'}), T + 100);
    assert.equal(retried.created, false);
    assert.throws(() => store.createInvoice('alpha', invoice(17, {userId: 'limited-user'}), T + 100), code('invoice_rate_limit'));
    assert.throws(() => store.createInvoice('alpha', invoice(17), T + 100, () => {throw new PaymentError('chain_not_ready', 503);}), code('chain_not_ready'));
    assert.equal(count(store, 'invoices'), 16); assert.equal(count(store, 'audit'), audits);
    assert.equal(nextIndex(store), 20); assert.equal(unused(store), 4);
    assert.deepEqual(store.addressManifest('alpha', 'bsc'), before);
  } finally {store.close();}
});

test('low-water refill restores20 before allocation, preserves children and never repeats an invoice address', () => {
  const store = fixture();
  try {
    const branch = publicInput('bsc'); store.registerPublicBranch('alpha', 'bsc', branch, T);
    const firstPool = store.addressManifest('alpha', 'bsc');
    const allocated = Array.from({length: 16}, (_, i) => store.createInvoice('alpha', invoice(i + 1), T + i).invoice.address);
    assert.equal(unused(store), 4); assert.equal(nextIndex(store), 20);
    allocated.push(store.createInvoice('alpha', invoice(17), T + 100).invoice.address);
    assert.equal(unused(store), 19); assert.equal(nextIndex(store), 36);
    assert.equal(count(store, 'addresses'), 36); assert.equal(count(store, 'hd_addresses'), 36);
    assert.equal(new Set(allocated).size, allocated.length);
    const manifest = store.addressManifest('alpha', 'bsc');
    assert.deepEqual(manifest.map(row => row.childIndex), Array.from({length: 36}, (_, i) => i));
    assert.deepEqual(manifest.map(row => row.address), Array.from({length: 36}, (_, i) => expectedAddress('bsc', branch.key, i)));
    assert.deepEqual(manifest.slice(0, 20).map(row => row.address), firstPool.map(row => row.address));
    assert.equal(new Set(store.getAddresses('bsc')).size, 36);
  } finally {store.close();}
});

test('public branch fingerprint cannot be reused across projects or chains', () => {
  const store = fixture();
  try {
    project(store, 'beta'); const branch = publicInput('bsc');
    store.registerPublicBranch('alpha', 'bsc', branch, T);
    assert.throws(() => store.registerPublicBranch('beta', 'bsc', branch, T), code('public_branch_conflict'));
    // Changing serialized ancestry metadata does not change deriving material.
    const repackaged = new HDKey({depth: 4, index: 0, parentFingerprint: (branch.key.parentFingerprint ^ 0xffffffff) >>> 0,
      publicKey: branch.key.publicKey!, chainCode: branch.key.chainCode!}).publicExtendedKey;
    assert.notEqual(repackaged, branch.xpub);
    assert.throws(() => store.registerPublicBranch('beta', 'bsc', {...branch, xpub: repackaged}, T), code('public_branch_conflict'));
    const sameMaterialOnTron = {...branch, firstAddress: expectedAddress('tron', branch.key, 0), derivationPath: "m/44'/195'/0'/0"};
    assert.throws(() => store.registerPublicBranch('beta', 'tron', sameMaterialOnTron, T), code('public_branch_conflict'));
    assert.throws(() => store.registerPublicBranch('alpha', 'tron', sameMaterialOnTron, T), code('public_branch_conflict'));
    assert.equal(count(store, 'hd_branches'), 1); assert.equal(count(store, 'addresses'), 20);
    assert.deepEqual(store.addressManifest('beta', 'bsc'), []); assert.deepEqual(store.addressManifest('beta', 'tron'), []);
    store.registerPublicBranch('alpha', 'tron', publicInput('tron'), T);
    assert.equal(count(store, 'hd_branches'), 2);
  } finally {store.close();}
});

test('new branch collision with a manual address rolls back registration and every generated child', () => {
  const store = fixture();
  try {
    const branch = publicInput('bsc'), collision = expectedAddress('bsc', branch.key, 7);
    store.addAddresses('alpha', 'bsc', [collision], T);
    const before = store.addressManifest('alpha', 'bsc'), audits = count(store, 'audit');
    assert.throws(() => store.registerPublicBranch('alpha', 'bsc', branch, T), code('hd_address_conflict'));
    assert.equal(count(store, 'hd_branches'), 0); assert.equal(count(store, 'hd_addresses'), 0);
    assert.equal(count(store, 'addresses'), 1); assert.equal(count(store, 'audit'), audits);
    assert.deepEqual(store.addressManifest('alpha', 'bsc'), before);
    assert.equal(store.createInvoice('alpha', invoice(1), T).invoice.address, collision);
  } finally {store.close();}
});

test('refill collision rolls back index, partially inserted children, invoice and quota', () => {
  const store = fixture();
  try {
    project(store, 'beta'); const branch = publicInput('bsc'); store.registerPublicBranch('alpha', 'bsc', branch, T);
    for (let i = 1; i <= 16; i++) store.createInvoice('alpha', invoice(i), T + i);
    store.addAddresses('beta', 'bsc', [expectedAddress('bsc', branch.key, 25)], T + 100);
    const before = store.addressManifest('alpha', 'bsc'), audits = count(store, 'audit');
    for (let attempt = 0; attempt < 2; attempt++) {
      assert.throws(() => store.createInvoice('alpha', invoice(17), T + 200 + attempt), code('hd_address_conflict'));
      assert.equal(nextIndex(store), 20); assert.equal(unused(store), 4);
      assert.equal(count(store, 'invoices'), 16); assert.equal(count(store, 'addresses'), 21);
      assert.equal(count(store, 'hd_addresses'), 20); assert.equal(count(store, 'audit'), audits);
      assert.deepEqual(store.addressManifest('alpha', 'bsc'), before);
    }
  } finally {store.close();}
});

test('private key input, recovery-address mismatch and invalid path leave no branch or addresses', () => {
  const store = fixture();
  try {
    const branch = publicInput('bsc');
    assert.throws(() => store.registerPublicBranch('alpha', 'bsc', {...branch, xpub: branch.key.privateExtendedKey}, T), code('invalid_public_branch'));
    assert.throws(() => store.registerPublicBranch('alpha', 'bsc', {...branch, firstAddress: manual(999)}, T), code('first_address_mismatch'));
    for (const derivationPath of ["m/44'/195'/0'/0", "m/44'/60'/0'/1", "m/44'/60'/0'/0/0", "m/44'/60'/2147483648'/0", "m/44'/60'/00'/0"]) {
      assert.throws(() => store.registerPublicBranch('alpha', 'bsc', {...branch, derivationPath}, T), code('invalid_derivation_path'));
    }
    assert.throws(() => store.registerPublicBranch('missing', 'bsc', branch, T), code('project_not_found'));
    assert.equal(count(store, 'hd_branches'), 0); assert.equal(count(store, 'addresses'), 0); assert.equal(count(store, 'hd_addresses'), 0);
  } finally {store.close();}
});

test('exhausted non-hardened index range drains existing pool then returns unavailable without wrapping', () => {
  const store = fixture();
  try {
    const branch = publicInput('bsc'); store.registerPublicBranch('alpha', 'bsc', branch, T);
    store.db.prepare('UPDATE hd_branches SET next_index=? WHERE project_id=? AND chain=?').run(LIMIT, 'alpha', 'bsc');
    const addresses = Array.from({length: 20}, (_, i) => store.createInvoice('alpha', invoice(i + 1), T + i).invoice.address);
    assert.equal(new Set(addresses).size, 20); assert.equal(unused(store), 0); assert.equal(nextIndex(store), LIMIT);
    const audits = count(store, 'audit');
    assert.throws(() => store.createInvoice('alpha', invoice(21), T + 100), code('address_pool_empty'));
    assert.equal(count(store, 'audit'), audits); assert.equal(count(store, 'invoices'), 20); assert.equal(count(store, 'addresses'), 20);
    assert.deepEqual(store.addressManifest('alpha', 'bsc').map(row => row.childIndex), Array.from({length: 20}, (_, i) => i));
    assert.equal(nextIndex(store), LIMIT);
  } finally {store.close();}
});

test('last non-hardened child is usable once and never crosses into hardened derivation', () => {
  const store = fixture();
  try {
    const branch = publicInput('bsc'); store.registerPublicBranch('alpha', 'bsc', branch, T);
    for (let i = 1; i <= 16; i++) store.createInvoice('alpha', invoice(i), T + i);
    store.db.prepare('UPDATE hd_branches SET next_index=? WHERE project_id=? AND chain=?').run(LIMIT - 1, 'alpha', 'bsc');
    store.createInvoice('alpha', invoice(17), T + 100);
    const terminal = store.addressManifest('alpha', 'bsc').find(row => row.childIndex === LIMIT - 1);
    assert.ok(terminal); assert.equal(terminal.address, expectedAddress('bsc', branch.key, LIMIT - 1));
    assert.equal(nextIndex(store), LIMIT); assert.equal(count(store, 'hd_addresses'), 21);
    for (let i = 18; i <= 21; i++) store.createInvoice('alpha', invoice(i), T + i + 100);
    assert.throws(() => store.createInvoice('alpha', invoice(22), T + 200), code('address_pool_empty'));
    assert.equal(count(store, 'hd_addresses'), 21); assert.equal(nextIndex(store), LIMIT);
  } finally {store.close();}
});

test('restart preserves next index, child manifest, allocations and invoice idempotency', () => {
  const directory = mkdtempSync(join(tmpdir(), 'payments-hd-restart-')), path = join(directory, 'isolated.sqlite');
  let store = new PaymentStore(path, MASTER);
  try {
    project(store); store.initializeCursor('bsc', 100, hash('bsc'), T);
    const branch = publicInput('bsc'); store.registerPublicBranch('alpha', 'bsc', branch, T);
    for (let i = 1; i <= 17; i++) store.createInvoice('alpha', invoice(i), T + i);
    const before = store.addressManifest('alpha', 'bsc'); assert.equal(nextIndex(store), 36);
    store.close(); store = new PaymentStore(path, MASTER);
    assert.deepEqual(store.addressManifest('alpha', 'bsc'), before); assert.equal(nextIndex(store), 36);
    assert.equal(store.createInvoice('alpha', invoice(17), T + 100).created, false);
    const created = store.createInvoice('alpha', invoice(18), T + 100).invoice;
    assert.equal(nextIndex(store), 36); assert.equal(unused(store), 18);
    assert.equal(before.find(row => row.address === created.address)!.invoiceId, null);
    const assigned = store.addressManifest('alpha', 'bsc').filter(row => row.invoiceId !== null);
    assert.equal(assigned.length, 18); assert.equal(new Set(assigned.map(row => row.address)).size, 18);
  } finally {store.close(); cleanup(directory);}
});

test('schema1 database upgrades to schema2 without changing existing manual invoice or reservation', () => {
  const directory = mkdtempSync(join(tmpdir(), 'payments-hd-migration-')), path = join(directory, 'isolated.sqlite');
  let store = new PaymentStore(path, MASTER);
  try {
    project(store); store.initializeCursor('bsc', 100, hash('bsc'), T);
    store.addAddresses('alpha', 'bsc', [manual(500), manual(501)], T);
    const original = store.createInvoice('alpha', invoice(1), T).invoice;
    // Reconstruct the schema1 boundary from before public-only HD support.
    store.db.exec('DROP TABLE hd_addresses; DROP TABLE hd_branches; PRAGMA user_version=1');
    store.close(); store = new PaymentStore(path, MASTER);
    assert.equal(store.db.prepare('PRAGMA user_version').get()!.user_version, 2);
    assert.equal(count(store, 'hd_branches'), 0); assert.equal(count(store, 'hd_addresses'), 0);
    assert.deepEqual(store.getInvoice('alpha', 'user-1', original.id, T), original);
    assert.equal(store.createInvoice('alpha', invoice(1), T).created, false);
    const second = store.createInvoice('alpha', invoice(2), T).invoice;
    assert.notEqual(second.address, original.address);
    assert.ok(store.addressManifest('alpha', 'bsc').every(row => row.childIndex === null && row.fingerprint === null && row.derivationPath === null));
    assert.throws(() => store.createInvoice('alpha', invoice(3), T), code('address_pool_empty'));
  } finally {store.close(); cleanup(directory);}
});
