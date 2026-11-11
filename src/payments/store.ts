import {createHash, randomUUID} from 'node:crypto';
import {closeSync, mkdirSync, openSync} from 'node:fs';
import {dirname} from 'node:path';
import {DatabaseSync, type SQLOutputValue} from 'node:sqlite';
import {ASSETS, normalizeAddress, parseAmount} from './assets.ts';
import {hashSecret, openSecret, sealSecret, validateWebhookUrl} from './security.ts';
import {derivePaymentAddress,validatePublicBranch} from './hd.ts';
import {PaymentError, type Chain, type ConfirmedBlock, type CreateInvoice, type Cursor, type Delivery, type Invoice, type InvoiceStatus, type Project, type ProjectInput} from './types.ts';

const WINDOW_MS = 30 * 60 * 1000;
const MAX_ATOMIC = (1n << 256n) - 1n;
const KEY_CHECK = 'standalone-payments-key-check-v1';
type Row = Record<string, SQLOutputValue>;

function fail(code = 'invalid_request', status = 400): never {throw new PaymentError(code, status);}
function validTime(now: number): number {if (!Number.isSafeInteger(now) || now < 0) fail(); return now;}
function text(value: unknown, max = 200): string {if (typeof value !== 'string' || value.length < 1 || value.length > max || value.includes('\0')) fail(); return value;}
function chainValue(chain: unknown): Chain {if (chain !== 'bsc' && chain !== 'tron') fail(); return chain;}
function blockHeight(value: number): number {if (!Number.isSafeInteger(value) || value < 0) fail('invalid_block'); return value;}
function hash(chain: Chain, value: string): string {
  if (typeof value !== 'string' || !/^(?:0x)?[a-fA-F0-9]{64}$/.test(value)) fail('invalid_block');
  const bare = value.replace(/^0x/, '').toLowerCase(); return chain === 'bsc' ? `0x${bare}` : bare;
}
function atomic(value: string): string {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,77})$/.test(value) || BigInt(value) > MAX_ATOMIC) fail('invalid_transfer');
  return value;
}

/** A separate, watch-only payment ledger. No wallet private keys are stored here. */
export class PaymentStore {
  readonly db: DatabaseSync;
  private readonly masterKey: Buffer;

  constructor(path: string, masterKey: Buffer) {
    if (!Buffer.isBuffer(masterKey) || masterKey.length !== 32) throw new Error('Payment master key must contain 32 bytes');
    this.masterKey = Buffer.from(masterKey);
    if (path !== ':memory:') {
      mkdirSync(dirname(path), {recursive: true, mode: 0o700});
      try {
        closeSync(openSync(path, 'wx', 0o600));
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
      }
    }
    this.db = new DatabaseSync(path);
    try {
      this.db.exec('PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;');
      const version = Number(this.db.prepare('PRAGMA user_version').get()!.user_version);
      if (version > 2) throw new Error('Unsupported payment database schema');
      const tables = this.db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").all().map(row => String(row.name));
      if (tables.length && !['projects', 'invoices', 'scan_cursors'].every(name => tables.includes(name))) throw new Error('Payment database must be separate from other application databases');
      this.db.exec('PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;');
      this.transaction(() => {
        this.db.exec(`
          CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS projects (
            id TEXT PRIMARY KEY, api_key_hash TEXT NOT NULL UNIQUE,
            webhook_url TEXT NOT NULL, webhook_secret TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1))
          );
          CREATE TABLE IF NOT EXISTS addresses (
            project_id TEXT NOT NULL REFERENCES projects(id), chain TEXT NOT NULL CHECK(chain IN ('bsc','tron')),
            address TEXT NOT NULL, assigned_invoice_id TEXT UNIQUE, created_at INTEGER NOT NULL,
            PRIMARY KEY(chain,address)
          );
          CREATE INDEX IF NOT EXISTS addresses_pool ON addresses(project_id,chain,assigned_invoice_id);
          CREATE TABLE IF NOT EXISTS hd_branches (
            fingerprint TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id),
            chain TEXT NOT NULL CHECK(chain IN ('bsc','tron')), xpub TEXT NOT NULL,
            derivation_path TEXT NOT NULL, next_index INTEGER NOT NULL DEFAULT 0 CHECK(next_index BETWEEN 0 AND 2147483648),
            created_at INTEGER NOT NULL, UNIQUE(project_id,chain)
          );
          CREATE TABLE IF NOT EXISTS hd_addresses (
            chain TEXT NOT NULL, address TEXT NOT NULL, fingerprint TEXT NOT NULL REFERENCES hd_branches(fingerprint),
            child_index INTEGER NOT NULL CHECK(child_index BETWEEN 0 AND 2147483647),
            PRIMARY KEY(chain,address), UNIQUE(fingerprint,child_index),
            FOREIGN KEY(chain,address) REFERENCES addresses(chain,address)
          );
          CREATE TABLE IF NOT EXISTS invoices (
            id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id), user_id TEXT NOT NULL,
            order_id TEXT NOT NULL, chain TEXT NOT NULL, token_contract TEXT NOT NULL,
            address TEXT NOT NULL, amount TEXT NOT NULL, amount_atomic TEXT NOT NULL,
            received_atomic TEXT NOT NULL DEFAULT '0', timely_received_atomic TEXT NOT NULL DEFAULT '0',
            status TEXT NOT NULL DEFAULT 'pending', created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
            min_block INTEGER NOT NULL, idempotency_key TEXT NOT NULL,
            UNIQUE(project_id,order_id), UNIQUE(project_id,idempotency_key), UNIQUE(chain,address),
            FOREIGN KEY(chain,address) REFERENCES addresses(chain,address)
          );
          CREATE INDEX IF NOT EXISTS invoices_user_quota ON invoices(project_id,user_id,created_at);
          CREATE TABLE IF NOT EXISTS scan_cursors (chain TEXT PRIMARY KEY, height INTEGER NOT NULL, hash TEXT NOT NULL, updated_at INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS chain_events (
            chain TEXT NOT NULL, tx_hash TEXT NOT NULL, log_index INTEGER NOT NULL,
            block_number INTEGER NOT NULL, block_hash TEXT NOT NULL, timestamp INTEGER NOT NULL,
            token_contract TEXT NOT NULL, from_address TEXT NOT NULL, to_address TEXT NOT NULL,
            amount_atomic TEXT NOT NULL, invoice_id TEXT NOT NULL REFERENCES invoices(id),
            PRIMARY KEY(chain,tx_hash,log_index)
          );
          CREATE TABLE IF NOT EXISTS outbox (
            id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id), invoice_id TEXT NOT NULL REFERENCES invoices(id),
            body TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0,
            next_attempt_at INTEGER NOT NULL, lease_until INTEGER, created_at INTEGER NOT NULL
          );
          CREATE INDEX IF NOT EXISTS outbox_ready ON outbox(status,next_attempt_at,lease_until);
          CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY, at INTEGER NOT NULL, project_id TEXT,
            action TEXT NOT NULL, subject_id TEXT NOT NULL, detail TEXT NOT NULL
          );
          PRAGMA user_version=2;
        `);
        const check = this.db.prepare("SELECT value FROM metadata WHERE key='master_key_check'").get();
        try {
          if (check) {if (openSecret(String(check.value), this.masterKey) !== KEY_CHECK) throw new Error('Invalid key');}
          else {
            // Also check older module databases before adding the key marker.
            for (const row of this.db.prepare('SELECT webhook_secret FROM projects').all()) openSecret(String(row.webhook_secret), this.masterKey);
            this.db.prepare('INSERT INTO metadata(key,value) VALUES(?,?)').run('master_key_check', sealSecret(KEY_CHECK, this.masterKey));
          }
        } catch {throw new Error('Incorrect payment master key or damaged encrypted data');}
      });
    } catch (error) {this.db.close(); this.masterKey.fill(0); throw error;}
  }

  private transaction<T>(fn: () => T): T {
    this.db.exec('BEGIN IMMEDIATE');
    try {const result = fn(); this.db.exec('COMMIT'); return result;}
    catch (error) {this.db.exec('ROLLBACK'); throw error;}
  }
  private audit(action: string, subject: string, now: number, project: string | null = null, detail: object = {}): void {
    this.db.prepare('INSERT INTO audit(at,project_id,action,subject_id,detail) VALUES(?,?,?,?,?)').run(now, project, action, subject, JSON.stringify(detail));
  }
  private project(projectId: string): Row {
    const row = this.db.prepare('SELECT * FROM projects WHERE id=? AND enabled=1').get(text(projectId));
    if (!row) fail('project_not_found', 404); return row;
  }
  private invoice(row: Row): Invoice {
    return {id: String(row.id), projectId: String(row.project_id), userId: String(row.user_id), orderId: String(row.order_id),
      chain: row.chain as Chain, asset: 'USDT', tokenContract: String(row.token_contract), address: String(row.address),
      amount: String(row.amount), amountAtomic: String(row.amount_atomic), receivedAtomic: String(row.received_atomic),
      status: row.status as InvoiceStatus, createdAt: Number(row.created_at), expiresAt: Number(row.expires_at)};
  }

  createProject(input: ProjectInput): Project {
    const id = text(input.id), apiKey = text(input.apiKey, 1024), secret = text(input.webhookSecret, 1024);
    if (apiKey.length < 24 || secret.length < 24) fail('weak_secret');
    validateWebhookUrl(input.webhookUrl);
    const sealed = sealSecret(secret, this.masterKey), apiHash = hashSecret(apiKey);
    return this.transaction(() => {
      if (this.db.prepare('SELECT id FROM projects WHERE id=? OR api_key_hash=?').get(id, apiHash)) fail('project_conflict', 409);
      this.db.prepare('INSERT INTO projects(id,api_key_hash,webhook_url,webhook_secret) VALUES(?,?,?,?)').run(id, apiHash, input.webhookUrl, sealed);
      this.audit('project.created', id, Date.now(), id);
      return {id, webhookUrl: input.webhookUrl, enabled: true};
    });
  }

  authenticate(apiKey: string): Project | null {
    if (typeof apiKey !== 'string' || apiKey.length > 1024) return null;
    const row = this.db.prepare('SELECT id,webhook_url FROM projects WHERE api_key_hash=? AND enabled=1').get(hashSecret(apiKey));
    return row ? {id: String(row.id), webhookUrl: String(row.webhook_url), enabled: true} : null;
  }

  addAddresses(projectId: string, chain: Chain, addresses: readonly string[], now = Date.now()): number {
    chainValue(chain); validTime(now);
    if (!Array.isArray(addresses) || addresses.length < 1 || addresses.length > 10000) fail();
    const normalized = [...new Set(addresses.map(address => normalizeAddress(chain, address)))];
    return this.transaction(() => {
      this.project(projectId);
      let added = 0;
      for (const address of normalized) {
        const exists = this.db.prepare('SELECT project_id FROM addresses WHERE chain=? AND address=?').get(chain, address);
        if (exists && exists.project_id !== projectId) fail('address_conflict', 409);
        if (exists) continue;
        this.db.prepare('INSERT INTO addresses(project_id,chain,address,created_at) VALUES(?,?,?,?)').run(projectId, chain, address, now);
        added++;
      }
      if (added) this.audit('addresses.added', chain, now, projectId, {count: added});
      return added;
    });
  }

  /** Only an offline-exported external-chain xpub is accepted; never an xprv/seed. */
  registerPublicBranch(projectId:string,chain:Chain,input:{xpub:string;firstAddress:string;derivationPath:string},now=Date.now()):void {
    chainValue(chain);validTime(now);
    const branch=validatePublicBranch(chain,input.xpub);
    const expected=normalizeAddress(chain,input.firstAddress);
    const pathPattern=chain==='bsc'?/^m\/44'\/60'\/(0|[1-9]\d{0,9})'\/0$/:/^m\/44'\/195'\/(0|[1-9]\d{0,9})'\/0$/;
    const match=typeof input.derivationPath==='string'?pathPattern.exec(input.derivationPath):null;
    if(!match||Number(match[1])>=2**31)fail('invalid_derivation_path');
    if(derivePaymentAddress(chain,branch.xpub,0)!==expected)fail('first_address_mismatch');
    this.transaction(()=>{
      this.project(projectId);
      const existing=this.db.prepare('SELECT * FROM hd_branches WHERE project_id=? AND chain=?').get(projectId,chain);
      if(existing){
        if(existing.fingerprint!==branch.fingerprint||existing.derivation_path!==input.derivationPath)fail('public_branch_conflict',409);
        return;
      }
      if(this.db.prepare('SELECT fingerprint FROM hd_branches WHERE fingerprint=?').get(branch.fingerprint))fail('public_branch_conflict',409);
      this.db.prepare('INSERT INTO hd_branches(fingerprint,project_id,chain,xpub,derivation_path,created_at) VALUES(?,?,?,?,?,?)').run(branch.fingerprint,projectId,chain,branch.xpub,input.derivationPath,now);
      this.fillPublicPool(projectId,chain,now);
      this.audit('public_branch.registered',chain,now,projectId,{fingerprint:branch.fingerprint,derivationPath:input.derivationPath});
    });
  }

  /** Called only inside a transaction, after all new-invoice limits have passed. */
  private fillPublicPool(projectId:string,chain:Chain,now:number):void {
    const branch=this.db.prepare('SELECT * FROM hd_branches WHERE project_id=? AND chain=?').get(projectId,chain);
    if(!branch)return;
    const available=Number(this.db.prepare('SELECT COUNT(*) AS n FROM addresses WHERE project_id=? AND chain=? AND assigned_invoice_id IS NULL').get(projectId,chain)!.n);
    if(available>=5)return;
    let index=Number(branch.next_index);
    for(let count=available;count<20&&index<2**31;count++,index++){
      const address=derivePaymentAddress(chain,String(branch.xpub),index);
      if(this.db.prepare('SELECT address FROM addresses WHERE chain=? AND address=?').get(chain,address))fail('hd_address_conflict',409);
      this.db.prepare('INSERT INTO addresses(project_id,chain,address,created_at) VALUES(?,?,?,?)').run(projectId,chain,address,now);
      this.db.prepare('INSERT INTO hd_addresses(chain,address,fingerprint,child_index) VALUES(?,?,?,?)').run(chain,address,String(branch.fingerprint),index);
    }
    this.db.prepare('UPDATE hd_branches SET next_index=? WHERE fingerprint=?').run(index,String(branch.fingerprint));
    this.audit('public_pool.refilled',chain,now,projectId,{nextIndex:index});
  }

  addressManifest(projectId:string,chain:Chain){
    chainValue(chain);this.project(projectId);
    return this.db.prepare(`SELECT a.address,a.assigned_invoice_id AS invoiceId,b.fingerprint,b.derivation_path AS derivationPath,h.child_index AS childIndex
      FROM addresses a LEFT JOIN hd_addresses h ON h.chain=a.chain AND h.address=a.address
      LEFT JOIN hd_branches b ON b.fingerprint=h.fingerprint WHERE a.project_id=? AND a.chain=? ORDER BY h.child_index,a.address`).all(projectId,chain);
  }

  createInvoice(projectId: string, input: CreateInvoice, now = Date.now(), authorizeNew?: () => void): {invoice: Invoice; created: boolean} {
    validTime(now); chainValue(input.chain);
    const userId = text(input.userId), orderId = text(input.orderId), idem = text(input.idempotencyKey);
    const amount = parseAmount(input.chain, input.amount);
    return this.transaction(() => {
      this.project(projectId);
      const retry = this.db.prepare('SELECT * FROM invoices WHERE project_id=? AND idempotency_key=?').get(projectId, idem);
      if (retry) {
        if (retry.user_id !== userId || retry.order_id !== orderId || retry.chain !== input.chain || retry.amount_atomic !== amount.atomic) fail('idempotency_conflict', 409);
        this.expireRows(now, projectId);
        return {invoice: this.invoice(this.db.prepare('SELECT * FROM invoices WHERE id=?').get(String(retry.id))!), created: false};
      }
      if (this.db.prepare('SELECT id FROM invoices WHERE project_id=? AND order_id=?').get(projectId, orderId)) fail('order_conflict', 409);
      // Readiness gates new allocations only. A persisted idempotent retry remains
      // readable during an upstream outage and never consumes a new quota/address.
      authorizeNew?.();
      const cursor = this.getCursor(input.chain);
      if (!cursor) fail('chain_not_ready', 503);
      const quota = this.db.prepare('SELECT COUNT(*) AS count,MIN(created_at) AS oldest FROM invoices WHERE project_id=? AND user_id=? AND created_at>?').get(projectId, userId, now - WINDOW_MS)!;
      if (Number(quota.count) >= 3) throw new PaymentError('invoice_rate_limit', 429, Math.max(1, Math.ceil((Number(quota.oldest) + WINDOW_MS - now) / 1000)));
      this.expireRows(now, projectId);
      const pending = this.db.prepare("SELECT COUNT(*) AS count FROM invoices WHERE project_id=? AND status IN ('pending','underpaid')").get(projectId)!;
      if (Number(pending.count) >= 1000) fail('project_pending_limit', 429);
      this.fillPublicPool(projectId,input.chain,now);
      const address = this.db.prepare('SELECT address FROM addresses WHERE project_id=? AND chain=? AND assigned_invoice_id IS NULL ORDER BY created_at,address LIMIT 1').get(projectId, input.chain);
      if (!address) fail('address_pool_empty', 503);
      const id = randomUUID();
      this.db.prepare(`INSERT INTO invoices(id,project_id,user_id,order_id,chain,token_contract,address,amount,amount_atomic,created_at,expires_at,min_block,idempotency_key)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(id, projectId, userId, orderId, input.chain, ASSETS[input.chain].contract, String(address.address), amount.amount, amount.atomic, now, now + WINDOW_MS, cursor.height + 1, idem);
      this.db.prepare('UPDATE addresses SET assigned_invoice_id=? WHERE chain=? AND address=? AND assigned_invoice_id IS NULL').run(id, input.chain, String(address.address));
      this.audit('invoice.created', id, now, projectId, {userId, orderId, chain: input.chain});
      return {invoice: this.invoice(this.db.prepare('SELECT * FROM invoices WHERE id=?').get(id)!), created: true};
    });
  }

  getInvoice(projectId: string, userId: string, id: string, now = Date.now()): Invoice | null {
    validTime(now); text(projectId); text(userId); text(id);
    return this.transaction(() => {
      // Scope before mutating expiry: a foreign lookup has no side effects.
      const row = this.db.prepare('SELECT * FROM invoices WHERE project_id=? AND user_id=? AND id=?').get(projectId, userId, id);
      if (!row) return null;
      this.expireRows(now, projectId, id);
      return this.invoice(this.db.prepare('SELECT * FROM invoices WHERE id=?').get(id)!);
    });
  }

  private expireRows(now: number, projectId?: string, id?: string): number {
    let query = "SELECT id,project_id FROM invoices WHERE status IN ('pending','underpaid') AND expires_at<=?";
    const params: (number | string)[] = [now];
    if (projectId !== undefined) {query += ' AND project_id=?'; params.push(projectId);}
    if (id !== undefined) {query += ' AND id=?'; params.push(id);}
    const rows = this.db.prepare(query).all(...params);
    for (const row of rows) {
      this.db.prepare("UPDATE invoices SET status='expired' WHERE id=?").run(String(row.id));
      this.audit('invoice.expired', String(row.id), now, String(row.project_id));
    }
    return rows.length;
  }
  expireInvoices(now = Date.now()): number {validTime(now); return this.transaction(() => this.expireRows(now));}

  getCursor(chain: Chain): Cursor | null {
    chainValue(chain);
    const row = this.db.prepare('SELECT height,hash FROM scan_cursors WHERE chain=?').get(chain);
    return row ? {height: Number(row.height), hash: String(row.hash)} : null;
  }
  initializeCursor(chain: Chain, height: number, blockHash: string, now = Date.now()): void {
    chainValue(chain); blockHeight(height); validTime(now); const normalized = hash(chain, blockHash);
    this.transaction(() => {
      const old = this.getCursor(chain);
      if (old) {if (old.height !== height || old.hash !== normalized) fail('cursor_already_initialized', 409); return;}
      this.db.prepare('INSERT INTO scan_cursors(chain,height,hash,updated_at) VALUES(?,?,?,?)').run(chain, height, normalized, now);
      this.audit('cursor.initialized', chain, now, null, {height, hash: normalized});
    });
  }
  getAddresses(chain: Chain): string[] {
    chainValue(chain);
    // Include the unassigned pool before scanning. Assigning an invoice while an
    // RPC request is in flight must not introduce an address absent from it.
    return this.db.prepare('SELECT address FROM addresses WHERE chain=? ORDER BY address').all(chain).map(row => String(row.address));
  }

  ingestBlock(block: ConfirmedBlock, now = Date.now()): void {
    chainValue(block.chain); blockHeight(block.height); validTime(now); validTime(block.timestamp);
    const blockHash = hash(block.chain, block.hash), parentHash = hash(block.chain, block.parentHash);
    if (!Array.isArray(block.transfers)) fail('invalid_block');
    this.transaction(() => {
      const cursor = this.getCursor(block.chain);
      if (!cursor) fail('cursor_not_initialized', 409);
      if (cursor.height === block.height && cursor.hash === blockHash) return;
      if (cursor.height === block.height) fail('cursor_reorg', 409);
      if (block.height !== cursor.height + 1) fail('cursor_gap', 409);
      if (parentHash !== cursor.hash) fail('cursor_reorg', 409);
      for (const transfer of block.transfers) {
        const txHash = hash(block.chain, transfer.txHash), txBlockHash = hash(block.chain, transfer.blockHash);
        if (!Number.isSafeInteger(transfer.logIndex) || transfer.logIndex < 0 || transfer.blockNumber !== block.height || txBlockHash !== blockHash || transfer.timestamp !== block.timestamp) fail('invalid_transfer');
        const value = atomic(transfer.amountAtomic), contract = normalizeAddress(block.chain, transfer.tokenContract);
        const from = normalizeAddress(block.chain, transfer.from, true), to = normalizeAddress(block.chain, transfer.to);
        if (contract !== normalizeAddress(block.chain, ASSETS[block.chain].contract) || value === '0') continue;
        const seen = this.db.prepare('SELECT * FROM chain_events WHERE chain=? AND tx_hash=? AND log_index=?').get(block.chain, txHash, transfer.logIndex);
        if (seen) {
          if (seen.amount_atomic !== value || seen.to_address !== to || seen.from_address !== from || seen.token_contract !== contract || seen.block_hash !== blockHash) fail('transfer_conflict', 409);
          continue;
        }
        const row = this.db.prepare('SELECT * FROM invoices WHERE chain=? AND address=?').get(block.chain, to);
        // Network timestamps have one-second resolution; a payment in the same
        // second as invoice creation is valid. The block watermark and never-
        // reused address independently prevent historical payment attribution.
        if (!row || transfer.timestamp < Math.floor(Number(row.created_at) / 1000) * 1000 || transfer.blockNumber < Number(row.min_block)) continue;
        this.db.prepare(`INSERT INTO chain_events(chain,tx_hash,log_index,block_number,block_hash,timestamp,token_contract,from_address,to_address,amount_atomic,invoice_id)
          VALUES(?,?,?,?,?,?,?,?,?,?,?)`).run(block.chain, txHash, transfer.logIndex, block.height, blockHash, block.timestamp, contract, from, to, value, String(row.id));
        const received = BigInt(String(row.received_atomic)) + BigInt(value);
        const timely = transfer.timestamp < Number(row.expires_at);
        const timelyReceived = BigInt(String(row.timely_received_atomic)) + (timely ? BigInt(value) : 0n);
        const expected = BigInt(String(row.amount_atomic));
        const fulfilled = row.status === 'paid' || row.status === 'overpaid';
        let status = row.status as InvoiceStatus;
        if (!fulfilled) {
          if (!timely || row.status === 'late_payment') status = 'late_payment';
          else if (timelyReceived > expected) status = 'overpaid';
          else if (timelyReceived === expected) status = 'paid';
          else status = 'underpaid';
        }
        this.db.prepare('UPDATE invoices SET received_atomic=?,timely_received_atomic=?,status=? WHERE id=?').run(received.toString(), timelyReceived.toString(), status, String(row.id));
        const invoice = this.invoice(this.db.prepare('SELECT * FROM invoices WHERE id=?').get(String(row.id))!);
        // A ledger restored before this block must reproduce the same delivery ID.
        const identity = ['payment-transfer-v1', block.chain, txHash, transfer.logIndex, invoice.projectId, invoice.id];
        const eventId = createHash('sha256').update(JSON.stringify(identity)).digest('hex');
        const paid = !fulfilled && (status === 'paid' || status === 'overpaid');
        const body = JSON.stringify({eventId, type: paid ? 'payment.paid' : 'payment.review', createdAt: now, invoice,
          transfer: {chain: block.chain, txHash, logIndex: transfer.logIndex, amountAtomic: value, blockNumber: block.height, blockHash, timestamp: block.timestamp}});
        this.db.prepare('INSERT INTO outbox(id,project_id,invoice_id,body,next_attempt_at,created_at) VALUES(?,?,?,?,?,?)').run(eventId, String(row.project_id), String(row.id), body, now, now);
        this.audit(paid ? 'invoice.paid' : 'invoice.payment_received', String(row.id), now, String(row.project_id), {eventId, txHash, logIndex: transfer.logIndex, status});
      }
      this.db.prepare('UPDATE scan_cursors SET height=?,hash=?,updated_at=? WHERE chain=?').run(block.height, blockHash, now, block.chain);
      this.audit('cursor.advanced', block.chain, now, null, {height: block.height, hash: blockHash});
    });
  }

  claimDelivery(now = Date.now(), leaseMs = 30000, excludedProjects: readonly string[] = []): Delivery | null {
    validTime(now);
    if (!Number.isSafeInteger(leaseMs) || leaseMs < 1 || leaseMs > 3600000) fail();
    return this.transaction(() => {
      const row = this.db.prepare(`SELECT o.*,p.webhook_url,p.webhook_secret FROM outbox o JOIN projects p ON p.id=o.project_id
        WHERE p.enabled=1 AND o.next_attempt_at<=? AND (o.status='pending' OR (o.status='processing' AND o.lease_until<=?))
          AND o.project_id NOT IN (SELECT value FROM json_each(?))
        ORDER BY o.next_attempt_at,o.created_at,o.id LIMIT 1`).get(now, now, JSON.stringify(excludedProjects));
      if (!row) return null;
      const secret = openSecret(String(row.webhook_secret), this.masterKey);
      this.db.prepare("UPDATE outbox SET status='processing',attempts=attempts+1,lease_until=? WHERE id=?").run(now + leaseMs, String(row.id));
      this.audit('delivery.claimed', String(row.id), now, String(row.project_id), {attempt: Number(row.attempts) + 1});
      return {id: String(row.id), projectId: String(row.project_id), url: String(row.webhook_url), secret, body: String(row.body), attempts: Number(row.attempts) + 1};
    });
  }

  completeDelivery(id: string, success: boolean, now = Date.now(), retryAfterMs?: number): void {
    text(id); validTime(now);
    if (typeof success !== 'boolean' || (retryAfterMs !== undefined && (!Number.isSafeInteger(retryAfterMs) || retryAfterMs < 0 || retryAfterMs > 7 * 86400000))) fail();
    this.transaction(() => {
      const row = this.db.prepare('SELECT * FROM outbox WHERE id=?').get(id);
      if (!row || row.status !== 'processing') return;
      if (success) this.db.prepare("UPDATE outbox SET status='sent',lease_until=NULL WHERE id=?").run(id);
      else {
        const retry = retryAfterMs ?? Math.min(3600000, 1000 * 2 ** Math.min(Number(row.attempts) - 1, 12));
        this.db.prepare("UPDATE outbox SET status='pending',lease_until=NULL,next_attempt_at=? WHERE id=?").run(now + retry, id);
      }
      this.audit(success ? 'delivery.sent' : 'delivery.retry', id, now, String(row.project_id));
    });
  }

  close(): void {this.db.close(); this.masterKey.fill(0);}
}
