import express, {type ErrorRequestHandler, type Express} from 'express';
import {parseAmount} from './assets.ts';
import {PaymentError, type CreateInvoice, type Invoice, type Project} from './types.ts';

/** Project credentials belong on the project's backend, never in browser code. */
export interface PaymentHttpStore {
  authenticate(apiKey: string): Project | null;
  createInvoice(projectId: string, input: CreateInvoice, now?: number): {invoice: Invoice; created: boolean};
  getInvoice(projectId: string, userId: string, id: string, now?: number): Invoice | null;
}

export interface PaymentsHttpOptions {
  now?: () => number;
  readiness?: () => boolean | Promise<boolean>;
  rateLimit?: {windowMs?: number; ipMax?: number; projectMax?: number; maxEntries?: number};
}

const identifier = /^[A-Za-z0-9_.:-]{1,128}$/;

function validId(value: unknown): value is string {
  return typeof value === 'string' && identifier.test(value);
}

function positiveInteger(value: number | undefined, fallback: number): number {
  if (value === undefined) return fallback;
  if (!Number.isSafeInteger(value) || value <= 0) throw new Error('Invalid payment HTTP rate limit configuration');
  return value;
}

/** Fixed windows, bounded storage, and LRU eviction. Socket IPs are never taken from proxy headers. */
class RequestLimiter {
  private readonly entries = new Map<string, {count: number; resetsAt: number}>();
  private nextCleanup = 0;

  constructor(private readonly windowMs: number, private readonly maximum: number, private readonly capacity: number) {}

  consume(key: string, now: number): number | null {
    if (now >= this.nextCleanup) {
      for (const [entryKey, entry] of this.entries) if (entry.resetsAt <= now) this.entries.delete(entryKey);
      this.nextCleanup = now + this.windowMs;
    }
    let entry = this.entries.get(key);
    if (!entry || entry.resetsAt <= now) entry = {count: 0, resetsAt: now + this.windowMs};
    this.entries.delete(key);
    if (this.entries.size >= this.capacity) this.entries.delete(this.entries.keys().next().value!);
    this.entries.set(key, entry);
    if (entry.count >= this.maximum) return Math.max(1, Math.ceil((entry.resetsAt - now) / 1_000));
    entry.count++;
    return null;
  }
}

export function createPaymentsApp(store: PaymentHttpStore, options: PaymentsHttpOptions = {}): Express {
  const app = express();
  const now = options.now ?? Date.now;
  const windowMs = positiveInteger(options.rateLimit?.windowMs, 60_000);
  const capacity = positiveInteger(options.rateLimit?.maxEntries, 10_000);
  const ipLimiter = new RequestLimiter(windowMs, positiveInteger(options.rateLimit?.ipMax, 60), capacity);
  const projectLimiter = new RequestLimiter(windowMs, positiveInteger(options.rateLimit?.projectMax, 120), capacity);

  app.disable('x-powered-by');
  app.disable('etag');
  app.set('trust proxy', false);
  app.set('query parser', 'simple');
  app.use((_req, res, next) => {
    res.set('Cache-Control', 'no-store');
    res.set('X-Content-Type-Options', 'nosniff');
    res.set('Referrer-Policy', 'no-referrer');
    res.set('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'");
    next();
  });
  app.use((req, _res, next) => {
    if (req.headers.origin !== undefined) return next(new PaymentError('BROWSER_REQUEST_FORBIDDEN', 403));
    next();
  });

  // Probe responses do not depend on project credentials or the request limiter.
  app.get('/health', (_req, res) => {res.json({ok: true});});
  app.get('/ready', async (_req, res) => {
    let ready = false;
    try {ready = options.readiness ? await options.readiness() : false;} catch { /* Readiness errors are private. */ }
    res.status(ready ? 200 : 503).json({ready});
  });

  app.use((req, _res, next) => {
    const retryAfter = ipLimiter.consume(req.socket.remoteAddress ?? 'unknown', now());
    next(retryAfter === null ? undefined : new PaymentError('IP_RATE_LIMITED', 429, retryAfter));
  });
  app.use('/v1', (req, res, next) => {
    const header = req.headers.authorization;
    const match = typeof header === 'string' && header.length <= 1_031 ? /^Bearer ([^\s,]+)$/i.exec(header) : null;
    const project = match ? store.authenticate(match[1]) : null;
    if (!project || !project.enabled) return next(new PaymentError('UNAUTHORIZED', 401));
    const retryAfter = projectLimiter.consume(project.id, now());
    if (retryAfter !== null) return next(new PaymentError('PROJECT_RATE_LIMITED', 429, retryAfter));
    res.locals.paymentProject = project;
    next();
  });
  const json = express.json({limit: '8kb', strict: true, inflate: false});

  app.post('/v1/invoices', (req, _res, next) => {
    if (!req.is('application/json')) return next(new PaymentError('UNSUPPORTED_MEDIA_TYPE', 415));
    next();
  }, json, (req, res) => {
    if (Object.keys(req.query).length) throw new PaymentError('INVALID_QUERY', 400);
    const body: unknown = req.body;
    if (!body || typeof body !== 'object' || Array.isArray(body)) throw new PaymentError('INVALID_INVOICE', 400);
    const input = body as Record<string, unknown>;
    const fields = Object.keys(input);
    if (fields.length !== 4 || fields.some(field => !['userId', 'orderId', 'chain', 'amount'].includes(field)) ||
        !validId(input.userId) || !validId(input.orderId) || (input.chain !== 'bsc' && input.chain !== 'tron') || typeof input.amount !== 'string') {
      throw new PaymentError('INVALID_INVOICE', 400);
    }
    parseAmount(input.chain, input.amount);
    const idempotencyKey = req.headers['idempotency-key'];
    if (!validId(idempotencyKey)) throw new PaymentError('INVALID_IDEMPOTENCY_KEY', 400);
    const project = res.locals.paymentProject as Project;
    const result = store.createInvoice(project.id, {
      userId: input.userId,
      orderId: input.orderId,
      chain: input.chain,
      amount: input.amount,
      idempotencyKey,
    }, now());
    res.status(result.created ? 201 : 200).json({invoice: result.invoice});
  });

  app.get('/v1/invoices/:id', (req, res) => {
    if (Object.keys(req.query).length !== 1 || !validId(req.query.userId) || !validId(req.params.id)) {
      throw new PaymentError('INVALID_QUERY', 400);
    }
    const project = res.locals.paymentProject as Project;
    const invoice = store.getInvoice(project.id, req.query.userId, req.params.id, now());
    if (!invoice) throw new PaymentError('INVOICE_NOT_FOUND', 404);
    res.json({invoice});
  });
  app.use((_req, _res, next) => {next(new PaymentError('NOT_FOUND', 404));});
  const handleError: ErrorRequestHandler = (error: unknown, _req, res, _next) => {
    if (res.headersSent) {res.end(); return;}
    if (error instanceof PaymentError && Number.isInteger(error.status) && error.status >= 400 && error.status <= 599 && /^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(error.code)) {
      if (typeof error.retryAfter === 'number' && Number.isFinite(error.retryAfter) && error.retryAfter > 0) {
        res.set('Retry-After', String(Math.ceil(error.retryAfter)));
      }
      if (error.status === 401) res.set('WWW-Authenticate', 'Bearer');
      res.status(error.status).json({error: {code: error.code}});
      return;
    }
    const parserType = error && typeof error === 'object' && 'type' in error ? error.type : undefined;
    const parserErrors: Record<string, [number, string]> = {
      'entity.too.large': [413, 'REQUEST_TOO_LARGE'],
      'entity.parse.failed': [400, 'INVALID_JSON'],
      'encoding.unsupported': [415, 'UNSUPPORTED_ENCODING'],
      'charset.unsupported': [415, 'UNSUPPORTED_ENCODING'],
      'request.aborted': [400, 'INVALID_REQUEST'],
      'request.size.invalid': [400, 'INVALID_REQUEST'],
    };
    const [status, code] = error instanceof URIError ? [400, 'INVALID_REQUEST'] :
      typeof parserType === 'string' && Object.hasOwn(parserErrors, parserType) ? parserErrors[parserType] : [500, 'INTERNAL_ERROR'];
    res.status(status).json({error: {code}});
  };
  app.use(handleError);
  return app;
}
