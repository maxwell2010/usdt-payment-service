import {readFileSync} from 'node:fs';
import {resolve,dirname} from 'node:path';
import {z} from 'zod';

export const IPV4_LOOPBACK = [127, 0, 0, 1].join('.');
const IPV6_LOOPBACK = ['', '', '1'].join(':');

const schema=z.object({
  databasePath:z.string().min(1),masterKey:z.string().regex(/^[A-Za-z0-9+/]{43}=$/),
  host:z.enum([IPV4_LOOPBACK,IPV6_LOOPBACK]).default(IPV4_LOOPBACK),port:z.number().int().min(1024).max(65535).default(3501),
  pollIntervalMs:z.number().int().min(1000).max(60_000).default(3000)
}).strict();

export function parseAlchemyApiKey(value: unknown): string {
  if (typeof value !== 'string' || !value || value.length > 128 || /[^A-Za-z0-9_-]/.test(value)) {
    throw new Error('ALCHEMY_API_KEY is missing or invalid');
  }
  return value;
}

export function loadPaymentConfig(path=process.env.PAYMENTS_CONFIG??'runtime/payments/service.json'){
  const configPath=resolve(path),raw=readFileSync(configPath,'utf8');
  if(Buffer.byteLength(raw)>16_384)throw new Error('Payment configuration is too large');
  const parsed=schema.safeParse(JSON.parse(raw));
  if(!parsed.success)throw new Error('Invalid payment configuration');
  const key=Buffer.from(parsed.data.masterKey,'base64');
  if(key.length!==32)throw new Error('Invalid payment master key');
  return {...parsed.data,configPath,masterKey:key,databasePath:resolve(dirname(configPath),parsed.data.databasePath)};
}
