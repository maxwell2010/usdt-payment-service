import test from 'node:test';
import assert from 'node:assert/strict';
import {ASSETS,normalizeAddress,parseAmount,tronAddressHex} from '../src/payments/assets.ts';
import {sealSecret,openSecret,isPublicAddress,validateWebhookUrl,webhookSignature,verifyWebhookSignature,resolveWebhookAddresses} from '../src/payments/security.ts';
import {PaymentDispatcher} from '../src/payments/dispatcher.ts';
import type {Delivery} from '../src/payments/types.ts';

const ipv4 = (...octets: number[]) => octets.join('.');
const ipv6 = (...groups: string[]) => groups.join(':');

test('payment precision is preserved across both mainnet token decimals',()=>{
  assert.deepEqual(parseAmount('bsc','123456.000001'),{amount:'123456.000001',atomic:'123456000001000000000000'});
  assert.deepEqual(parseAmount('tron','123456.000001'),{amount:'123456.000001',atomic:'123456000001'});
  assert.deepEqual(parseAmount('tron','1.000000'),{amount:'1',atomic:'1000000'});
  for(const amount of ['0','-1','01','1e3','NaN','1.0000001','1000000.000001',' 1','1.'])assert.throws(()=>parseAmount('bsc',amount));
});
test('TRON addresses require valid Base58Check and normalize equivalent hex encoding',()=>{
  const address=ASSETS.tron.contract,hex=tronAddressHex(address);
  assert.equal(normalizeAddress('tron',hex),address);assert.equal(normalizeAddress('tron','0x'+hex),address);
  assert.throws(()=>normalizeAddress('tron',address.slice(0,-1)+'1'));
  assert.throws(()=>normalizeAddress('tron','41'+'0'.repeat(40)));
  assert.equal(normalizeAddress('bsc',ASSETS.bsc.contract.toUpperCase().replace('0X','0x')),ASSETS.bsc.contract);
  assert.throws(()=>normalizeAddress('bsc','0x'+'0'.repeat(40)));
});
test('webhook secret encryption authenticates ciphertext and rejects a foreign master key',()=>{
  const key=Buffer.alloc(32,7),sealed=sealSecret('synthetic-webhook-secret',key);
  assert(!sealed.includes('synthetic'));assert.equal(openSecret(sealed,key),'synthetic-webhook-secret');
  assert.throws(()=>openSecret(sealed,Buffer.alloc(32,8)));
  const [version, nonce, tag, ciphertext] = sealed.split(':');
  const changed = (Number.parseInt(ciphertext.slice(0, 2), 16) ^ 1).toString(16).padStart(2, '0');
  assert.throws(()=>openSecret([version, nonce, tag, changed + ciphertext.slice(2)].join(':'),key));
  assert.throws(()=>openSecret([version, nonce, tag.slice(0, 24), ciphertext].join(':'),key), /Invalid encrypted payment secret/);
});
test('webhook signature authenticates raw bytes and timestamp with a bounded replay window',()=>{
  const now=1_800_000_000_000,timestamp=String(now/1000),body='{"invoice":"synthetic"}',secret='synthetic-secret';
  const signature=webhookSignature(secret,timestamp,body);
  assert(verifyWebhookSignature(secret,timestamp,body,signature,now));
  assert(!verifyWebhookSignature(secret,timestamp,body+' ',signature,now));
  assert(!verifyWebhookSignature(secret,timestamp,body,signature,now+300_001));
  assert(!verifyWebhookSignature('wrong',timestamp,body,signature,now));
});
test('webhook destinations block localhost, credentials, alternate ports and private IPs',()=>{
  const authenticatedUrl = new URL('https://example.com');
  authenticatedUrl.username = 'synthetic-user';
  authenticatedUrl.password = 'synthetic-password';
  for(const url of ['http://example.com','https://localhost','https://' + ipv4(10, 0, 0, 1),'https://[' + ipv6('', '', '1') + ']','https://example.com:8443',authenticatedUrl.href,'https://host.internal','https://example.com/#fragment'])assert.throws(()=>validateWebhookUrl(url));
  assert.equal(validateWebhookUrl('https://example.com/hook'),'https://example.com/hook');
  const blocked = [
    ipv4(127, 0, 0, 1), ipv4(10, 0, 0, 1), ipv4(169, 254, 169, 254), ipv4(172, 16, 0, 1),
    ipv4(192, 168, 1, 1), ipv4(100, 64, 0, 1), ipv4(0, 0, 0, 0), ipv4(224, 0, 0, 1),
    ipv6('', '', '1'), ipv6('fd00', '', '1'), ipv6('fe80', '', '1'),
    ipv6('', '', 'ffff', ipv4(127, 0, 0, 1)), ipv6('2001', 'db8', '', '1'),
  ];
  for(const ip of blocked)assert(!isPublicAddress(ip),ip);
  for(const ip of [ipv4(8, 8, 8, 8), ipv4(1, 1, 1, 1), ipv6('2606', '4700', '4700', '', '1111')])assert(isPublicAddress(ip),ip);
});
test('dispatcher preserves unknown outcomes for retry and passes 429 retry hints',async()=>{
  const queued:Delivery[]=[{id:'event1',projectId:'project',url:'https://example.com/hook',secret:'synthetic',body:'{}',attempts:1},{id:'event2',projectId:'project',url:'https://example.com/hook',secret:'synthetic',body:'{}',attempts:1}];
  const completed:unknown[]=[];
  const dispatcher=new PaymentDispatcher({claimDelivery:(_now,_lease,excluded)=>excluded?.includes('project')?null:queued.shift()??null,completeDelivery:(...args)=>{completed.push(args);}},async(_url,_body,_secret,event)=>{if(event==='event1')throw new Error('unknown transport outcome');return {ok:false,retryAfterMs:60_000};},()=>123);
  await dispatcher.tick();assert.deepEqual(completed,[['event1',false,123,undefined],['event2',false,123,60_000]]);
});
test('webhook DNS rejects mixed public/private resolutions and re-resolves every attempt',async()=>{
  let calls=0;
  const publicResult = {address: ipv4(1, 1, 1, 1), family: 4};
  const loopbackResult = {address: ipv4(127, 0, 0, 1), family: 4};
  const resolver=async()=>{calls++;return calls===1?[publicResult]:[publicResult,loopbackResult];};
  assert.deepEqual(await resolveWebhookAddresses('example.com',resolver),[publicResult]);
  await assert.rejects(resolveWebhookAddresses('example.com',resolver),/not public/);assert.equal(calls,2);
});
test('dispatcher stops claiming work when shutdown begins during a delivery',async()=>{
  let stopping=false,claims=0,completions=0;
  const dispatcher=new PaymentDispatcher({claimDelivery:(_now,_lease,excluded)=>{
    assert(!stopping);
    if(excluded?.includes('project'))return null;
    claims++;
    return {id:'event',projectId:'project',url:'https://example.com',secret:'synthetic',body:'{}',attempts:1};
  },completeDelivery:()=>{completions++;}},async()=>{stopping=true;return {ok:true};},()=>123,()=>stopping);
  await dispatcher.tick();assert.equal(claims,1);assert.equal(completions,1);
});
