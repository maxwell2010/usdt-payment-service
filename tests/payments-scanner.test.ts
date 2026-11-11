import test from 'node:test';
import assert from 'node:assert/strict';
import {PaymentScanner,type ScannerStore} from '../src/payments/scanner.ts';
import {PaymentError,type Chain,type ChainReader,type ConfirmedBlock,type Cursor} from '../src/payments/types.ts';

function fixture(chain:Chain='bsc') {
  let cursor:Cursor|null=null,head:Cursor={height:10,hash:'hash-10'},failAt:number|null=null;
  const blocks:number[]=[],committed:ConfirmedBlock[]=[];
  const store:ScannerStore={
    getCursor:()=>cursor?{...cursor}:null,
    initializeCursor:(_chain,height,hash)=>{if(!cursor)cursor={height,hash};},
    getAddresses:()=>['recipient'],
    ingestBlock:block=>{committed.push(structuredClone(block));cursor={height:block.height,hash:block.hash};},
  };
  const reader:ChainReader={chain,head:async()=>({...head}),block:async(height,recipients)=>{
    blocks.push(height);assert.deepEqual(recipients,['recipient']);
    if(height===failAt)throw new PaymentError('rpc_rate_limited',503,5);
    return {chain,height,hash:`hash-${height}`,parentHash:`hash-${height-1}`,timestamp:1_700_000_000_000+height,transfers:[]};
  }};
  return {store,reader,blocks,committed,setCursor:(value:Cursor)=>{cursor=value;},setHead:(height:number,hash=`hash-${height}`)=>{head={height,hash};},fail:(height:number|null)=>{failAt=height;}};
}
test('first scanner startup only initializes current confirmed head, without historical replay',async()=>{
  const f=fixture();const scanner=new PaymentScanner(f.store,[f.reader],{now:()=>123});
  assert.equal(scanner.status('bsc').ready,false);await scanner.tick();
  assert.deepEqual(f.store.getCursor('bsc'),{height:10,hash:'hash-10'});assert.deepEqual(f.blocks,[]);assert.deepEqual(f.committed,[]);
  assert.deepEqual(scanner.status('bsc'),{ready:true,lastSuccessAt:123});
});
test('scanner catches up a bounded contiguous batch; restart resumes persistent cursor only',async()=>{
  const f=fixture();f.setCursor({height:5,hash:'hash-5'});
  const scanner=new PaymentScanner(f.store,[f.reader],{maxBlocksPerTick:2,now:()=>100});
  await scanner.tick();assert.deepEqual(f.blocks,[6,7]);assert.equal(scanner.status('bsc').ready,false);
  assert.equal(scanner.status('bsc').error,'chain_catching_up');assert.equal(scanner.status('bsc').lastSuccessAt,null);
  const restarted=new PaymentScanner(f.store,[f.reader],{maxBlocksPerTick:10,now:()=>200});
  await restarted.tick();assert.deepEqual(f.blocks,[6,7,8,9,10]);assert.deepEqual(restarted.status('bsc'),{ready:true,lastSuccessAt:200});
});
test('429 and failed blocks never skip cursor; next tick resumes the same failed height',async()=>{
  const f=fixture();f.setCursor({height:7,hash:'hash-7'});f.fail(9);
  const scanner=new PaymentScanner(f.store,[f.reader]);await assert.rejects(scanner.tick());
  assert.deepEqual(f.store.getCursor('bsc'),{height:8,hash:'hash-8'});assert.equal(scanner.status('bsc').error,'rpc_rate_limited');
  assert.equal(scanner.status('bsc').ready,false);
  f.fail(null);await scanner.tick();assert.deepEqual(f.blocks,[8,9,9,10]);assert.equal(scanner.status('bsc').ready,true);
});
test('cursor/hash mismatch and broken parent refuse credit and keep readiness false',async t=>{
  for(const mode of ['cursor','parent','head','chain'] as const)await t.test(mode,async()=>{
    const f=fixture();f.setCursor({height:mode==='cursor'?10:9,hash:mode==='cursor'?'wrong':'hash-9'});
    if(mode!=='cursor')f.reader.block=async height=>({chain:mode==='chain'?'tron':'bsc',height,hash:mode==='head'?'wrong':'hash-10',parentHash:mode==='parent'?'wrong':'hash-9',timestamp:100,transfers:[]});
    const scanner=new PaymentScanner(f.store,[f.reader]);await assert.rejects(scanner.tick());assert.deepEqual(f.committed,[]);assert.equal(scanner.status('bsc').ready,false);
  });
});
test('overlapping ticks coalesce per chain and independent chain failures do not halt others',async()=>{
  const f=fixture(),g=fixture('tron');let release!:()=>void,calls=0;
  f.reader.head=async()=>{calls++;await new Promise<void>(resolve=>{release=resolve;});throw new PaymentError('rpc_timeout',503);};
  const scanner=new PaymentScanner({
    getCursor:chain=>chain==='bsc'?f.store.getCursor(chain):g.store.getCursor(chain),
    initializeCursor:(chain,h,hash,now)=>(chain==='bsc'?f.store:g.store).initializeCursor(chain,h,hash,now),
    getAddresses:chain=>(chain==='bsc'?f.store:g.store).getAddresses(chain),
    ingestBlock:(block,now)=>(block.chain==='bsc'?f.store:g.store).ingestBlock(block,now),
  },[f.reader,g.reader]);
  const a=scanner.tickChain('bsc'),b=scanner.tickChain('bsc');assert.equal(a,b);assert.equal(calls,1);
  await scanner.tickChain('tron');assert.equal(scanner.status('tron').ready,true);
  release();await assert.rejects(a);assert.equal(scanner.status('bsc').ready,false);
});
test('previous ready status survives an in-flight poll, failures invalidate it immediately',async()=>{
  const f=fixture();let now=100;const scanner=new PaymentScanner(f.store,[f.reader],{now:()=>now});
  await scanner.tick();let release!:(value:Cursor)=>void;
  f.reader.head=()=>new Promise<Cursor>(resolve=>{release=resolve;});
  const tick=scanner.tickChain('bsc');assert.deepEqual(scanner.status('bsc'),{ready:true,lastSuccessAt:100});
  now=200;release({height:10,hash:'hash-10'});await tick;assert.deepEqual(scanner.status('bsc'),{ready:true,lastSuccessAt:200});
  f.reader.head=async()=>{throw new Error('private endpoint details');};
  await assert.rejects(scanner.tick());assert.deepEqual(scanner.status('bsc'),{ready:false,lastSuccessAt:200,error:'chain_scan_failed'});
});
test('frozen and future-dated provider heads revoke readiness without initializing or advancing a cursor',async()=>{
  const f=fixture();let now=1_700_000_000_000;
  f.reader.head=async()=>({height:10,hash:'hash-10',timestamp:now-120_001});
  const scanner=new PaymentScanner(f.store,[f.reader],{now:()=>now});
  await assert.rejects(scanner.tick());assert.equal(scanner.status('bsc').error,'chain_head_stale');assert.equal(f.store.getCursor('bsc'),null);
  f.reader.head=async()=>({height:10,hash:'hash-10',timestamp:now-60_000});
  await scanner.tick();assert.equal(scanner.status('bsc').ready,true);
  f.reader.head=async()=>({height:10,hash:'hash-10',timestamp:now+30_001});
  await assert.rejects(scanner.tick());assert.equal(scanner.status('bsc').ready,false);assert.equal(f.store.getCursor('bsc')?.height,10);
  f.reader.head=async()=>({height:10,hash:'hash-10',timestamp:now-120_001});
  now++;await assert.rejects(scanner.tick());assert.equal(scanner.status('bsc').error,'chain_head_stale');
});
test('scanner requires atomic persisted cursor after ingest and validates configured bounds',async()=>{
  const f=fixture();f.setCursor({height:9,hash:'hash-9'});f.store.ingestBlock=()=>{};
  const scanner=new PaymentScanner(f.store,[f.reader]);await assert.rejects(scanner.tick());
  assert.equal(scanner.status('bsc').error,'cursor_not_committed');
  assert.throws(()=>new PaymentScanner(f.store,[f.reader,f.reader]),/duplicate_chain_reader/);
  assert.throws(()=>new PaymentScanner(f.store,[f.reader],{maxBlocksPerTick:0}),/invalid_scanner_options/);
});
test('address pool imported during an awaited read prevents cursor advance and retries the block',async()=>{
  const f=fixture();f.setCursor({height:9,hash:'hash-9'});let addresses=['recipient'];
  f.store.getAddresses=()=>[...addresses];let release!:()=>void;
  const original=f.reader.block;
  f.reader.block=async(height,targets)=>{await new Promise<void>(resolve=>{release=resolve;});return original(height,targets);};
  const scanner=new PaymentScanner(f.store,[f.reader]);
  const tick=scanner.tickChain('bsc');await Promise.resolve();addresses.push('newly-imported');release();
  await assert.rejects(tick,(e:unknown)=>e instanceof PaymentError && e.code==='address_pool_changed');
  assert.deepEqual(f.store.getCursor('bsc'),{height:9,hash:'hash-9'});assert.equal(f.committed.length,0);
  addresses=['recipient'];f.reader.block=original;await scanner.tick();assert.equal(f.committed.length,1);
});
