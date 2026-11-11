import test from 'node:test';
import assert from 'node:assert/strict';
import {ASSETS, normalizeAddress, TRANSFER_TOPIC} from '../src/payments/assets.ts';
import {AlchemyBscReader,AlchemyTronReader,TRON_MAINNET_GENESIS} from '../src/payments/chains.ts';
import {PaymentError} from '../src/payments/types.ts';

const testApiKey='test_key-chains';
const bscRpc=`https://bnb-mainnet.g.alchemy.com/v2/${testApiKey}`;
const tronRpc=`https://tron-mainnet.g.alchemy.com/v2/${testApiKey}/walletsolidity`;
const bscTo=`0x${'22'.repeat(20)}`,bscFrom=`0x${'11'.repeat(20)}`;
const bscHash=`0x${'ab'.repeat(32)}`,bscParent=`0x${'bc'.repeat(32)}`,bscTx=`0x${'cd'.repeat(32)}`;
const word=(hex:string)=>hex.replace(/^0x/,'').padStart(64,'0');
const json=(value:unknown,status=200,headers?:HeadersInit)=>new Response(JSON.stringify(value),{status,headers});
const bscHeader=()=>({number:'0x64',hash:bscHash,parentHash:bscParent,timestamp:'0x6553f100',transactions:[bscTx]});
const bscLog=()=>({address:ASSETS.bsc.contract,topics:[`0x${TRANSFER_TOPIC}`,`0x${word(bscFrom)}`,`0x${word(bscTo)}`],
  data:`0x${(2n**200n+123n).toString(16).padStart(64,'0')}`,blockNumber:'0x64',blockHash:bscHash,transactionHash:bscTx,transactionIndex:'0x0',logIndex:'0x1',removed:false});
type BscFixture={chainId:string;header:ReturnType<typeof bscHeader>;logs:unknown[];receipt:Record<string,unknown>;requests:{method:string;params:unknown[]}[]};
function bscFixture() {
  const f:BscFixture={chainId:'0x38',header:bscHeader(),logs:[bscLog()],receipt:{status:'0x1',transactionHash:bscTx,transactionIndex:'0x0',blockNumber:'0x64',blockHash:bscHash,logs:[bscLog()]},requests:[]};
  const request:typeof fetch=async(input,init)=>{
    assert.equal(String(input),bscRpc);
    assert.equal(init?.method,'POST');
    assert.equal(init?.redirect,'error');
    assert.deepEqual(init?.headers,{'content-type':'application/json','accept':'application/json'});
    const call=JSON.parse(String(init?.body)); f.requests.push(call);
    let result:unknown;
    if (call.method==='eth_chainId') result=f.chainId;
    else if (call.method==='eth_getBlockByNumber') result=f.header;
    else if (call.method==='eth_getLogs') result=f.logs;
    else if (call.method==='eth_getTransactionReceipt') result=f.receipt;
    else throw new Error('unexpected RPC');
    return json({jsonrpc:'2.0',id:call.id,result});
  };
  return {f,reader:new AlchemyBscReader(testApiKey,{fetch:request})};
}
test('Alchemy readers reject unsafe key path segments before transport',()=>{
  for(const Reader of [AlchemyBscReader,AlchemyTronReader]) {
    for(const key of ['', 'key/next', '..', 'key?query', 'key#fragment', '%2f', 'key\n', 'key with spaces', 'a'.repeat(129)]) {
      assert.throws(()=>new Reader(key),{message:'ALCHEMY_API_KEY is missing or invalid'});
    }
  }
});
test('BSC finalized USDT reader preserves uint256 precision and binds receipt, block and recipient',async()=>{
  const {f,reader}=bscFixture();
  assert.deepEqual(await reader.head(),{height:100,hash:bscHash,timestamp:1_700_000_000_000});
  const result=await reader.block(100,[bscTo.toUpperCase().replace('0X','0x')]);
  assert.equal(result.transfers[0].amountAtomic,(2n**200n+123n).toString());
  assert.equal(result.transfers[0].to,bscTo); assert.equal(result.transfers[0].from,bscFrom);
  assert.equal(result.transfers[0].tokenContract,ASSETS.bsc.contract);
  assert.equal(result.transfers[0].blockHash,bscHash);
  assert.equal(f.requests.filter(r=>r.method==='eth_getLogs').length,1);
  const filter=(f.requests.find(r=>r.method==='eth_getLogs')!.params[0]) as Record<string,unknown>;
  assert.equal(filter.fromBlock,'0x64');assert.equal(filter.toBlock,'0x64');assert.equal(filter.address,ASSETS.bsc.contract);
  assert.deepEqual(filter.topics,[`0x${TRANSFER_TOPIC}`]);
});
test('BSC filtering uses one request for many addresses; foreign recipients never credit',async()=>{
  const {f,reader}=bscFixture();
  const addresses=Array.from({length:250},(_,n)=>`0x${(n+1000).toString(16).padStart(40,'0')}`);
  assert.deepEqual((await reader.block(100,addresses)).transfers,[]);
  assert.equal(f.requests.filter(r=>r.method==='eth_getLogs').length,1);
  assert.equal(f.requests.filter(r=>r.method==='eth_getTransactionReceipt').length,0);
});
test('BSC rejects wrong network and unsupported finality without a confirmations fallback',async()=>{
  const {f,reader}=bscFixture();f.chainId='0x61';
  await assert.rejects(reader.head(),(e:unknown)=>e instanceof PaymentError && e.code==='wrong_rpc_network');
  const methods:string[]=[];
  const noFinality=new AlchemyBscReader(testApiKey,{fetch:async(_input,init)=>{
    const r=JSON.parse(String(init?.body));methods.push(r.method);
    return json(r.method==='eth_chainId'?{jsonrpc:'2.0',id:r.id,result:'0x38'}:{jsonrpc:'2.0',id:r.id,error:{code:-32602}});
  }});
  await assert.rejects(noFinality.head());assert.deepEqual(methods,['eth_chainId','eth_getBlockByNumber']);
});
test('BSC rejects tampered or incomplete event and receipt contracts',async t=>{
  const mutations:{name:string;change:(f:BscFixture)=>void}[]=[
    {name:'wrong token',change:f=>{(f.logs[0] as any).address=bscFrom;}},
    {name:'wrong finalized hash',change:f=>{f.header.hash=`0x${'ef'.repeat(32)}`;}},
    {name:'wrong transaction position',change:f=>{(f.logs[0] as any).transactionIndex='0x1';}},
    {name:'removed event',change:f=>{(f.logs[0] as any).removed=true;}},
    {name:'missing removed flag',change:f=>{delete (f.logs[0] as any).removed;}},
    {name:'malformed amount',change:f=>{(f.logs[0] as any).data='0x1';}},
    {name:'high address topic bits',change:f=>{(f.logs[0] as any).topics[2]=`0x${'ff'.repeat(32)}`;}},
    {name:'duplicate event',change:f=>{f.logs.push(structuredClone(f.logs[0]));}},
    {name:'failed receipt',change:f=>{f.receipt.status='0x0';}},
    {name:'missing receipt logs',change:f=>{delete f.receipt.logs;}},
    {name:'partial receipt logs',change:f=>{f.receipt.logs=[];}},
    {name:'extra receipt event missing in getLogs',change:f=>{const l=bscLog();l.logIndex='0x2';(f.receipt.logs as unknown[]).push(l);}},
    {name:'receipt other block',change:f=>{f.receipt.blockHash=bscParent;}},
  ];
  for (const m of mutations) await t.test(m.name,async()=>{
    const {f,reader}=bscFixture(); await reader.head();m.change(f);
    await assert.rejects(reader.block(100,[bscTo]),(e:unknown)=>e instanceof PaymentError && e.code==='invalid_rpc_response');
  });
});
test('BSC mint from zero is a valid event while zero amount does not credit',async()=>{
  const {f,reader}=bscFixture();
  for (const l of [f.logs[0],(f.receipt.logs as any[])[0]] as any[]) l.topics[1]=`0x${'0'.repeat(64)}`;
  assert.equal((await reader.block(100,[bscTo])).transfers[0].from,`0x${'0'.repeat(40)}`);
  for (const l of [f.logs[0],(f.receipt.logs as any[])[0]] as any[]) l.data=`0x${'0'.repeat(64)}`;
  assert.deepEqual((await reader.block(100,[bscTo])).transfers,[]);
});
test('RPC HTTP429 honors Retry-After across ticks and then retries the same read',async()=>{
  let now=0,calls=0;
  const reader=new AlchemyBscReader(testApiKey,{now:()=>now,fetch:async(_input,init)=>{
    calls++;const r=JSON.parse(String(init?.body));
    if(calls===1)return json({},429,{'retry-after':'10'});
    return json({jsonrpc:'2.0',id:r.id,result:r.method==='eth_chainId'?'0x38':bscHeader()});
  }});
  await assert.rejects(reader.head(),(e:unknown)=>e instanceof PaymentError && e.code==='rpc_rate_limited' && e.retryAfter===10);
  now=9_999;await assert.rejects(reader.head(),(e:unknown)=>e instanceof PaymentError && e.code==='rpc_backoff');assert.equal(calls,1);
  now=10_000;assert.equal((await reader.head()).height,100);assert.equal(calls,3);
});
test('absurd Retry-After cannot overflow into a permanent Infinity backoff',async()=>{
  const reader=new AlchemyBscReader(testApiKey,{now:()=>0,fetch:async()=>json({},429,{'retry-after':'9'.repeat(400)})});
  await assert.rejects(reader.head(),(e:unknown)=>e instanceof PaymentError && e.retryAfter===60);
  await assert.rejects(reader.head(),(e:unknown)=>e instanceof PaymentError && e.code==='rpc_backoff' && e.retryAfter===60);
});
test('parallel successful getLogs cannot erase block-header HTTP429 backoff',async()=>{
  let calls=0,blockPhase=false;let release!:(value:Response)=>void;
  const reader=new AlchemyBscReader(testApiKey,{now:()=>0,fetch:async(_input,init)=>{
    calls++;const r=JSON.parse(String(init?.body));
    if(!blockPhase)return json({jsonrpc:'2.0',id:r.id,result:r.method==='eth_chainId'?'0x38':bscHeader()});
    if(r.method==='eth_getBlockByNumber')return json({},429,{'retry-after':'20'});
    return await new Promise<Response>(resolve=>{release=resolve;}).then(()=>json({jsonrpc:'2.0',id:r.id,result:[]}));
  }});
  await reader.head();blockPhase=true;
  await assert.rejects(reader.block(100,[bscTo]),(e:unknown)=>e instanceof PaymentError && e.code==='rpc_rate_limited');
  release(json({}));await new Promise<void>(resolve=>setImmediate(resolve));
  const before=calls;
  await assert.rejects(reader.head(),(e:unknown)=>e instanceof PaymentError && e.code==='rpc_backoff' && e.retryAfter===20);
  assert.equal(calls,before);
});
test('RPC rejects malformed/error/id mismatches and bounded response overflows',async t=>{
  for(const result of ['not json',JSON.stringify({jsonrpc:'2.0',id:500,result:'0x38'}),JSON.stringify({jsonrpc:'2.0',id:1,error:{code:-1},result:'0x38'}),'x'.repeat(65)])
    await t.test(result.slice(0,25),async()=>{
      const reader=new AlchemyBscReader(testApiKey,{maxResponseBytes:64,fetch:async()=>new Response(result)});
      await assert.rejects(reader.head(),PaymentError);
    });
});
test('RPC timeout aborts transport and emits a sanitized retryable error',async()=>{
  const reader=new AlchemyBscReader(testApiKey,{timeoutMs:5,fetch:async(input,init)=>await new Promise<Response>((_resolve,reject)=>{
    init!.signal!.addEventListener('abort',()=>reject(new Error(`Transport failed for ${String(input)}`)),{once:true});
  })});
  await assert.rejects(reader.head(),(e:unknown)=>e instanceof PaymentError && e.code==='rpc_timeout' && !e.message.includes(testApiKey));
});
test('service abort interrupts an active RPC and prevents new transport calls',async()=>{
  const controller=new AbortController();let calls=0;
  const reader=new AlchemyBscReader(testApiKey,{signal:controller.signal,fetch:async(_input,init)=>{
    calls++;return await new Promise<Response>((_resolve,reject)=>init!.signal!.addEventListener('abort',()=>reject(new Error('aborted')),{once:true}));
  }});
  const head=reader.head();controller.abort();
  await assert.rejects(head,(e:unknown)=>e instanceof PaymentError && e.code==='rpc_aborted');
  await assert.rejects(reader.head(),(e:unknown)=>e instanceof PaymentError && e.code==='rpc_aborted');assert.equal(calls,1);
});

const tronTo=normalizeAddress('tron',`41${'22'.repeat(20)}`),tronFrom=normalizeAddress('tron',`41${'11'.repeat(20)}`);
const tronHash='0000000000000064'+'ab'.repeat(24),tronParent='0000000000000063'+'bc'.repeat(24),tronTx='cd'.repeat(32);
const tronTime=1_700_000_000_000;
const tronLog=()=>({address:'a614f803b6fd780986a42c78ec9c7f77e6ded13c',topics:[TRANSFER_TOPIC,word('11'.repeat(20)),word('22'.repeat(20))],data:word('f4240')});
const tronHeader=()=>({blockID:tronHash,block_header:{raw_data:{number:100,parentHash:tronParent,timestamp:tronTime}},transactions:[{txID:tronTx,raw_data:{contract:[{type:'TriggerSmartContract'}]},ret:[{contractRet:'SUCCESS'}]}]});
type TronFixture={genesis:string;header:ReturnType<typeof tronHeader>;receipts:any[]};
function tronFixture(){
  const f:TronFixture={genesis:TRON_MAINNET_GENESIS,header:tronHeader(),receipts:[{id:tronTx,blockNumber:100,blockTimeStamp:tronTime,receipt:{result:'SUCCESS'},log:[tronLog()]}]};
  const reader=new AlchemyTronReader(testApiKey,{fetch:async(input,init)=>{
    const url=String(input);
    assert.equal(init?.method,'POST');assert.equal(init?.redirect,'error');
    const body=JSON.parse(String(init?.body));
    if(url===`${tronRpc}/getblockbynum` && body.num===0)return json({blockID:f.genesis});
    if(url===`${tronRpc}/getnowblock`||url===`${tronRpc}/getblockbynum`)return json(f.header);
    if(url===`${tronRpc}/gettransactioninfobyblocknum`)return json(f.receipts);
    throw new Error('unexpected TRON endpoint');
  }});
  return {f,reader};
}
test('TRON validates mainnet genesis and solidified receipt coverage with exact event identity',async()=>{
  const {reader}=tronFixture();assert.deepEqual(await reader.head(),{height:100,hash:tronHash,timestamp:tronTime});
  const block=await reader.block(100,[tronTo]);assert.equal(block.transfers.length,1);
  assert.deepEqual(block.transfers[0],{txHash:tronTx,logIndex:0,tokenContract:ASSETS.tron.contract,from:tronFrom,to:tronTo,amountAtomic:'1000000',blockNumber:100,blockHash:tronHash,timestamp:tronTime});
});
test('TRON ignores foreign token and recipient and accepts no-result plain TRX receipts',async()=>{
  const {f,reader}=tronFixture();f.receipts[0].log[0].address='33'.repeat(20);
  assert.deepEqual((await reader.block(100,[tronTo])).transfers,[]);
  f.receipts[0].log=[tronLog()];assert.deepEqual((await reader.block(100,[tronFrom])).transfers,[]);
  f.header.transactions[0].raw_data.contract[0].type='TransferContract';f.receipts[0].receipt={net_usage:281};delete f.receipts[0].log;
  assert.deepEqual((await reader.block(100,[tronTo])).transfers,[]);
});
test('TRON protobuf-omitted empty log data/topics are valid only for unrelated events',async()=>{
  const {f,reader}=tronFixture();
  f.receipts[0].log=[{address:'33'.repeat(20)},tronLog()];
  const result=await reader.block(100,[tronTo]);assert.equal(result.transfers[0].logIndex,1);
  delete f.receipts[0].log[1].data;
  await assert.rejects(reader.block(100,[tronTo]),PaymentError);
});
test('TRON rejects malformed/incomplete data without advancing over missing receipts',async t=>{
  const mutations:{name:string;change:(f:TronFixture)=>void}[]=[
    {name:'wrong network',change:f=>{f.genesis='00'.repeat(32);}},
    {name:'receipt missing',change:f=>{f.receipts=[];}},
    {name:'duplicate receipt',change:f=>{f.receipts.push(structuredClone(f.receipts[0]));}},
    {name:'receipt unknown id',change:f=>{f.receipts[0].id='ef'.repeat(32);}},
    {name:'wrong block height',change:f=>{f.receipts[0].blockNumber=99;}},
    {name:'wrong timestamp',change:f=>{f.receipts[0].blockTimeStamp++;}},
    {name:'missing contract receipt result',change:f=>{delete f.receipts[0].receipt.result;}},
    {name:'failed receipt claims logs',change:f=>{f.receipts[0].receipt.result='OUT_OF_ENERGY';}},
    {name:'failed transaction claims logs',change:f=>{f.header.transactions[0].ret[0].contractRet='REVERT';}},
    {name:'malformed data',change:f=>{f.receipts[0].log[0].data='-1';}},
    {name:'forged topic padding',change:f=>{f.receipts[0].log[0].topics[2]='ff'.repeat(32);}},
    {name:'event missing topic',change:f=>{f.receipts[0].log[0].topics.pop();}},
    {name:'block ID height mismatch',change:f=>{f.header.blockID='00'.repeat(32);}},
  ];
  for(const m of mutations)await t.test(m.name,async()=>{const {f,reader}=tronFixture();m.change(f);await assert.rejects(reader.block(100,[tronTo]),PaymentError);});
});
test('TRON legitimate failed contract transaction creates no credit, empty block is valid',async()=>{
  const {f,reader}=tronFixture();f.header.transactions[0].ret[0].contractRet='OUT_OF_ENERGY';
  f.receipts[0].receipt.result='OUT_OF_ENERGY';f.receipts[0].result='FAILED';delete f.receipts[0].log;
  assert.deepEqual((await reader.block(100,[tronTo])).transfers,[]);
  f.header.transactions=[];f.receipts=[];assert.deepEqual((await reader.block(100,[tronTo])).transfers,[]);
});
