import {ASSETS, normalizeAddress, TRANSFER_TOPIC} from './assets.ts';
import {parseAlchemyApiKey} from './config.ts';
import {PaymentError, type Chain, type ChainReader, type ConfirmedBlock, type Cursor, type Transfer} from './types.ts';

/** Alchemy endpoints verified 2026-11-11:
 * https://www.alchemy.com/docs/reference/node-supported-chains
 * https://www.alchemy.com/docs/chains/tron/tron-solidity-http-api-endpoints/tron-solidity-http-api-endpoints/get-transaction-info-by-block-number
 * Chain wire contracts verified 2026-11-10:
 * https://docs.bnbchain.org/bnb-smart-chain/developers/json_rpc/bsc-api-list/
 * https://developers.tron.network/reference/gettransactioninfobyblocknum-1
 * https://developers.tron.network/docs/confirmation-semantics
 * Genesis: https://namespaces.chainagnostic.org/tron/caip2 (cross-checked against
 * public mainnet and https://developers.tron.network/reference/eth_chainid).
 * RPC responses remain a trust boundary: this is not a light-client proof verifier.
 */
export const TRON_MAINNET_GENESIS = '00000000000000001ebf88508a03865c71d452e25f4d51194196a1d22b6653dc';
export type ReaderOptions = {
  fetch?:typeof fetch; timeoutMs?:number; maxResponseBytes?:number;
  retryDelayMs?:number; now?:()=>number; signal?:AbortSignal;
};
const ALCHEMY_HOSTS: Record<Chain, string> = {
  bsc: 'bnb-mainnet.g.alchemy.com',
  tron: 'tron-mainnet.g.alchemy.com',
};
function alchemyEndpoint(chain: Chain, apiKey: string): string {
  return `https://${ALCHEMY_HOSTS[chain]}/v2/${parseAlchemyApiKey(apiKey)}`;
}
type ObjectValue = Record<string, unknown>;
const MAX_ITEMS = 20_000;
function invalid():never { throw new PaymentError('invalid_rpc_response', 503); }
function object(value:unknown):ObjectValue {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return invalid();
  return value as ObjectValue;
}
function array(value:unknown, limit=MAX_ITEMS):unknown[] {
  if (!Array.isArray(value) || value.length > limit) return invalid();
  return value;
}
function integer(value:unknown, minimum=0):number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < minimum) return invalid();
  return value;
}
function hex(value:unknown, bytes:number, prefix:boolean):string {
  if (typeof value !== 'string' || !new RegExp(`^${prefix?'0x':''}[0-9a-fA-F]{${bytes*2}}$`).test(value)) return invalid();
  return value.toLowerCase();
}
function quantity(value:unknown):number {
  if (typeof value !== 'string' || !/^0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)$/.test(value)) return invalid();
  const n=BigInt(value);
  if (n>BigInt(Number.MAX_SAFE_INTEGER)) return invalid();
  return Number(n);
}
function timestamp(value:unknown):number { return integer(value,1); }
function address(chain:Chain, value:unknown):string {
  if (typeof value !== 'string') return invalid();
  try { return normalizeAddress(chain,value); } catch { return invalid(); }
}
function topicAddress(chain:Chain,value:unknown,prefix:boolean):string {
  const word=hex(value,32,prefix).replace(/^0x/,'');
  if (!/^0{24}/.test(word)) return invalid();
  // Mint/burn events may contain the zero address, which is forbidden as a
  // configured receiving wallet but is valid on the blockchain event wire.
  if (/^0{64}$/.test(word)) return chain==='bsc'?`0x${'0'.repeat(40)}`:'T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb';
  return address(chain,chain==='bsc'?`0x${word.slice(24)}`:`41${word.slice(24)}`);
}
function amount(value:unknown,prefix:boolean):string {
  const n=BigInt(`0x${hex(value,32,prefix).replace(/^0x/,'')}`);
  // Zero-value events do not discharge invoices and are harmless to ignore.
  return n.toString();
}
function optionsPositive(value:number|undefined,fallback:number,max:number):number {
  const n=value??fallback;
  if (!Number.isSafeInteger(n) || n<1 || n>max) throw new Error('invalid_reader_options');
  return n;
}

/** No retries hide an uncertain read. A failed request delays the next tick, which
 * retries the same persistent block cursor. The URL/body is never put in errors. */
class JsonTransport {
  private readonly request:typeof fetch;
  private readonly timeoutMs:number;
  private readonly maxBytes:number;
  private readonly retryDelayMs:number;
  private readonly now:()=>number;
  private readonly signal:AbortSignal|undefined;
  private nextAllowed=0;
  private failures=0;
  private failureGeneration=0;
  constructor(private readonly endpoint:string, options:ReaderOptions) {
    this.request=options.fetch??fetch;
    this.timeoutMs=optionsPositive(options.timeoutMs,12_000,120_000);
    this.maxBytes=optionsPositive(options.maxResponseBytes,16*1024*1024,64*1024*1024);
    this.retryDelayMs=optionsPositive(options.retryDelayMs,1_000,60_000);
    this.now=options.now??Date.now;
    this.signal=options.signal;
  }
  async post(path:string,body:unknown):Promise<unknown> {
    if (this.signal?.aborted) throw new PaymentError('rpc_aborted',503);
    if (this.now()<this.nextAllowed) throw new PaymentError('rpc_backoff',503,Math.ceil((this.nextAllowed-this.now())/1000));
    const generation=this.failureGeneration;
    const controller=new AbortController();
    const signal=this.signal?AbortSignal.any([controller.signal,this.signal]):controller.signal;
    const timer=setTimeout(()=>controller.abort(),this.timeoutMs);
    let retryMs=0;
    try {
      const response=await this.request(`${this.endpoint}${path}`,{
        method:'POST',headers:{'content-type':'application/json','accept':'application/json'},
        body:JSON.stringify(body),signal,redirect:'error',
      });
      if (!response.ok) {
        if (response.status===429) {
          const after=response.headers.get('retry-after');
          if (after && /^\d+$/.test(after)) retryMs=Number(after)*1000;
          else if (after) { const date=Date.parse(after); if (Number.isFinite(date)) retryMs=Math.max(0,date-this.now()); }
          // Malformed/absurd Retry-After must not overflow the retry watermark.
          if (!Number.isFinite(retryMs) || retryMs>86_400_000) retryMs=60_000;
        }
        await response.body?.cancel();
        throw new PaymentError(response.status===429?'rpc_rate_limited':'rpc_unavailable',503);
      }
      const declared=response.headers.get('content-length');
      if (declared && (!/^\d+$/.test(declared) || Number(declared)>this.maxBytes)) {
        await response.body?.cancel(); return invalid();
      }
      if (!response.body) return invalid();
      const reader=response.body.getReader();
      const chunks:Uint8Array[]=[]; let bytes=0;
      try {
        while (true) {
          const part=await reader.read(); if (part.done) break;
          bytes+=part.value.byteLength;
          if (bytes>this.maxBytes) { await reader.cancel(); return invalid(); }
          chunks.push(part.value);
        }
      } finally { reader.releaseLock(); }
      let result:unknown;
      try { result=JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { return invalid(); }
      // A parallel successful block-header read must not erase a 429 received
      // by its getLogs sibling while both requests were in flight.
      if (this.failureGeneration===generation) { this.failures=0; this.nextAllowed=0; }
      return result;
    } catch (error) {
      if (this.signal?.aborted) throw new PaymentError('rpc_aborted',503);
      this.failureGeneration++;
      this.failures=Math.min(this.failures+1,7);
      const delay=Math.max(retryMs,Math.min(60_000,this.retryDelayMs*2**(this.failures-1)));
      this.nextAllowed=this.now()+delay;
      if (error instanceof PaymentError) throw new PaymentError(error.code,error.status,Math.ceil(delay/1000));
      throw new PaymentError(controller.signal.aborted?'rpc_timeout':'rpc_unavailable',503,Math.ceil(delay/1000));
    } finally { clearTimeout(timer); }
  }
}

type BscHeader={height:number;hash:string;parentHash:string;timestamp:number;transactions:string[]};
function bscHeader(value:unknown):BscHeader {
  const b=object(value); const seconds=quantity(b.timestamp);
  const transactions=array(b.transactions).map(t=>hex(t,32,true));
  if (new Set(transactions).size!==transactions.length || seconds>Number.MAX_SAFE_INTEGER/1000) return invalid();
  return {height:quantity(b.number),hash:hex(b.hash,32,true),parentHash:hex(b.parentHash,32,true),timestamp:timestamp(seconds*1000),transactions};
}

export class AlchemyBscReader implements ChainReader {
  readonly chain='bsc' as const;
  private readonly http:JsonTransport;
  private id=0;
  private finalized:Cursor|null=null;
  constructor(apiKey:string,options:ReaderOptions={}) { this.http=new JsonTransport(alchemyEndpoint('bsc',apiKey),options); }
  private async rpc(method:string,params:unknown[]):Promise<unknown> {
    const id=++this.id; const body=object(await this.http.post('',{jsonrpc:'2.0',id,method,params}));
    if (body.jsonrpc!=='2.0' || body.id!==id || 'error' in body || !('result' in body)) return invalid();
    return body.result;
  }
  async head():Promise<Cursor> {
    if (quantity(await this.rpc('eth_chainId',[]))!==56) throw new PaymentError('wrong_rpc_network',503);
    // Never substitute latest-minus-confirmations when finalized is unsupported.
    const b=bscHeader(await this.rpc('eth_getBlockByNumber',['finalized',false]));
    this.finalized={height:b.height,hash:b.hash,timestamp:b.timestamp}; return {...this.finalized};
  }
  private log(value:unknown,b:BscHeader):{transfer:Transfer;index:number} {
    const l=object(value); const index=quantity(l.logIndex); const tx=hex(l.transactionHash,32,true);
    const txIndex=quantity(l.transactionIndex);
    if (l.removed!==false || hex(l.blockHash,32,true)!==b.hash || quantity(l.blockNumber)!==b.height || b.transactions[txIndex]!==tx) return invalid();
    const topics=array(l.topics,4);
    if (topics.length!==3 || hex(topics[0],32,true)!==`0x${TRANSFER_TOPIC}` || address('bsc',l.address)!==ASSETS.bsc.contract) return invalid();
    return {index,transfer:{txHash:tx,logIndex:index,tokenContract:ASSETS.bsc.contract,
      from:topicAddress('bsc',topics[1],true),to:topicAddress('bsc',topics[2],true),amountAtomic:amount(l.data,true),
      blockNumber:b.height,blockHash:b.hash,timestamp:b.timestamp}};
  }
  async block(height:number,recipients:readonly string[]):Promise<ConfirmedBlock> {
    integer(height);
    if (!this.finalized || height>this.finalized.height) await this.head();
    if (height>this.finalized!.height) throw new PaymentError('block_not_finalized',503);
    const tag=`0x${height.toString(16)}`;
    const [rawHeader,rawLogs]=await Promise.all([
      this.rpc('eth_getBlockByNumber',[tag,false]),
      this.rpc('eth_getLogs',[{fromBlock:tag,toBlock:tag,address:ASSETS.bsc.contract,topics:[`0x${TRANSFER_TOPIC}`]}]),
    ]);
    const b=bscHeader(rawHeader);
    if (b.height!==height || (height===this.finalized!.height && b.hash!==this.finalized!.hash)) return invalid();
    const targetSet=new Set(recipients.map(r=>address('bsc',r)));
    const logs:Transfer[]=[];
    let previousLog=-1;
    for (const entry of array(rawLogs)) {
      const {transfer,index}=this.log(entry,b);
      if (index<=previousLog) return invalid();
      previousLog=index;
      if (targetSet.has(transfer.to)) logs.push(transfer);
    }
    logs.sort((a,c)=>a.logIndex-c.logIndex);
    if (new Set(logs.map(l=>l.logIndex)).size!==logs.length) return invalid();
    for (const tx of new Set(logs.map(l=>l.txHash))) {
      const receipt=object(await this.rpc('eth_getTransactionReceipt',[tx]));
      if (quantity(receipt.status)!==1 || hex(receipt.transactionHash,32,true)!==tx || hex(receipt.blockHash,32,true)!==b.hash || quantity(receipt.blockNumber)!==height || b.transactions[quantity(receipt.transactionIndex)]!==tx) return invalid();
      const selected:Transfer[]=[]; let previous=-1;
      for (const entry of array(receipt.logs)) {
        const l=object(entry); const idx=quantity(l.logIndex);
        if (idx<=previous || l.removed!==false || hex(l.transactionHash,32,true)!==tx || hex(l.blockHash,32,true)!==b.hash || quantity(l.blockNumber)!==height || b.transactions[quantity(l.transactionIndex)]!==tx) return invalid();
        previous=idx;
        if (typeof l.data!=='string' || !/^0x(?:[0-9a-fA-F]{2})*$/.test(l.data)) return invalid();
        const topics=array(l.topics,16).map(t=>hex(t,32,true));
        const contract=address('bsc',l.address);
        if (contract===ASSETS.bsc.contract && topics[0]===`0x${TRANSFER_TOPIC}`) {
          const t=this.log(l,b).transfer; if (targetSet.has(t.to)) selected.push(t);
        }
      }
      const expected=logs.filter(l=>l.txHash===tx);
      if (JSON.stringify(selected)!==JSON.stringify(expected)) return invalid();
    }
    return {chain:'bsc',height,hash:b.hash,parentHash:b.parentHash,timestamp:b.timestamp,transfers:logs.filter(l=>l.amountAtomic!=='0')};
  }
}

type TronHeader={height:number;hash:string;parentHash:string;timestamp:number;transactions:ObjectValue[]};
function tronHeader(value:unknown):TronHeader {
  const b=object(value), raw=object(object(b.block_header).raw_data);
  const height=integer(raw.number), hash=hex(b.blockID,32,false);
  if (BigInt(`0x${hash.slice(0,16)}`)!==BigInt(height)) return invalid();
  const transactions=b.transactions===undefined?[]:array(b.transactions).map(object);
  const ids=transactions.map(t=>hex(t.txID,32,false));
  if (new Set(ids).size!==ids.length) return invalid();
  return {height,hash,parentHash:hex(raw.parentHash,32,false),timestamp:timestamp(raw.timestamp),transactions};
}

export class AlchemyTronReader implements ChainReader {
  readonly chain='tron' as const;
  private readonly http:JsonTransport;
  private identified=false;
  private finalized:Cursor|null=null;
  constructor(apiKey:string,options:ReaderOptions={}) { this.http=new JsonTransport(alchemyEndpoint('tron',apiKey),options); }
  private async post(path:string,body:unknown):Promise<unknown> {
    const result=await this.http.post(`/walletsolidity/${path}`,body);
    if (result && typeof result==='object' && !Array.isArray(result) && ('Error' in result || 'error' in result)) return invalid();
    return result;
  }
  async head():Promise<Cursor> {
    if (!this.identified) {
      // Proto3 omits the zero number/timestamp in the genesis header.
      const genesis=object(await this.post('getblockbynum',{num:0}));
      if (hex(genesis.blockID,32,false)!==TRON_MAINNET_GENESIS) throw new PaymentError('wrong_rpc_network',503);
      this.identified=true;
    }
    const b=tronHeader(await this.post('getnowblock',{}));
    this.finalized={height:b.height,hash:b.hash,timestamp:b.timestamp}; return {...this.finalized};
  }
  async block(height:number,recipients:readonly string[]):Promise<ConfirmedBlock> {
    integer(height,1);
    if (!this.finalized || height>this.finalized.height) await this.head();
    if (height>this.finalized!.height) throw new PaymentError('block_not_finalized',503);
    const b=tronHeader(await this.post('getblockbynum',{num:height}));
    if (b.height!==height || (height===this.finalized!.height && b.hash!==this.finalized!.hash)) return invalid();
    const targets=new Set(recipients.map(r=>address('tron',r)));
    const receipts=array(await this.post('gettransactioninfobyblocknum',{num:height}));
    if (receipts.length!==b.transactions.length) return invalid();
    const byId=new Map<string,ObjectValue>();
    for (const entry of receipts) {
      const r=object(entry), id=hex(r.id,32,false);
      if (byId.has(id) || integer(r.blockNumber)!==height || timestamp(r.blockTimeStamp)!==b.timestamp) return invalid();
      byId.set(id,r);
    }
    const transfers:Transfer[]=[];
    for (const transaction of b.transactions) {
      const id=hex(transaction.txID,32,false), r=byId.get(id); if (!r) return invalid();
      const ret=array(transaction.ret,1); if (ret.length!==1) return invalid();
      const outcome=object(ret[0]).contractRet;
      if (typeof outcome!=='string' || !/^[A-Z_]+$/.test(outcome)) return invalid();
      const details=object(r.receipt);
      if (r.result!==undefined && r.result!=='FAILED' && r.result!=='SUCESS') return invalid();
      const rawLogs=r.log===undefined?[]:array(r.log);
      const contracts=array(object(transaction.raw_data).contract,10).map(object);
      const smart=contracts.some(c=>c.type==='TriggerSmartContract' || c.type==='CreateSmartContract');
      if (details.result!==undefined && (typeof details.result!=='string' || !/^[A-Z_]+$/.test(details.result))) return invalid();
      if ((smart || rawLogs.length>0) && details.result===undefined) return invalid();
      // Ordinary TRX transfers legitimately omit receipt.result. Contract receipts
      // must explicitly succeed; failed receipts never create payment credits.
      const success=outcome==='SUCCESS' && r.result!=='FAILED' && (!smart && rawLogs.length===0 || details.result==='SUCCESS');
      if (!success) { if (rawLogs.length>0) return invalid(); continue; }
      for (let logIndex=0;logIndex<rawLogs.length;logIndex++) {
        const l=object(rawLogs[logIndex]);
        const contract=address('tron',`41${hex(l.address,20,false)}`);
        // Proto3 JSON omits empty bytes/repeated fields on unrelated LOG0 or
        // indexed-only events. USDT Transfer still requires all three topics
        // and the exact 32-byte uint below.
        const topics=(l.topics===undefined?[]:array(l.topics,16)).map(t=>hex(t,32,false));
        const data=l.data===undefined?'':l.data;
        if (typeof data!=='string' || !/^(?:[0-9a-fA-F]{2})*$/.test(data)) return invalid();
        if (contract!==ASSETS.tron.contract || topics[0]!==TRANSFER_TOPIC) continue;
        if (topics.length!==3) return invalid();
        const from=topicAddress('tron',topics[1],false),to=topicAddress('tron',topics[2],false);
        const atomic=amount(data,false);
        if (targets.has(to) && atomic!=='0') transfers.push({txHash:id,logIndex,tokenContract:ASSETS.tron.contract,from,to,amountAtomic:atomic,blockNumber:height,blockHash:b.hash,timestamp:b.timestamp});
      }
    }
    // Detect a source changing the block between its body and receipts reads.
    const checked=tronHeader(await this.post('getblockbynum',{num:height}));
    if (checked.hash!==b.hash || checked.height!==height || checked.parentHash!==b.parentHash || checked.timestamp!==b.timestamp || JSON.stringify(checked.transactions.map(t=>t.txID))!==JSON.stringify(b.transactions.map(t=>t.txID))) return invalid();
    return {chain:'tron',height,hash:b.hash,parentHash:b.parentHash,timestamp:b.timestamp,transfers};
  }
}
