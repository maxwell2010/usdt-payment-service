import {PaymentError, type Chain, type ChainReader, type ConfirmedBlock, type Cursor} from './types.ts';

export interface ScannerStore {
  getCursor(chain:Chain):Cursor|null;
  initializeCursor(chain:Chain,height:number,hash:string,now?:number):unknown;
  getAddresses(chain:Chain):string[];
  ingestBlock(block:ConfirmedBlock,now?:number):unknown;
}
export type ScannerStatus={ready:boolean;lastSuccessAt:number|null;error?:string};
export type ScannerOptions={maxBlocksPerTick?:number;maxHeadAgeMs?:number;now?:()=>number};

/** One sequential consumer per chain per instance. The owning service must also
 * enforce one process per database; the store atomically enforces cursor CAS.
 * First startup sets a watermark only, deliberately omitting historical replay.
 */
export class PaymentScanner {
  private readonly readers=new Map<Chain,ChainReader>();
  private readonly active=new Map<Chain,Promise<void>>();
  private readonly states=new Map<Chain,ScannerStatus>();
  private readonly maxBlocks:number;
  private readonly now:()=>number;
  private readonly maxHeadAgeMs:number;
  constructor(private readonly store:ScannerStore,readers:readonly ChainReader[],options:ScannerOptions={}) {
    this.maxBlocks=options.maxBlocksPerTick??10;
    if (!Number.isSafeInteger(this.maxBlocks) || this.maxBlocks<1 || this.maxBlocks>1000) throw new Error('invalid_scanner_options');
    this.maxHeadAgeMs=options.maxHeadAgeMs??120_000;
    if (!Number.isSafeInteger(this.maxHeadAgeMs) || this.maxHeadAgeMs<1 || this.maxHeadAgeMs>86_400_000) throw new Error('invalid_scanner_options');
    this.now=options.now??Date.now;
    for (const reader of readers) {
      if (this.readers.has(reader.chain)) throw new Error('duplicate_chain_reader');
      this.readers.set(reader.chain,reader); this.states.set(reader.chain,{ready:false,lastSuccessAt:null});
    }
  }
  status(chain:Chain):ScannerStatus { return {...(this.states.get(chain)??{ready:false,lastSuccessAt:null,error:'chain_not_configured'})}; }
  async tick():Promise<void> {
    const results=await Promise.allSettled([...this.readers.keys()].map(chain=>this.tickChain(chain)));
    const errors=results.filter((r):r is PromiseRejectedResult=>r.status==='rejected').map(r=>r.reason);
    if (errors.length) throw new AggregateError(errors,'payment_scanner_failed');
  }
  tickChain(chain:Chain):Promise<void> {
    const existing=this.active.get(chain); if (existing) return existing;
    const reader=this.readers.get(chain); if (!reader) return Promise.reject(new PaymentError('chain_not_configured',503));
    const work=this.scan(reader).finally(()=>{this.active.delete(chain);});
    this.active.set(chain,work); return work;
  }
  private async scan(reader:ChainReader):Promise<void> {
    const previous=this.status(reader.chain);
    try {
      const head=await reader.head();
      if (!Number.isSafeInteger(head.height) || head.height<0 || typeof head.hash!=='string' || !head.hash) throw new PaymentError('invalid_chain_head',503);
      if (head.timestamp!==undefined && (!Number.isSafeInteger(head.timestamp) || head.timestamp<1 || this.now()-head.timestamp>this.maxHeadAgeMs || head.timestamp-this.now()>30_000)) throw new PaymentError('chain_head_stale',503);
      let cursor=this.store.getCursor(reader.chain);
      if (!cursor) {
        this.store.initializeCursor(reader.chain,head.height,head.hash,this.now());
        cursor=this.store.getCursor(reader.chain);
      }
      if (!cursor || cursor.height>head.height || (cursor.height===head.height && cursor.hash!==head.hash)) throw new PaymentError('chain_cursor_mismatch',503);
      for (let count=0;cursor.height<head.height && count<this.maxBlocks;count++) {
        const addresses=this.store.getAddresses(reader.chain);
        const block=await reader.block(cursor.height+1,addresses);
        // Imported addresses can change while RPC is awaited. Assignment of an
        // existing pool address does not change this set; importing does.
        if (JSON.stringify([...new Set(addresses)].sort())!==JSON.stringify([...new Set(this.store.getAddresses(reader.chain))].sort())) throw new PaymentError('address_pool_changed',503);
        if (block.chain!==reader.chain || block.height!==cursor.height+1 || block.parentHash!==cursor.hash || (block.height===head.height && block.hash!==head.hash)) throw new PaymentError('chain_cursor_mismatch',503);
        this.store.ingestBlock(block,this.now());
        const saved=this.store.getCursor(reader.chain);
        if (!saved || saved.height!==block.height || saved.hash!==block.hash) throw new PaymentError('cursor_not_committed',503);
        cursor=saved;
      }
      const caughtUp=cursor.height===head.height && cursor.hash===head.hash;
      this.states.set(reader.chain,{ready:caughtUp,lastSuccessAt:caughtUp?this.now():previous.lastSuccessAt,...(!caughtUp?{error:'chain_catching_up'}:{})});
    } catch (error) {
      this.states.set(reader.chain,{ready:false,lastSuccessAt:previous.lastSuccessAt,error:error instanceof PaymentError?error.code:'chain_scan_failed'});
      throw error instanceof PaymentError?error:new PaymentError('chain_scan_failed',503);
    }
  }
}
