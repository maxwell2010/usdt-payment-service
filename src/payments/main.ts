import {createServer} from 'node:http';
import {loadPaymentConfig,parseAlchemyApiKey} from './config.ts';
import {PaymentStore} from './store.ts';
import {AlchemyBscReader,AlchemyTronReader} from './chains.ts';
import {PaymentScanner} from './scanner.ts';
import {PaymentDispatcher} from './dispatcher.ts';
import {createPaymentsApp} from './http.ts';
import {ServiceLease} from './lease.ts';
import {PaymentError,type Chain} from './types.ts';
import {postWebhook} from './security.ts';

async function main(){
  const alchemyApiKey=parseAlchemyApiKey(process.env.ALCHEMY_API_KEY);
  const config=loadPaymentConfig(),store=new PaymentStore(config.databasePath,config.masterKey);
  config.masterKey.fill(0);
  const lease=new ServiceLease(store.db);
  if(!lease.acquire()){store.close();throw new Error('Payment service already owns this database');}
  let stopping=false;
  const stopController=new AbortController();
  const active=new Set<Promise<void>>();
  const timers=new Map<ReturnType<typeof setTimeout>,()=>void>();
  const pause=(ms:number)=>new Promise<void>(resolve=>{if(stopping){resolve();return;}const timer=setTimeout(()=>{timers.delete(timer);resolve();},ms);timers.set(timer,resolve);});
  const scanner=new PaymentScanner({
    getCursor:chain=>{lease.assertHeld();return store.getCursor(chain);},
    initializeCursor:(chain,height,hash,now)=>{lease.assertHeld();return store.initializeCursor(chain,height,hash,now);},
    getAddresses:chain=>store.getAddresses(chain),
    ingestBlock:(block,now)=>{lease.assertHeld();store.ingestBlock(block,now);}
  },[new AlchemyBscReader(alchemyApiKey,{signal:stopController.signal}),new AlchemyTronReader(alchemyApiKey,{signal:stopController.signal})],{maxBlocksPerTick:25});
  const dispatcher=new PaymentDispatcher({
    claimDelivery:(now,leaseMs,excludedProjects)=>{lease.assertHeld();return store.claimDelivery(now,leaseMs,excludedProjects);},
    completeDelivery:(id,success,now,retryAfterMs)=>{lease.assertHeld();store.completeDelivery(id,success,now,retryAfterMs);}
  },(url,body,secret,event,now)=>postWebhook(url,body,secret,event,now,stopController.signal),Date.now,()=>stopping);
  const ready=(chain:Chain)=>{
    try{lease.assertHeld();}catch{return false;}
    const status=scanner.status(chain);
    return !stopping&&status.ready&&status.lastSuccessAt!==null&&Date.now()-status.lastSuccessAt<120_000;
  };
  const app=createPaymentsApp({
    authenticate:key=>store.authenticate(key),
    createInvoice:(project,input,now)=>store.createInvoice(project,input,now,()=>{if(!ready(input.chain))throw new PaymentError('chain_not_ready',503,5);}),
    getInvoice:(...args)=>store.getInvoice(...args)
  },{readiness:()=>ready('bsc')&&ready('tron')});
  const server=createServer(app);
  server.requestTimeout=15_000;server.headersTimeout=10_000;server.keepAliveTimeout=5_000;server.maxHeadersCount=32;
  let heartbeat:ReturnType<typeof setInterval>|undefined;
  const shutdown=async()=>{
    if(stopping)return;stopping=true;
    stopController.abort();
    for(const [timer,resolve] of timers){clearTimeout(timer);resolve();}timers.clear();
    const closed=new Promise<void>(resolve=>{if(server.listening)server.close(()=>resolve());else resolve();});
    server.closeIdleConnections();
    await Promise.allSettled([...active]);await closed;
    if(heartbeat)clearInterval(heartbeat);
    lease.release();store.close();
  };
  const run=(work:()=>Promise<void>)=>{const promise=work();active.add(promise);void promise.finally(()=>active.delete(promise));};
  try{
    await new Promise<void>((resolve,reject)=>{server.once('error',reject);server.listen(config.port,config.host,()=>{server.removeListener('error',reject);resolve();});});
    heartbeat=setInterval(()=>{try{if(!lease.renew())throw new Error('lease_lost');}catch{process.exitCode=1;void shutdown();}},5000);
    for(const chain of ['bsc','tron'] as const)run(async()=>{
      while(!stopping){
        try{await scanner.tickChain(chain);}catch{/* Health remains false, persistent cursor is retained. */}
        await pause(scanner.status(chain).error==='chain_catching_up'?100:config.pollIntervalMs);
      }
    });
    run(async()=>{while(!stopping){try{lease.assertHeld();store.expireInvoices();await dispatcher.tick();}catch{/* Durable delivery will be retried. */}await pause(1000);}});
    process.once('SIGINT',()=>void shutdown());process.once('SIGTERM',()=>void shutdown());
    console.log(`Payment service listening on loopback port ${config.port}; readiness requires both chains`);
  }catch(error){await shutdown();throw error;}
}
main().catch(()=>{console.error('Payment service startup failed. Check ALCHEMY_API_KEY, local configuration and database ownership.');process.exitCode=1;});
