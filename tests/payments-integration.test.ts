import {IPV4_LOOPBACK} from '../src/payments/config.ts';
import test from 'node:test';
import assert from 'node:assert/strict';
import {once} from 'node:events';
import {mkdtempSync,writeFileSync,existsSync,readFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve,sep} from 'node:path';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {HDKey} from '@scure/bip32';
import {derivePaymentAddress} from '../src/payments/hd.ts';
import {PaymentStore} from '../src/payments/store.ts';
import {PaymentScanner} from '../src/payments/scanner.ts';
import {PaymentDispatcher} from '../src/payments/dispatcher.ts';
import {createPaymentsApp} from '../src/payments/http.ts';
import {normalizeAddress,ASSETS} from '../src/payments/assets.ts';
import {verifyWebhookSignature,webhookSignature} from '../src/payments/security.ts';
import type {Chain,ChainReader,ConfirmedBlock,Invoice} from '../src/payments/types.ts';
import {PaymentError} from '../src/payments/types.ts';

const T=1_800_000_000_000;
const address=(n:number)=>'0x'+n.toString(16).padStart(40,'0');
const hash=(chain:Chain,n:number)=>(chain==='bsc'?'0x':'')+n.toString(16).padStart(64,'0');
function cleanup(path:string){
  const parent=resolve(tmpdir())+sep,target=resolve(path);
  assert(target.startsWith(parent)&&target.includes('payments-integration-'));
  rmSync(target,{recursive:true,force:true});
}
test('project HTTP -> confirmed transfers on both chains -> persisted outbox -> retry -> one project fulfillment',async()=>{
  const folder=mkdtempSync(join(tmpdir(),'payments-integration-')),file=join(folder,'ledger.db'),master=Buffer.alloc(32,42);
  let store=new PaymentStore(file,master),now=T;
  const apiKey='synthetic-api-key-integration-long',secret='synthetic-webhook-secret-integration';
  store.createProject({id:'alpha',apiKey,webhookSecret:secret,webhookUrl:'https://example.com/hook'});
  store.addAddresses('alpha','bsc',[1,2,3,4,5].map(address),now);
  store.addAddresses('alpha','tron',[normalizeAddress('tron','41'+'1'.padStart(40,'0'))],now);
  const blocks=new Map<Chain,ConfirmedBlock>(),heights:Record<Chain,number>={bsc:100,tron:100};
  const readers:ChainReader[]=(['bsc','tron'] as const).map(chain=>({chain,head:async()=>({height:heights[chain],hash:hash(chain,heights[chain])}),block:async(height)=>{const block=blocks.get(chain);assert.equal(block?.height,height);return block!;}}));
  const scanner=new PaymentScanner(store,readers,{now:()=>now});await scanner.tick();
  const server=createPaymentsApp(store,{now:()=>now,readiness:()=>true}).listen(0,IPV4_LOOPBACK);await once(server,'listening');
  const base=`http://${IPV4_LOOPBACK}:${(server.address() as {port:number}).port}`;
  const post=(n:number,chain:Chain='bsc',userId='alice')=>fetch(base+'/v1/invoices',{method:'POST',headers:{authorization:'Bearer '+apiKey,'content-type':'application/json','idempotency-key':'request-'+chain+n},body:JSON.stringify({userId,orderId:'order-'+chain+n,chain,amount:'10'})});
  let serverClosed=false;
  try{
    const attempts=await Promise.all([1,2,3,4].map(n=>post(n)));
    assert.equal(attempts.filter(r=>r.status===201).length,3);assert.equal(attempts.filter(r=>r.status===429).length,1);
    const bscInvoice=(await attempts.find(r=>r.status===201)!.json()).invoice as Invoice;
    const tronResponse=await post(1,'tron','bob');assert.equal(tronResponse.status,201);
    const tronInvoice=(await tronResponse.json()).invoice as Invoice;
    now+=1000;
    for(const invoice of [bscInvoice,tronInvoice]){
      const chain=invoice.chain;heights[chain]=101;
      blocks.set(chain,{chain,height:101,hash:hash(chain,101),parentHash:hash(chain,100),timestamp:now,transfers:[{txHash:hash(chain,999),logIndex:0,tokenContract:ASSETS[chain].contract,from:chain==='bsc'?address(999):normalizeAddress('tron','41'+'999'.padStart(40,'0')),to:invoice.address,amountAtomic:invoice.amountAtomic,blockNumber:101,blockHash:hash(chain,101),timestamp:now}]});
    }
    await scanner.tick();
    assert.equal(store.getInvoice('alpha','alice',bscInvoice.id,now)?.status,'paid');
    assert.equal(store.getInvoice('alpha','bob',tronInvoice.id,now)?.status,'paid');
    const fulfilled=new Set<string>();let deliveries=0;
    const dispatcher=new PaymentDispatcher(store,async(_url,body,webhookSecret,eventId,at)=>{
      const timestamp=String(Math.floor(at!/1000));assert(verifyWebhookSignature(secret,timestamp,body,webhookSignature(webhookSecret,timestamp,body),at));
      const event=JSON.parse(body);assert.equal(event.eventId,eventId);assert.equal(event.type,'payment.paid');
      fulfilled.add(event.invoice.id);deliveries++;
      // Recipient committed the purchase, but sender did not get its acknowledgement.
      if(deliveries===1)throw new Error('ambiguous transport failure');
      return {ok:true};
    },()=>now);
    await dispatcher.tick();assert.equal(fulfilled.size,2);
    assert.equal(Number(store.db.prepare("SELECT COUNT(*) AS n FROM outbox WHERE status='pending'").get()!.n),1);
    server.closeAllConnections();await new Promise<void>(done=>server.close(()=>done()));serverClosed=true;
    store.close();store=new PaymentStore(file,master);now+=2000;
    const resumed=new PaymentScanner(store,readers,{now:()=>now});await resumed.tick();
    assert.equal(Number(store.db.prepare('SELECT COUNT(*) AS n FROM chain_events').get()!.n),2);
    const retry=new PaymentDispatcher(store,async(_url,body)=>{const event=JSON.parse(body);fulfilled.add(event.invoice.id);deliveries++;return {ok:true};},()=>now);
    await retry.tick();assert.equal(fulfilled.size,2);assert.equal(deliveries,3);
    assert.equal(Number(store.db.prepare("SELECT COUNT(*) AS n FROM outbox WHERE status='sent'").get()!.n),2);
  }finally{
    if(!serverClosed){server.closeAllConnections();await new Promise<void>(done=>server.close(()=>done()));}
    store.close();cleanup(folder);
  }
});

test('a held project webhook does not block another project or overlap sends to its own project', async () => {
  const store = new PaymentStore(':memory:', Buffer.alloc(32, 17));
  const webhook = (project: string) => `https://example.com/${project}`;
  let releaseAlpha!: () => void;
  const heldAlpha = new Promise<void>(resolve => {releaseAlpha = resolve;});
  let tick: Promise<void> | undefined;

  try {
    for (const project of ['alpha', 'beta']) {
      store.createProject({id: project, apiKey: `synthetic-api-key-${project}-isolation`,
        webhookUrl: webhook(project), webhookSecret: `synthetic-webhook-${project}-isolation`});
    }
    store.initializeCursor('bsc', 100, hash('bsc', 100), T);
    store.addAddresses('alpha', 'bsc', [address(1), address(2)], T);
    store.addAddresses('beta', 'bsc', [address(3)], T);
    const create = (project: string, orderId: string) => store.createInvoice(project, {
      userId: 'alice', orderId, chain: 'bsc', amount: '10', idempotencyKey: orderId
    }, T).invoice;
    const alpha = [create('alpha', 'order-1'), create('alpha', 'order-2')];
    const beta = create('beta', 'order-1');
    const confirm = (height: number, timestamp: number, invoices: Invoice[]) => {
      const blockHash = hash('bsc', height);
      store.ingestBlock({chain: 'bsc', height, hash: blockHash, parentHash: hash('bsc', height - 1), timestamp,
        transfers: invoices.map((invoice, logIndex) => ({txHash: hash('bsc', height + 500), logIndex,
          tokenContract: ASSETS.bsc.contract, from: address(999), to: invoice.address, amountAtomic: invoice.amountAtomic,
          blockNumber: height, blockHash, timestamp}))}, timestamp);
    };
    confirm(101, T + 1000, alpha);
    confirm(102, T + 2000, [beta]);

    const sends: {projectId: string; url: string}[] = [];
    let firstAlpha = true;
    const dispatcher = new PaymentDispatcher(store, async (url, body) => {
      const {invoice} = JSON.parse(body) as {invoice: Invoice};
      sends.push({projectId: invoice.projectId, url});
      if (invoice.projectId === 'alpha' && firstAlpha) {
        firstAlpha = false;
        await heldAlpha;
      }
      return {ok: true};
    }, () => T + 3000);

    tick = dispatcher.tick();
    void tick.catch(() => {});
    await new Promise<void>(resolve => setImmediate(resolve));

    assert.deepEqual([...sends], [{projectId: 'alpha', url: webhook('alpha')}, {projectId: 'beta', url: webhook('beta')}]);
    const betaDelivery = store.db.prepare('SELECT status FROM outbox WHERE invoice_id=?').get(beta.id);
    assert.equal(betaDelivery?.status, 'sent');

    releaseAlpha();
    await tick;
    await dispatcher.tick();
    assert.deepEqual(sends.map(send => send.projectId), ['alpha', 'beta', 'alpha']);
    assert.equal(store.db.prepare("SELECT COUNT(*) AS n FROM outbox WHERE status='sent'").get()?.n, 3);
  } finally {
    releaseAlpha();
    try {await tick;} finally {store.close();}
  }
});

test('admin creates private configuration and project files without printing credentials or overwriting files',()=>{
  const folder=mkdtempSync(join(tmpdir(),'payments-integration-')),config=join(folder,'service.json'),credentials=join(folder,'alpha.json');
  const cli=(...args:string[])=>spawnSync(process.execPath,['--import','tsx','scripts/payments-admin.ts',...args],{cwd:resolve('.'),encoding:'utf8'});
  const digest=(path:string)=>createHash('sha256').update(readFileSync(path)).digest('hex');
  try{
    assert.equal(cli('init','--config',config).status,0);const before=digest(config);
    assert.notEqual(cli('init','--config',config).status,0);assert.equal(digest(config),before);
    const project=cli('project','--config',config,'--id','alpha','--webhook','https://example.com/hook','--credentials',credentials);
    assert.equal(project.status,0);
    const secrets=JSON.parse(readFileSync(credentials,'utf8'));
    assert(!project.stdout.includes(secrets.apiKey));assert(!project.stderr.includes(secrets.webhookSecret));
    const rejected=join(folder,'rejected.json');
    assert.notEqual(cli('project','--config',config,'--id','alpha','--webhook','https://example.com/hook','--credentials',rejected).status,0);
    assert(!existsSync(rejected));
    const addresses=join(folder,'addresses.txt');writeFileSync(addresses,address(1)+'\n'+address(2)+'\n');
    assert.equal(cli('addresses','--config',config,'--project','alpha','--chain','bsc','--file',addresses).status,0);
    const publicBranch=HDKey.fromMasterSeed(Buffer.alloc(32,13)).derive("m/44'/195'/0'/0");
    const branchFile=join(folder,'public-branch.json'),manifest=join(folder,'manifest.json');
    const publicInput={xpub:publicBranch.publicExtendedKey,firstAddress:derivePaymentAddress('tron',publicBranch.publicExtendedKey,0),derivationPath:"m/44'/195'/0'/0"};
    writeFileSync(branchFile,JSON.stringify(publicInput));
    const registered=cli('hd-branch','--config',config,'--project','alpha','--chain','tron','--file',branchFile);
    assert.equal(registered.status,0);assert(!registered.stdout.includes(publicBranch.publicExtendedKey));
    assert.equal(cli('address-manifest','--config',config,'--project','alpha','--chain','tron','--out',manifest).status,0);
    const exported=JSON.parse(readFileSync(manifest,'utf8'));assert.equal(exported.addresses.length,20);
    assert.equal(exported.addresses[0].address,publicInput.firstAddress);assert.equal(exported.addresses[0].childIndex,0);
    writeFileSync(branchFile,JSON.stringify({...publicInput,xpub:publicBranch.privateExtendedKey}));
    const rejectedPrivate=cli('hd-branch','--config',config,'--project','alpha','--chain','tron','--file',branchFile);
    assert.notEqual(rejectedPrivate.status,0);assert(!rejectedPrivate.stdout.includes(publicBranch.privateExtendedKey));assert(!rejectedPrivate.stderr.includes(publicBranch.privateExtendedKey));
    writeFileSync(branchFile,JSON.stringify({...publicInput,seed:'synthetic-private-field'}));
    assert.notEqual(cli('hd-branch','--config',config,'--project','alpha','--chain','tron','--file',branchFile).status,0);
    const parsed=JSON.parse(readFileSync(config,'utf8')),store=new PaymentStore(join(folder,'ledger.db'),Buffer.from(parsed.masterKey,'base64'));
    try{assert.equal(store.authenticate(secrets.apiKey)?.id,'alpha');assert.equal(store.getAddresses('bsc').length,2);}finally{store.close();}
  }finally{cleanup(folder);}
});

test('readiness refusal prevents new allocation but a persisted identical retry survives an RPC outage',()=>{
  const store=new PaymentStore(':memory:',Buffer.alloc(32,9));
  try{
    store.createProject({id:'alpha',apiKey:'synthetic-api-key-readiness',webhookSecret:'synthetic-webhook-readiness',webhookUrl:'https://example.com/hook'});
    store.addAddresses('alpha','bsc',[address(1),address(2)],T);store.initializeCursor('bsc',100,hash('bsc',100),T);
    const input={userId:'alice',orderId:'one',chain:'bsc' as const,amount:'10',idempotencyKey:'one'};
    const invoice=store.createInvoice('alpha',input,T).invoice;
    const unavailable=()=>{throw new PaymentError('chain_not_ready',503);};
    assert.equal(store.createInvoice('alpha',input,T,unavailable).invoice.id,invoice.id);
    assert.throws(()=>store.createInvoice('alpha',{...input,orderId:'two',idempotencyKey:'two'},T,unavailable),/chain_not_ready/);
    assert.equal(Number(store.db.prepare('SELECT COUNT(*) AS n FROM invoices').get()!.n),1);
    assert.equal(Number(store.db.prepare('SELECT COUNT(*) AS n FROM addresses WHERE assigned_invoice_id IS NULL').get()!.n),1);
  }finally{store.close();}
});
