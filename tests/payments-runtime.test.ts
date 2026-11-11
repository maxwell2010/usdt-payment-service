import {IPV4_LOOPBACK} from '../src/payments/config.ts';
import test from 'node:test';
import assert from 'node:assert/strict';
import {existsSync,mkdtempSync,writeFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve,sep} from 'node:path';
import {pathToFileURL} from 'node:url';
import {createServer} from 'node:net';
import {spawn,type ChildProcess} from 'node:child_process';
import {once} from 'node:events';

test('standalone runtime requires an Alchemy key, initializes both chains and gracefully releases its lease', {timeout:20_000},async()=>{
  const directory=mkdtempSync(join(tmpdir(),'payments-runtime-')),config=join(directory,'service.json');
  const testApiKey='test_key-runtime';
  const portServer=createServer().listen(0,IPV4_LOOPBACK);await once(portServer,'listening');
  const port=(portServer.address() as {port:number}).port;await new Promise<void>(done=>portServer.close(()=>done()));
  writeFileSync(config,JSON.stringify({databasePath:'ledger.db',masterKey:Buffer.alloc(32,77).toString('base64'),host:IPV4_LOOPBACK,port,pollIntervalMs:1000}),{mode:0o600});
  const bootstrap=join(directory,'bootstrap.mjs');
  // The fake transport exists only in this isolated test subprocess, never in production.
  writeFileSync(bootstrap,`
    const bscRpc=${JSON.stringify(`https://bnb-mainnet.g.alchemy.com/v2/${testApiKey}`)};
    const tronRpc=${JSON.stringify(`https://tron-mainnet.g.alchemy.com/v2/${testApiKey}/walletsolidity`)};
    const hash='0x'+(50).toString(16).padStart(64,'0');
    const tronHash=(50).toString(16).padStart(16,'0')+'1'.repeat(48);
    globalThis.fetch=async(input,init)=>{
      const body=JSON.parse(init.body),url=String(input);
      if(init.method!=='POST'||init.redirect!=='error')throw new Error('Unexpected Alchemy test RPC options');
      const seconds=Math.floor(Date.now()/1000);
      let value;
      if(url===bscRpc){
        let result;
        if(body.method==='eth_chainId')result='0x38';
        else if(body.method==='eth_getBlockByNumber'&&body.params[0]==='finalized')result={number:'0x32',hash,parentHash:'0x'+'0'.repeat(64),timestamp:'0x'+seconds.toString(16),transactions:[]};
        else throw new Error('Unexpected Alchemy BSC test method');
        value={jsonrpc:'2.0',id:body.id,result};
      }else if(url===tronRpc+'/getblockbynum'&&body.num===0)value={blockID:'00000000000000001ebf88508a03865c71d452e25f4d51194196a1d22b6653dc'};
      else if(url===tronRpc+'/getnowblock')value={blockID:tronHash,block_header:{raw_data:{number:50,parentHash:'0'.repeat(64),timestamp:seconds*1000}},transactions:[]};
      else throw new Error('Unexpected Alchemy test RPC route');
      return new Response(JSON.stringify(value),{headers:{'content-type':'application/json'}});
    };
    process.on('message',message=>{if(message==='stop')process.emit('SIGTERM');});
    process.channel?.unref();
    await import(${JSON.stringify(pathToFileURL(resolve('src/payments/main.ts')).href)});
  `);
  const children:ChildProcess[]=[];
  const start=(key:string|null=testApiKey)=>{
    const env:NodeJS.ProcessEnv={...process.env,PAYMENTS_CONFIG:config};
    for(const name of Object.keys(env))if(name.toUpperCase()==='ALCHEMY_API_KEY')delete env[name];
    if(key!==null)env.ALCHEMY_API_KEY=key;
    const child=spawn(process.execPath,['--import','tsx',bootstrap],{cwd:resolve('.'),env,stdio:['ignore','pipe','pipe','ipc']});
    children.push(child);return child;
  };
  const waitExit=async(child:ChildProcess)=>child.exitCode!==null||child.signalCode!==null?[child.exitCode]:await once(child,'exit');
  const ready=async()=>{
    for(let i=0;i<60;i++){
      try{const response=await fetch(`http://${IPV4_LOOPBACK}:${port}/ready`,{signal:AbortSignal.timeout(500)});if(response.status===200)return;}catch{}
      await new Promise(done=>setTimeout(done,50));
    }
    throw new Error('Isolated payment runtime never became ready');
  };
  try{
    assert.equal((await waitExit(start(null)))[0],1);
    assert.equal(existsSync(join(directory,'ledger.db')),false);
    const first=start();await ready();
    const duplicate=start();assert.equal((await waitExit(duplicate))[0],1);
    first.send('stop');assert.equal((await waitExit(first))[0],0);
    const restarted=start();await ready();restarted.send('stop');assert.equal((await waitExit(restarted))[0],0);
  }finally{
    for(const child of children)if(child.exitCode===null&&child.signalCode===null){child.kill();await waitExit(child);}
    const target=resolve(directory);assert(target.startsWith(resolve(tmpdir())+sep)&&target.includes('payments-runtime-'));
    rmSync(target,{recursive:true,force:true});
  }
});
