import {randomBytes} from 'node:crypto';
import {mkdirSync,writeFileSync,readFileSync,unlinkSync,statSync} from 'node:fs';
import {resolve,dirname} from 'node:path';
import {IPV4_LOOPBACK,loadPaymentConfig} from '../src/payments/config.ts';
import {PaymentStore} from '../src/payments/store.ts';
import {validateWebhookUrl} from '../src/payments/security.ts';
import {PaymentError,type Chain} from '../src/payments/types.ts';

function args(){
  const [command,...rest]=process.argv.slice(2),options=new Map<string,string>();
  for(let i=0;i<rest.length;i+=2){if(!rest[i]?.startsWith('--')||!rest[i+1]||rest[i+1].startsWith('--')||options.has(rest[i]))throw new Error('Invalid arguments');options.set(rest[i],rest[i+1]);}
  return {command,options};
}
function privateFile(path:string,value:unknown){mkdirSync(dirname(path),{recursive:true,mode:0o700});writeFileSync(path,JSON.stringify(value,null,2)+'\n',{flag:'wx',mode:0o600});}
function run(){
  const {command,options}=args(),configPath=resolve(options.get('--config')??process.env.PAYMENTS_CONFIG??'runtime/payments/service.json');
  const allowed=command==='init'?['--config']:command==='project'?['--config','--id','--webhook','--credentials']:command==='addresses'||command==='hd-branch'?['--config','--project','--chain','--file']:command==='address-manifest'?['--config','--project','--chain','--out']:[];
  if(!allowed.length||[...options.keys()].some(key=>!allowed.includes(key)))throw new Error('Invalid arguments');
  if(command==='init'){
    privateFile(configPath,{databasePath:'ledger.db',masterKey:randomBytes(32).toString('base64'),host:IPV4_LOOPBACK,port:3501,pollIntervalMs:3000});
    console.log('Created private payment configuration. No credentials were printed.');return;
  }
  const config=loadPaymentConfig(configPath),store=new PaymentStore(config.databasePath,config.masterKey);config.masterKey.fill(0);
  try{
    if(command==='project'){
      const id=options.get('--id')??'',webhook=validateWebhookUrl(options.get('--webhook')??''),destination=options.get('--credentials');
      if(!/^[A-Za-z0-9_.:-]{1,128}$/.test(id)||!destination)throw new Error('Invalid project arguments');
      const credentials={projectId:id,apiKey:randomBytes(32).toString('base64url'),webhookSecret:randomBytes(32).toString('base64url')};
      const path=resolve(destination);privateFile(path,credentials);
      try{store.createProject({id,apiKey:credentials.apiKey,webhookSecret:credentials.webhookSecret,webhookUrl:webhook});}catch(error){unlinkSync(path);throw error;}
      console.log('Created project and private credentials file. Keep it on the project backend; no credentials were printed.');
    }else if(command==='address-manifest'){
      const project=options.get('--project')??'',chain=options.get('--chain'),out=options.get('--out');
      if(!out||chain!=='bsc'&&chain!=='tron')throw new Error('Invalid address manifest arguments');
      privateFile(resolve(out),{projectId:project,chain,addresses:store.addressManifest(project,chain)});
      console.log('Created private address manifest. No address or public key values were printed.');
    }else{
      const project=options.get('--project')??'',chain=options.get('--chain'),file=options.get('--file');
      if(!file||chain!=='bsc'&&chain!=='tron'||statSync(resolve(file)).size>1_000_000)throw new Error('Invalid address import arguments');
      const raw=readFileSync(resolve(file),'utf8');
      if(command==='hd-branch'){
        if(Buffer.byteLength(raw)>16_384)throw new Error('Invalid public branch file');
        const branch:unknown=JSON.parse(raw);
        if(!branch||typeof branch!=='object'||Array.isArray(branch)||Object.keys(branch).length!==3||Object.keys(branch).some(k=>!['xpub','firstAddress','derivationPath'].includes(k)))throw new Error('Invalid public branch file');
        const input=branch as Record<string,unknown>;
        if(typeof input.xpub!=='string'||typeof input.firstAddress!=='string'||typeof input.derivationPath!=='string')throw new Error('Invalid public branch file');
        store.registerPublicBranch(project,chain as Chain,{xpub:input.xpub,firstAddress:input.firstAddress,derivationPath:input.derivationPath});
        console.log('Registered watch-only branch. New addresses will be prepared automatically; no key values were printed.');
      }else{
        const addresses=raw.split(/\r?\n/).map(s=>s.trim()).filter(Boolean);
        if(!addresses.length||addresses.length>10_000)throw new Error('Invalid address count');
        store.addAddresses(project,chain as Chain,addresses);
        console.log(`Imported ${addresses.length} payment addresses. Address values were not printed.`);
      }
    }
  }finally{store.close();}
}
try{run();}catch(error){console.error(error instanceof PaymentError?`Payment administration failed: ${error.code}`:'Payment administration failed. Check arguments, configuration and existing files; values were not printed.');process.exitCode=1;}
