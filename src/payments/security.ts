import {createHash,createHmac,randomBytes,createCipheriv,createDecipheriv,timingSafeEqual} from 'node:crypto';
import {lookup} from 'node:dns/promises';
import type {LookupAddress} from 'node:dns';
import {isIP,type LookupFunction} from 'node:net';
import {request} from 'node:https';
import {PaymentError} from './types.ts';

export const hashSecret=(secret:string)=>createHash('sha256').update(secret).digest('hex');
export function sealSecret(secret:string,key:Buffer):string{
  if(key.length!==32)throw new Error('Payment master key must contain 32 bytes');
  const nonce=randomBytes(12),cipher=createCipheriv('aes-256-gcm',key,nonce);
  const data=Buffer.concat([cipher.update(secret,'utf8'),cipher.final()]);
  return ['v1',nonce.toString('hex'),cipher.getAuthTag().toString('hex'),data.toString('hex')].join(':');
}
export function openSecret(sealed:string,key:Buffer):string{
  const [version,nonce,tag,data,...extra]=sealed.split(':');
  if(version!=='v1'||extra.length||!/^[0-9a-f]{24}$/.test(nonce)||!/^[0-9a-f]{32}$/.test(tag)||!/^(?:[0-9a-f]{2})+$/.test(data))throw new Error('Invalid encrypted payment secret');
  const decipher=createDecipheriv('aes-256-gcm',key,Buffer.from(nonce,'hex'),{authTagLength:16});
  decipher.setAuthTag(Buffer.from(tag,'hex'));
  return Buffer.concat([decipher.update(Buffer.from(data,'hex')),decipher.final()]).toString('utf8');
}
export function validateWebhookUrl(input:string):string{
  let url:URL;try{url=new URL(input);}catch{throw new PaymentError('invalid_webhook_url',400);}
  const host=url.hostname.toLowerCase();
  if(input.length>2048||url.protocol!=='https:'||url.username||url.password||url.hash||(url.port&&url.port!=='443')||isIP(host.replace(/^\[|\]$/g,''))||!host.includes('.')||/(?:^|\.)(localhost|local|internal|invalid|test|onion)$/.test(host))throw new PaymentError('invalid_webhook_url',400);
  return url.toString();
}
export function isPublicAddress(address:string):boolean{
  const family=isIP(address);
  if(family===4){
    const [a,b,c]=address.split('.').map(Number);
    return !(a===0||a===10||a===127||a>=224||a===169&&b===254||a===172&&b>=16&&b<=31||a===192&&b===168||a===100&&b>=64&&b<=127||a===198&&(b===18||b===19)||a===192&&b===0||a===198&&b===51&&c===100||a===203&&b===0&&c===113);
  }
  // Only globally routable unicast, excluding documentation and transition ranges.
  const normalized=address.toLowerCase();
  return family===6&&/^[23][0-9a-f]{3}:/.test(normalized)&&!normalized.startsWith('2001:db8:')&&!normalized.startsWith('2001:0:')&&!normalized.startsWith('2002:');
}
export function webhookSignature(secret:string,timestamp:string,body:string):string{
  return 'v1='+createHmac('sha256',secret).update(timestamp+'.'+body).digest('hex');
}
export function verifyWebhookSignature(secret:string,timestamp:string,body:string,signature:string,now=Date.now()):boolean{
  if(!/^\d{10}$/.test(timestamp)||Math.abs(now-Number(timestamp)*1000)>300_000||!/^v1=[0-9a-f]{64}$/.test(signature))return false;
  const expected=webhookSignature(secret,timestamp,body);
  return timingSafeEqual(Buffer.from(expected),Buffer.from(signature));
}
export type WebhookResult={ok:boolean;retryAfterMs?:number};
type WebhookResolver=(host:string,options:{all:true;verbatim:true})=>Promise<LookupAddress[]>;
export async function resolveWebhookAddresses(host:string,resolver:WebhookResolver=lookup){
  let timer:ReturnType<typeof setTimeout>|undefined;
  try{
    const addresses=await Promise.race([
      resolver(host,{all:true,verbatim:true}),
      new Promise<never>((_resolve,reject)=>{timer=setTimeout(()=>reject(new Error('Webhook DNS timeout')),5000);})
    ]);
    if(!addresses.length||addresses.some(a=>!isPublicAddress(a.address)))throw new Error('Webhook destination is not public');
    return addresses;
  }finally{if(timer)clearTimeout(timer);}
}
/** Resolve every attempt and pin the connection to the validated IP. Never follow redirects. */
export async function postWebhook(urlString:string,body:string,secret:string,eventId:string,now=Date.now(),signal?:AbortSignal):Promise<WebhookResult>{
  signal?.throwIfAborted();
  const url=new URL(validateWebhookUrl(urlString));
  const addresses=await resolveWebhookAddresses(url.hostname);
  const selected=addresses.find(a=>a.family===4)??addresses[0];
  const pinnedLookup:LookupFunction=(_host,options,callback)=>{
    if(typeof options==='object'&&options.all)callback(null,[selected]);
    else callback(null,selected.address,selected.family);
  };
  const timestamp=Math.floor(now/1000).toString();
  return new Promise((resolve,reject)=>{
    const timeout=AbortSignal.timeout(10_000);
    const req=request(url,{method:'POST',lookup:pinnedLookup,family:selected.family,signal:signal?AbortSignal.any([signal,timeout]):timeout,timeout:10_000,headers:{'content-type':'application/json','content-length':Buffer.byteLength(body),'user-agent':'Standalone-USDT-Payments/1','x-payment-event-id':eventId,'x-payment-timestamp':timestamp,'x-payment-signature':webhookSignature(secret,timestamp,body)}},res=>{
      const raw=res.headers['retry-after'];let retryAfterMs:number|undefined;
      if(typeof raw==='string'){
        const value=/^\d+$/.test(raw)?Number(raw)*1000:Date.parse(raw)-now;
        if(Number.isFinite(value)&&value>0)retryAfterMs=Math.min(value,3_600_000);
      }
      res.destroy();
      resolve({ok:res.statusCode!==undefined&&res.statusCode>=200&&res.statusCode<300,retryAfterMs});
    });
    req.on('timeout',()=>req.destroy(new Error('Webhook timeout')));
    req.on('error',reject);req.end(body);
  });
}
