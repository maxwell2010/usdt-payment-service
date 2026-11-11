import {createHash} from 'node:crypto';
import {PaymentError,type Chain} from './types.ts';

// Fixed mainnet allowlist; never authorize a token by its name/symbol alone.
export const ASSETS = {
  bsc:{contract:'0x55d398326f99059ff775485246999027b3197955',decimals:18},
  tron:{contract:'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t',decimals:6}
} as const;
export const TRANSFER_TOPIC='ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
const alphabet='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const sha=(value:Buffer)=>createHash('sha256').update(value).digest();
function encode58(bytes:Buffer){
  let value=BigInt('0x'+bytes.toString('hex')),result='';
  while(value){result=alphabet[Number(value%58n)]+result;value/=58n;}
  for(const byte of bytes){if(byte!==0)break;result='1'+result;}
  return result;
}
function decode58(value:string){
  if(value.length>40)throw new PaymentError('invalid_address',400);
  let result=0n;
  for(const char of value){const digit=alphabet.indexOf(char);if(digit<0)throw new PaymentError('invalid_address',400);result=result*58n+BigInt(digit);}
  let hex=result.toString(16);if(hex.length%2)hex='0'+hex;
  let bytes=Buffer.from(hex,'hex');
  for(const char of value){if(char!=='1')break;bytes=Buffer.concat([Buffer.from([0]),bytes]);}
  return bytes;
}
export function normalizeAddress(chain:Chain,input:string,allowZero=false):string{
  if(typeof input!=='string')throw new PaymentError('invalid_address',400);
  if(chain==='bsc'){
    if(!/^0x[0-9a-fA-F]{40}$/.test(input)||!allowZero&&/^0x0{40}$/i.test(input))throw new PaymentError('invalid_address',400);
    return input.toLowerCase();
  }
  if(chain!=='tron')throw new PaymentError('invalid_chain',400);
  let payload:Buffer;
  if(/^(?:0x)?41[0-9a-fA-F]{40}$/.test(input))payload=Buffer.from(input.replace(/^0x/,'').toLowerCase(),'hex');
  else {
    const bytes=decode58(input);payload=bytes.subarray(0,21);
    if(bytes.length!==25||!sha(sha(payload)).subarray(0,4).equals(bytes.subarray(21)))throw new PaymentError('invalid_address',400);
  }
  if(payload.length!==21||payload[0]!==0x41||!allowZero&&payload.subarray(1).every(b=>b===0))throw new PaymentError('invalid_address',400);
  return encode58(Buffer.concat([payload,sha(sha(payload)).subarray(0,4)]));
}
export function tronAddressHex(input:string):string{
  return decode58(normalizeAddress('tron',input)).subarray(0,21).toString('hex');
}
export function parseAmount(chain:Chain,input:string):{amount:string;atomic:string}{
  if(!ASSETS[chain]||typeof input!=='string'||input.length>32||!/^(?:0|[1-9]\d{0,6})(?:\.\d{1,6})?$/.test(input))throw new PaymentError('invalid_amount',400);
  const [whole,fraction='']=input.split('.');
  const atomic=BigInt(whole)*10n**BigInt(ASSETS[chain].decimals)+BigInt(fraction.padEnd(ASSETS[chain].decimals,'0'));
  if(atomic<=0n||atomic>1_000_000n*10n**BigInt(ASSETS[chain].decimals))throw new PaymentError('invalid_amount',400);
  const trimmed=fraction.replace(/0+$/,'');
  return {amount:whole+(trimmed?'.'+trimmed:''),atomic:atomic.toString()};
}
