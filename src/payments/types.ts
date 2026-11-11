/** Standalone payment service contracts. Amounts are strings, timestamps Unix milliseconds. */
export type Chain = 'bsc' | 'tron';
export type InvoiceStatus = 'pending' | 'expired' | 'underpaid' | 'paid' | 'overpaid' | 'late_payment';
export type Project = {id:string; webhookUrl:string; enabled:boolean};
export type ProjectInput = {id:string; apiKey:string; webhookUrl:string; webhookSecret:string};
export type CreateInvoice = {userId:string; orderId:string; chain:Chain; amount:string; idempotencyKey:string};
export type Invoice = {id:string; projectId:string; userId:string; orderId:string; chain:Chain; asset:'USDT'; tokenContract:string; address:string; amount:string; amountAtomic:string; receivedAtomic:string; status:InvoiceStatus; createdAt:number; expiresAt:number};
export type Transfer = {txHash:string; logIndex:number; tokenContract:string; from:string; to:string; amountAtomic:string; blockNumber:number; blockHash:string; timestamp:number};
export type ConfirmedBlock = {chain:Chain; height:number; hash:string; parentHash:string; timestamp:number; transfers:Transfer[]};
export type Cursor = {height:number; hash:string; timestamp?:number};
export type Delivery = {id:string; projectId:string; url:string; secret:string; body:string; attempts:number};
export class PaymentError extends Error {
  constructor(readonly code:string, readonly status:number, readonly retryAfter?:number){super(code);}
}
export interface ChainReader {
  readonly chain:Chain;
  head():Promise<Cursor>;
  block(height:number, recipients:readonly string[]):Promise<ConfirmedBlock>;
}
