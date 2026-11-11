import type {Delivery} from './types.ts';
import {postWebhook,type WebhookResult} from './security.ts';

export interface DeliveryStore {
  claimDelivery(now?:number,leaseMs?:number,excludedProjects?:readonly string[]):Delivery|null;
  completeDelivery(id:string,success:boolean,now?:number,retryAfterMs?:number):void;
}
const MAX_PARALLEL_PROJECTS = 4;

/** At-least-once delivery. A timed-out request can already have reached the recipient. */
export class PaymentDispatcher {
  private running=false;
  constructor(private store:DeliveryStore,private send=postWebhook,private now=Date.now,private isStopping=()=>false){}
  async tick(limit=10){
    if(this.running)return;this.running=true;
    try{
      let remaining = limit;
      while (remaining > 0 && !this.isStopping()) {
        const batch: Delivery[] = [];
        const projects: string[] = [];
        while (batch.length < Math.min(remaining, MAX_PARALLEL_PROJECTS)) {
          const delivery = this.store.claimDelivery(this.now(), 60_000, projects);
          if (!delivery) break;
          batch.push(delivery);
          projects.push(delivery.projectId);
        }
        if (!batch.length) break;
        const results = await Promise.allSettled(batch.map(delivery => this.deliver(delivery)));
        const failed = results.find(result => result.status === 'rejected');
        if (failed) throw failed.reason;
        remaining -= batch.length;
      }
    }finally{this.running=false;}
  }

  private async deliver(delivery: Delivery): Promise<void> {
    let result: WebhookResult = {ok: false};
    try {
      result = await this.send(delivery.url, delivery.body, delivery.secret, delivery.id, this.now());
    } catch { /* No secret, URL, response or request body is logged. */ }
    this.store.completeDelivery(delivery.id, result.ok, this.now(), result.retryAfterMs);
  }
}
