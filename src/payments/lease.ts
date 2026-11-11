import {randomUUID} from 'node:crypto';
import type {DatabaseSync} from 'node:sqlite';
import {PaymentError} from './types.ts';

/** SQLite is on local disk. A lost lease fences every subsequent scanner/dispatcher write. */
export class ServiceLease {
  private readonly owner=randomUUID();
  constructor(private db:DatabaseSync,private now=Date.now,private durationMs=30_000){
    db.exec('CREATE TABLE IF NOT EXISTS service_lock(id INTEGER PRIMARY KEY CHECK(id=1),owner TEXT NOT NULL,expires_at INTEGER NOT NULL)');
  }
  acquire():boolean{
    const now=this.now();
    return this.db.prepare('INSERT INTO service_lock(id,owner,expires_at) VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET owner=excluded.owner,expires_at=excluded.expires_at WHERE service_lock.expires_at<=?').run(this.owner,now+this.durationMs,now).changes>0;
  }
  renew():boolean{
    const now=this.now();
    return this.db.prepare('UPDATE service_lock SET expires_at=? WHERE id=1 AND owner=? AND expires_at>?').run(now+this.durationMs,this.owner,now).changes>0;
  }
  assertHeld():void{
    const row=this.db.prepare('SELECT owner,expires_at FROM service_lock WHERE id=1').get();
    if(!row||row.owner!==this.owner||Number(row.expires_at)<=this.now())throw new PaymentError('service_not_ready',503);
  }
  release():void{this.db.prepare('DELETE FROM service_lock WHERE id=1 AND owner=?').run(this.owner);}
}
