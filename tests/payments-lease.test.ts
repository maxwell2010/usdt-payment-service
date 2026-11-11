import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {ServiceLease} from '../src/payments/lease.ts';
test('one payment process owns a ledger and a stale owner cannot renew or write after takeover',()=>{
  const db=new DatabaseSync(':memory:');let now=1000;
  try{
    const a=new ServiceLease(db,()=>now,30_000),b=new ServiceLease(db,()=>now,30_000);
    assert(a.acquire());assert(!b.acquire());a.assertHeld();assert.throws(()=>b.assertHeld());
    now+=30_001;assert.throws(()=>a.assertHeld());assert(!a.renew());assert(b.acquire());
    assert.throws(()=>a.assertHeld());assert(!a.renew());a.release();b.assertHeld();
    b.release();assert(a.acquire());
  }finally{db.close();}
});
