import test from 'node:test';
import assert from 'node:assert/strict';
import {createECDH, createHash, pbkdf2Sync} from 'node:crypto';
import {HDKey, HARDENED_OFFSET, type Versions} from '@scure/bip32';
import {keccak_256} from '@noble/hashes/sha3.js';
import {derivePaymentAddress, validatePublicBranch} from '../src/payments/hd.ts';
import {normalizeAddress, tronAddressHex} from '../src/payments/assets.ts';
import {PaymentError, type Chain} from '../src/payments/types.ts';

// Public, deliberately unsafe test fixtures. Never fund or use their keys.
// BIP32 vector 1: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vector-1
const TEST_SEED = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');
const root = () => HDKey.fromMasterSeed(TEST_SEED);
const branch = (chain: Chain, account = 0) => root().derive(`m/44'/${chain === 'bsc' ? 60 : 195}'/${account}'/0`);
const errorCode = (code: string) => (error: unknown) => error instanceof PaymentError && error.code === code;

function addressFromTestPrivate(chain: Chain, child: HDKey): string {
  // Independent native secp256k1 public-key computation, restricted to tests.
  const ecdh = createECDH('secp256k1');
  ecdh.setPrivateKey(Buffer.from(child.privateKey!));
  const digest = Buffer.from(keccak_256(ecdh.getPublicKey(undefined, 'uncompressed').subarray(1))).subarray(-20).toString('hex');
  return normalizeAddress(chain, chain === 'bsc' ? '0x' + digest : '41' + digest);
}

test('HD dependency matches official BIP32 vector 1 public parent/child derivation', () => {
  const digest = (key: string) => createHash('sha256').update(key).digest('hex');
  const parent = root().derive("m/0'/1/2'/2");
  assert.equal(digest(parent.publicExtendedKey), 'e3d665e5fb6cf2f00006cb06ff42df49c90687353cc56893ddc781a7036f4b89');
  assert.equal(digest(HDKey.fromExtendedKey(parent.publicExtendedKey).deriveChild(1_000_000_000).publicExtendedKey),
    'c55ab7cda629c99dcee54bf1e783b8442580a85107e522cc17cfad0f77ded0a6');
});

test('server receives only an external xpub and derives exactly the offline owner addresses', () => {
  for (const chain of ['bsc', 'tron'] as const) {
    const offline = branch(chain), xpub = offline.publicExtendedKey;
    const validated = validatePublicBranch(chain, xpub);
    assert.equal(validated.xpub, xpub); assert.match(validated.fingerprint, /^[a-f0-9]{64}$/);
    assert.equal(HDKey.fromExtendedKey(xpub).privateKey, null);
    for (const index of [0, 1, 2, 1000, HARDENED_OFFSET - 1]) {
      const expected = addressFromTestPrivate(chain, offline.deriveChild(index));
      assert.equal(derivePaymentAddress(chain, xpub, index), expected);
      assert.equal(derivePaymentAddress(chain, xpub, index), expected);
    }
  }
});

test('known Ethereum and Ledger TRON test-phrase receiving addresses match wallet fixtures', () => {
  // Ledger fixture: https://github.com/LedgerHQ/app-tron#test-seed
  // This public BIP39 phrase has no passphrase and must never hold money.
  const mnemonic = Array(11).fill('abandon').concat('about').join(' ');
  const seed = pbkdf2Sync(mnemonic, 'mnemonic', 2048, 64, 'sha512');
  const wallet = HDKey.fromMasterSeed(seed);
  assert.equal(derivePaymentAddress('bsc', wallet.derive("m/44'/60'/0'/0").publicExtendedKey, 0), '0x9858effd232b4033e47d90003d41ec34ecaeda94');
  assert.equal(derivePaymentAddress('tron', wallet.derive("m/44'/195'/0'/0").publicExtendedKey, 0), 'TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH');
});

test('the same public key uses chain-specific address encoding; dedicated paths keep streams separate', () => {
  const xpub = branch('bsc').publicExtendedKey;
  const bscAddress = derivePaymentAddress('bsc', xpub, 10), tronAddress = derivePaymentAddress('tron', xpub, 10);
  assert.equal(tronAddressHex(tronAddress), '41' + bscAddress.slice(2));
  assert.notEqual(derivePaymentAddress('tron', branch('tron').publicExtendedKey, 10), tronAddress);
  assert.notEqual(derivePaymentAddress('bsc', branch('bsc', 1).publicExtendedKey, 10), bscAddress);
});

test('branch fingerprint identifies actual derivation material despite serialized metadata repackaging', () => {
  const external = branch('bsc'), xpub = external.publicExtendedKey;
  const repackaged = new HDKey({depth: 4, index: 0, parentFingerprint: external.parentFingerprint ^ 1,
    chainCode: external.chainCode!, publicKey: external.publicKey!}).publicExtendedKey;
  assert.notEqual(repackaged, xpub);
  const original = validatePublicBranch('bsc', xpub), altered = validatePublicBranch('bsc', repackaged);
  assert.equal(original.fingerprint, altered.fingerprint);
  assert.equal(original.fingerprint, createHash('sha256').update(external.publicKey!).update(external.chainCode!).digest('hex'));
  assert.equal(derivePaymentAddress('bsc', repackaged, 3), derivePaymentAddress('bsc', xpub, 3));
  assert.notEqual(original.fingerprint, validatePublicBranch('bsc', branch('bsc', 1).publicExtendedKey).fingerprint);
});

test('private keys, unsupported branch shapes, checksum mutations and foreign versions are refused without echoing input', () => {
  const xpub = branch('bsc').publicExtendedKey;
  const tpub = new HDKey({versions: {private: 0x04358394, public: 0x043587cf}, depth: 4, index: 0,
    parentFingerprint: 1, chainCode: branch('bsc').chainCode!, publicKey: branch('bsc').publicKey!}).publicExtendedKey;
  const variants: unknown[] = [branch('bsc').privateExtendedKey, root().publicExtendedKey, root().derive("m/44'/60'/0'").publicExtendedKey,
    root().derive("m/44'/60'/0'/1").publicExtendedKey, root().derive("m/44'/60'/0'/0'").publicExtendedKey,
    branch('bsc').deriveChild(0).publicExtendedKey, tpub, '', xpub + ' ', ' ' + xpub, xpub.slice(0, -1) + (xpub.endsWith('1') ? '2' : '1'),
    'xpub' + '0'.repeat(107), 'xpub' + 'a'.repeat(10_000), null, 123];
  for (const input of variants) {
    assert.throws(() => validatePublicBranch('bsc', input as string), error => {
      assert(errorCode('invalid_public_branch')(error));
      assert.equal((error as Error).message, 'invalid_public_branch'); return true;
    });
  }
  assert.throws(() => validatePublicBranch('other' as Chain, xpub), errorCode('invalid_public_branch'));
});

test('hardened, fractional, negative, infinite and unsafe child indexes are refused', () => {
  const xpub = branch('bsc').publicExtendedKey;
  for (const index of [-1, 0.5, NaN, Infinity, HARDENED_OFFSET, Number.MAX_SAFE_INTEGER, '1', null]) {
    assert.throws(() => derivePaymentAddress('bsc', xpub, index as number), errorCode('invalid_derivation_index'));
  }
});

test('a library-skipped invalid child never silently consumes the wrong index', t => {
  const offline = branch('bsc'), xpub = offline.publicExtendedKey, skipped = HDKey.fromExtendedKey(xpub).deriveChild(2);
  t.mock.method(HDKey.prototype, 'deriveChild', () => skipped);
  assert.throws(() => derivePaymentAddress('bsc', xpub, 1), errorCode('invalid_derived_child'));
});

test('runtime derivation does not call seed creation, import private keys or produce a signing key', t => {
  const xpub = branch('tron').publicExtendedKey;
  t.mock.method(HDKey, 'fromMasterSeed', () => {throw new Error('Server must never derive a seed');});
  const original = HDKey.fromExtendedKey;
  t.mock.method(HDKey, 'fromExtendedKey', (key: string, versions?: Versions) => {
    assert(key.startsWith('xpub')); const parsed = original.call(HDKey, key, versions);assert.equal(parsed.privateKey, null);return parsed;
  });
  assert.equal(derivePaymentAddress('tron', xpub, 0), normalizeAddress('tron', derivePaymentAddress('tron', xpub, 0)));
});
