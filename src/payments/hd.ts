import {createHash, ECDH} from 'node:crypto';
import {HDKey, HARDENED_OFFSET} from '@scure/bip32';
import {keccak_256} from '@noble/hashes/sha3.js';
import {normalizeAddress} from './assets.ts';
import {PaymentError, type Chain} from './types.ts';

/** Public-only BIP32 receiving branches. Verified 2026-11-10 against:
 * https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
 * https://support.tronlink.org/hc/en-us/articles/18779153013913-Learn-about-HD-wallets
 *
 * Export the external branch m/44'/60'/account'/0 for BSC, or
 * m/44'/195'/account'/0 for TRON, on an independent offline signing device.
 * A serialized xpub reveals depth and its final child index, not the full
 * ancestral path. Operators must verify that path and recovery independently.
 */
const MAINNET_VERSIONS = {public: 0x0488b21e, private: 0x0488ade4};
const XPUB = /^xpub[1-9A-HJ-NP-Za-km-z]{107}$/;

function publicBranch(chain: Chain, xpub: string): HDKey {
  // Reject xprv/seed/raw-key input before a parser can import private material.
  if ((chain !== 'bsc' && chain !== 'tron') || typeof xpub !== 'string' || !XPUB.test(xpub)) {
    throw new PaymentError('invalid_public_branch', 400);
  }
  try {
    const branch = HDKey.fromExtendedKey(xpub, MAINNET_VERSIONS);
    if (branch.privateKey !== null || branch.publicKey?.length !== 33 || branch.chainCode?.length !== 32 ||
        branch.depth !== 4 || branch.index !== 0 || branch.publicExtendedKey !== xpub) {
      throw new Error('Unsupported public branch');
    }
    return branch;
  } catch {
    // Library parsing errors can contain caller-supplied data. Never expose it.
    throw new PaymentError('invalid_public_branch', 400);
  }
}

export function validatePublicBranch(chain: Chain, xpub: string): {xpub: string; fingerprint: string} {
  const branch = publicBranch(chain, xpub);
  // Full derivation-material identity, not BIP32's collision-prone 4-byte ID.
  // Metadata repackaging cannot bypass duplicate-branch protection in the ledger.
  const fingerprint = createHash('sha256').update(branch.publicKey!).update(branch.chainCode!).digest('hex');
  return {xpub, fingerprint};
}

export function derivePaymentAddress(chain: Chain, xpub: string, index: number): string {
  if (!Number.isSafeInteger(index) || index < 0 || index >= HARDENED_OFFSET) {
    throw new PaymentError('invalid_derivation_index', 400);
  }
  const branch = publicBranch(chain, xpub);
  try {
    const child = branch.deriveChild(index);
    // BIP32 permits a library to skip an invalid child. This service must never
    // reserve one index while returning another, which could duplicate an address.
    if (child.index !== index || child.depth !== branch.depth + 1 || child.privateKey !== null || child.publicKey?.length !== 33) {
      throw new Error('Invalid derived child');
    }
    const uncompressed = ECDH.convertKey(Buffer.from(child.publicKey), 'secp256k1', undefined, undefined, 'uncompressed');
    if (typeof uncompressed === 'string' || uncompressed.length !== 65 || uncompressed[0] !== 4) throw new Error('Invalid public key');
    const payload = Buffer.from(keccak_256(uncompressed.subarray(1))).subarray(-20).toString('hex');
    return normalizeAddress(chain, chain === 'bsc' ? '0x' + payload : '41' + payload);
  } catch {
    throw new PaymentError('invalid_derived_child', 503);
  }
}
