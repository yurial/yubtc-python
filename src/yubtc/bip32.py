"""BIP-32 hierarchical deterministic key derivation.

The BIP-32 spec turns a single seed into a tree of `(privkey, chain_code)`
pairs: a child is derived from a parent via `HMAC-SHA512(parent_chain_code,
data)`, where `data` depends on whether the derivation index is hardened
(`'`) or not. The chain code is what makes the tree work like a sibling
set -- a leaked chain code alone cannot derive children.

yubtc uses only the **main path** of the BIP-44 tree --
`m/44'/0'/0'/0/<i>` for receiving and change alike -- because the wallet
doesn't store anything and rescans the chain on every run. Walking the
whole tree would be O(N×M) instead of O(N), with no upside for the
single-account, single-chain use case the wallet covers.

Hardened vs non-hardened:
- Hardened (`m/44'`, `m/0'`, ...) uses the privkey in the HMAC data. The
  child cannot be derived from `(parent_pubkey, parent_chain_code)`.
- Non-hardened (`m/0`, `m/<i>`) uses the parent pubkey. The child *can*
  be derived from `(parent_pubkey, parent_chain_code)`, which is what
  lets xpub-bearing watch-only wallets see addresses without privkeys.

The 4-step hardened prefix `m/44'/0'/0'` lands on the account level; the
final two non-hardened segments select the chain (always `0` in yubtc)
and the index.
"""
import hashlib
import hmac

from yubtc.util import NotNone, require_kwargs_only

# secp256k1 group order. The mod-n addition in child derivation rejects
# IL >= n; the whole derivation is invalid when the sum is 0. These cases
# are vanishingly rare (~ 1 in 2^127) but the spec mandates checking.
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


@require_kwargs_only
def master_from_seed(seed: bytes = NotNone) -> tuple:
    """BIP-32 master key derivation.

    Returns `(master_privkey, master_chain_code)`, each 32 bytes. The
    seed is the BIP-39 64-byte output for the typical wallet path; BIP-32
    accepts any 16-64 byte seed.
    """
    hmac_out = hmac.new(b'Bitcoin seed', seed, hashlib.sha512).digest()
    return hmac_out[:32], hmac_out[32:]


def _derive_child_hardened(privkey: bytes, chain_code: bytes, index: int) -> tuple:
    """Hardened child: HMAC over (0x00 || privkey || index_BE).

    Hardened means the child cannot be derived from the parent's pubkey
    and chain code alone; the parent's privkey is required as input.
    The index is serialized with the hardened bit set
    (`i | 0x80000000`) so the same numeric index can never collide
    between hardened and non-hardened derivations.
    """
    data = b'\x00' + privkey + (index | 0x80000000).to_bytes(4, 'big')
    hmac_out = hmac.new(chain_code, data, hashlib.sha512).digest()
    IL_int = int.from_bytes(hmac_out[:32], 'big')
    IR = hmac_out[32:]
    if IL_int >= SECP256K1_N:
        raise ValueError('IL out of range, derive next child')
    child_int = (IL_int + int.from_bytes(privkey, 'big')) % SECP256K1_N
    if child_int == 0:
        raise ValueError('child key is zero, derive next child')
    return child_int.to_bytes(32, 'big'), IR


def _derive_child_normal(privkey: bytes, chain_code: bytes,
                         pubkey: bytes, index: int) -> tuple:
    """Non-hardened child: HMAC over (pubkey || index_BE).

    Non-hardened means the child *can* be derived from `(parent_pubkey,
    parent_chain_code)` alone -- the privkey is mixed in only via the
    `(IL + parent_privkey) mod n` step. This is what enables xpub.
    """
    data = pubkey + index.to_bytes(4, 'big')
    hmac_out = hmac.new(chain_code, data, hashlib.sha512).digest()
    IL_int = int.from_bytes(hmac_out[:32], 'big')
    IR = hmac_out[32:]
    if IL_int >= SECP256K1_N:
        raise ValueError('IL out of range, derive next child')
    child_int = (IL_int + int.from_bytes(privkey, 'big')) % SECP256K1_N
    if child_int == 0:
        raise ValueError('child key is zero, derive next child')
    return child_int.to_bytes(32, 'big'), IR


@require_kwargs_only
def derive_path(master_priv: bytes = NotNone,
                master_chain: bytes = NotNone,
                path: str = NotNone) -> tuple:
    """Derive a child key along a path like `m/44'/0'/0'/0/0`.

    Returns `(privkey, chain_code)` at the leaf. The path is rooted at
    `m` (the master). Segments ending with `'` are hardened, everything
    else is non-hardened.

    Non-hardened derivation requires the pubkey at each step, which is
    computed from the current privkey via secp256k1 each time. The
    master path `m/44'/0'/0'/0/<i>` exercises this twice per nonce --
    once at `m/0` (the chain level) and once at `m/<i>` (the index).

    Validates the path: `m` alone returns the master; non-`m` prefixes
    are rejected; numeric segments must be non-negative integers.
    """
    if not path.startswith('m'):
        raise ValueError("path must start with 'm'")
    if path == 'm':
        return master_priv, master_chain
    privkey, chain_code = master_priv, master_chain
    for segment in path.split('/')[1:]:
        hardened = segment.endswith("'")
        index_str = segment[:-1] if hardened else segment
        if not index_str or not index_str.isdigit():
            raise ValueError(f"invalid path segment: {segment!r}")
        index = int(index_str)
        if hardened:
            privkey, chain_code = _derive_child_hardened(privkey, chain_code, index)
        else:
            from coincurve import PrivateKey
            from yubtc.crypto import privkey2pubkey
            pubkey = privkey2pubkey(privkey=PrivateKey(privkey))
            privkey, chain_code = _derive_child_normal(
                privkey, chain_code, pubkey, index)
    return privkey, chain_code
