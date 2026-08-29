from typing import NamedTuple, TYPE_CHECKING

from coincurve import PrivateKey

from yubtc.fwd import TAddress, TNonce, TSatoshi, TSeed, TPassphrase
from yubtc.util import NotNone, OPTIONAL, require_kwargs_only

if TYPE_CHECKING:
    from yubtc.script import CScript

SUFFIX_PRIVKEY_COMPRESSED = 0x01
PREFIX_P2PKH = 0x00  # Public Key Hash
PREFIX_PUBKEY = 0x02  # Compressed pubkey prefix; the low bit signals parity of y.
PREFIX_P2SH = 0x05  # https://github.com/bitcoinbook/bitcoinbook/blob/develop/ch07.asciidoc#pay-to-script-hash-p2sh
PREFIX_TESTNET_P2PKH = 0x6F
PREFIX_TESTNET_P2SH = 0xc4
PREFIX_PRIVKEY = 0x80
PREFIX_ENCPRIVKEY = 0x0142  # BIP-38
PREFIX_EXTPUBKEY = 0x0488B21E  # BIP-32
# TODO: SEGWIT https://github.com/bitcoinbook/bitcoinbook/blob/develop/ch07.asciidoc#segregated-witness

# --- KDF selection (mirrors yubtc core/src/kdf.rs::KdfAlgo) ----------
#
# Four KDFs, one derivation shape for the three passphrase modes:
# stretch the mnemonic to 64 bytes, then take the BIP-44
# receiving-chain leaf at m/44'/0'/0'/0/<nonce>. Only the stretch
# differs, so `nonce` stays meaningful in every mode and one expensive
# stretch per wallet buys cheap BIP-32 walks per address.

KDF_YUBTC = 'yubtc'  # legacy cascade -- empty passphrase only
KDF_PBKDF2 = 'pbkdf2'  # BIP-39 compatible; default for non-empty passphrase
KDF_ARGON2ID = 'argon2id'  # Argon2id stretch, then BIP-44 walk
KDF_SCRYPT = 'scrypt'  # scrypt stretch, then BIP-44 walk
_KDF_ALGOS = (KDF_YUBTC, KDF_PBKDF2, KDF_ARGON2ID, KDF_SCRYPT)

# Frozen KDF parameters (mirrors kdf.rs). Changing any of these changes
# every key the affected KDF has ever produced -- no existing wallet
# would open again.
STRETCH_LEN = 64  # BIP-32 master-key construction expects 64 bytes
ARGON2_SALT_TAG = b'yubtc-argon2id-v1\x00'
ARGON2_TIME_COST = 3
ARGON2_MEMORY_KIB = 64 * 1024  # 64 MiB
ARGON2_PARALLELISM = 4
SCRYPT_SALT_TAG = b'yubtc-scrypt-v2\x00'
SCRYPT_LOG_N = 15  # N = 2^15
SCRYPT_R = 16  # r=16 -> 128 * r * N = 64 MiB
SCRYPT_P = 1
# hashlib.scrypt forwards `maxmem` to OpenSSL, whose default cap
# (32 MiB) is below the 64 MiB this frozen KDF legitimately needs.
# 2x headroom over 128 * r * N; the cap never changes the output bytes.
_SCRYPT_MAXMEM = 2 * 128 * SCRYPT_R * (1 << SCRYPT_LOG_N)


class KdfError(ValueError):
    """Base class for typed KDF failures (mirrors
    `yubtc core/src/kdf.rs::KdfError`)."""


class PassphraseRequired(KdfError):
    """The chosen KDF stretches a passphrase; an empty one was
    supplied (mirrors `KdfError::PassphraseRequired`)."""


class EmptyPassphraseIncompatible(KdfError):
    """The legacy yubtc cascade is passphrase-free by definition; a
    non-empty passphrase was supplied (mirrors
    `KdfError::EmptyPassphraseIncompatible`)."""


class Bip32Error(KdfError):
    """BIP-32 derivation failed (mirrors `KdfError::Bip32`)."""


def default_kdf(passphrase: TPassphrase) -> str:
    """Choose the default KDF given a passphrase (mirrors
    `KdfAlgo::default_for`): empty -> 'yubtc' (the legacy cascade,
    bit-for-bit with pre-passphrase wallets), non-empty -> 'pbkdf2'
    (the BIP-39-compatible path)."""
    if passphrase:
        return KDF_PBKDF2
    return KDF_YUBTC


def _stretch_pbkdf2(seed: TSeed, passphrase: TPassphrase) -> bytes:
    """PBKDF2-HMAC-SHA512 with the BIP-39 standard parameters (mirrors
    `kdf.rs::pbkdf2`): NFKD-normalised seed and passphrase, salt
    `b'mnemonic' + passphrase`, 2048 iterations, 64-byte output.
    `pbkdf2_hmac` is infallible for valid inputs."""
    from hashlib import pbkdf2_hmac
    import unicodedata
    seed_bytes = unicodedata.normalize('NFKD', seed).encode('utf-8')
    pass_bytes = unicodedata.normalize('NFKD', passphrase).encode('utf-8')
    return pbkdf2_hmac(
        'sha512',
        seed_bytes,
        b'mnemonic' + pass_bytes,
        2048,
        dklen=STRETCH_LEN,
    )


def _stretch_argon2id(seed: TSeed, passphrase: TPassphrase) -> bytes:
    """Argon2id stretch (the compute step of `kdf.rs::argon2id_bip44`):
    salt `b'yubtc-argon2id-v1\x00' + passphrase`, frozen parameters
    m=64 MiB / t=3 / p=4, Argon2id v0x13, 64-byte output. Neither input
    is NFKD-normalised here -- the Rust side hashes the raw UTF-8
    bytes, so a decomposed passphrase derives a different (but equally
    reproducible) key than its composed form."""
    from argon2.low_level import Type, hash_secret_raw
    return hash_secret_raw(
        secret=seed.encode('utf-8'),
        salt=ARGON2_SALT_TAG + passphrase.encode('utf-8'),
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_KIB,
        parallelism=ARGON2_PARALLELISM,
        hash_len=STRETCH_LEN,
        type=Type.ID,
    )


def _stretch_scrypt(seed: TSeed, passphrase: TPassphrase) -> bytes:
    """scrypt stretch (the compute step of `kdf.rs::scrypt_bip44`):
    salt `b'yubtc-scrypt-v2\x00' + passphrase`, frozen parameters
    N=2^15 / r=16 (64 MiB) / p=1, 64-byte output. Raw UTF-8 bytes, no
    NFKD -- same convention as the Argon2id stretch."""
    from hashlib import scrypt
    return scrypt(
        seed.encode('utf-8'),
        salt=SCRYPT_SALT_TAG + passphrase.encode('utf-8'),
        n=1 << SCRYPT_LOG_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=STRETCH_LEN,
        maxmem=_SCRYPT_MAXMEM,
    )


# The stretch for each passphrase KDF; the BIP-44 walk after it is shared.
_STRETCH = {
    KDF_PBKDF2: _stretch_pbkdf2,
    KDF_ARGON2ID: _stretch_argon2id,
    KDF_SCRYPT: _stretch_scrypt,
}


def _bip44_leaf(stretched: bytes, nonce: TNonce) -> bytes:
    """Turn 64 stretched bytes into the BIP-44 receiving-chain leaf at
    `m/44'/0'/0'/0/<nonce>` (mirrors `kdf.rs::bip44_leaf`).

    Every passphrase KDF funnels through here: the expensive stretch
    runs once per wallet, and each additional address costs one cheap
    BIP-32 walk -- which is what keeps address scanning affordable.
    Folding the nonce into the stretch salt instead would re-run the
    stretch per address."""
    from yubtc.bip32 import master_from_seed, derive_path
    if nonce >= 0x80000000:
        # BIP-32 limits non-hardened child indexes to < 2^31. The CLI
        # rejects such nonces upstream, but the library can't assume
        # that (mirrors `kdf.rs::make_bip44_path`).
        raise Bip32Error(
            f'BIP-32 derivation failed: path {nonce}: '
            f'non-hardened child index must be < 2^31')
    master_priv, master_chain = master_from_seed(seed=stretched)
    path = "m/44'/0'/0'/0/{nonce}".format(nonce=nonce)
    child_priv, _ = derive_path(master_priv=master_priv, master_chain=master_chain, path=path)
    return child_priv


def str2bytes(s: str) -> bytes:
    return s.encode('latin-1')


def bytes2str(b: bytes) -> str:
    return ''.join(map(chr, b))


def str2list(s: str) -> list:
    return [c for c in s]


@require_kwargs_only
def seed2bin(seed: TSeed = NotNone,
             nonce: TNonce = NotNone,
             passphrase: TPassphrase = None,
             kdf: str = OPTIONAL) -> bytes:
    """KDF: turn `(seed, nonce, passphrase, kdf)` into a 32-byte secret.

    Four derivations, selected by the `kdf` name (mirrors
    `yubtc core/src/kdf.rs::seed2bin`; the names are `KdfAlgo::as_str`):

    - **'yubtc'** -- the legacy `blake2b -> keccak -> sha256` cascade
      over `pack('>L', nonce) || seed` (latin-1). Passphrase-free by
      definition: a non-empty passphrase raises
      `EmptyPassphraseIncompatible`. The output is bit-for-bit
      identical to the pre-passphrase code path, so a wallet that has
      been around since before passphrase support still opens.

    - **'pbkdf2'** -- BIP-39 + BIP-32 + BIP-44. The mnemonic and
      passphrase are NFKD-normalized and UTF-8-encoded, then stretched
      through standard PBKDF2-HMAC-SHA512 (salt `b'mnemonic' +
      passphrase`, 2048 iter, 64 bytes). Any BIP-44 wallet (Trezor,
      Ledger, Electrum, ...) with the same mnemonic and passphrase
      arrives at the same key for the same nonce. An empty passphrase
      raises `PassphraseRequired`.

    - **'argon2id'** -- Argon2id stretch (salt
      `b'yubtc-argon2id-v1\x00' + passphrase`, frozen parameters
      m=64 MiB / t=3 / p=4, v0x13) feeding the same BIP-44 walk.
      Memory-hard, so a stolen mnemonic is far more expensive to
      brute-force on GPU/ASIC. Yubtc-only; empty passphrase raises
      `PassphraseRequired`.

    - **'scrypt'** -- scrypt stretch (salt `b'yubtc-scrypt-v2\x00' +
      passphrase`, frozen parameters N=2^15 / r=16 -> 64 MiB / p=1)
      feeding the same BIP-44 walk. Yubtc-only; empty passphrase raises
      `PassphraseRequired`.

    All three passphrase KDFs share one shape: stretch the mnemonic to
    64 bytes once, then walk `m/44'/0'/0'/0/<nonce>` -- the BIP-44
    receiving-chain path -- so `nonce` selects the address cheaply in
    every mode. A `nonce >= 2^31` raises `Bip32Error` (BIP-32 caps
    non-hardened child indexes).

    `kdf` may be omitted: the default is then chosen from the
    passphrase exactly as before this parameter existed (empty ->
    'yubtc', non-empty -> 'pbkdf2'), so existing callers keep deriving
    the same bytes. Passing `kdf` explicitly switches the algorithm --
    and its passphrase compatibility rules -- on. An unknown name
    raises `ValueError`.
    """
    from yubtc.hash import sha256, keccak256, blake2b256
    from struct import pack
    if kdf is OPTIONAL:
        # Caller did not choose: keep the historic passphrase routing
        # (empty -> legacy cascade, non-empty -> pbkdf2). The branch is
        # gated on the *string* being empty, not on the seed -- a seed
        # of "" is rejected by `TPrivKey` / `Wallet` higher up.
        kdf = default_kdf(passphrase)
    if kdf not in _KDF_ALGOS:
        raise ValueError(f'unknown kdf: {kdf!r}')
    if kdf == KDF_YUBTC:
        if passphrase:
            raise EmptyPassphraseIncompatible(
                'empty passphrase is incompatible with kdf=yubtc '
                '(legacy cascade is passphrase-free)')
        # Backward-compatible path: existing wallets and tests keep
        # producing the same bytes they always did.
        data = pack(">L", nonce) + str2bytes(seed)
        return sha256(keccak256(blake2b256(data)))
    if not passphrase:
        raise PassphraseRequired(f'passphrase required for kdf={kdf}')
    # The stretch is the only thing that differs between the three
    # passphrase KDFs; the BIP-44 walk after it is shared.
    stretched = _STRETCH[kdf](seed, passphrase)
    return _bip44_leaf(stretched, nonce)


def bin2privkey(data: bytes) -> bytes:
    privkey = bytearray(data)
    """
    Clamping the lower bits ensures the key is a multiple of the cofactor.
    This is done to prevent small subgroup attacks.
    Clamping the (second most) upper bit to one is done because certain
    implementations of the Montgomery Ladder don't correctly handle this
    bit being zero.
    """
    privkey[0] &= 248
    privkey[31] &= 127
    privkey[31] |= 64
    return bytes(privkey)


@require_kwargs_only
def seed2privkey(seed: TSeed = NotNone,
                 nonce: TNonce = NotNone,
                 passphrase: TPassphrase = '',
                 kdf: str = OPTIONAL) -> PrivateKey:
    """Derive the signing key from `(seed, nonce, passphrase, kdf)`.

    Clamp policy (decision C1): the X25519-style clamp applies ONLY to
    the legacy yubtc cascade (kdf='yubtc', which includes the default
    when `kdf` is omitted and the passphrase is empty), keeping
    bit-for-bit parity with pre-passphrase yubtc wallets. Every
    BIP-44-leaf KDF ('pbkdf2'/'argon2id'/'scrypt') feeds the raw
    32-byte leaf to secp256k1 verbatim, so addresses match what
    Trezor/Ledger/Electrum derive for the same (mnemonic, passphrase).
    Mirrors the Rust port's `seed2privkey_with_kdf`.

    `kdf` has the same meaning as in `seed2bin` (omit it to keep the
    historic passphrase routing; an unknown name or a passphrase
    incompatibility raises the same errors).
    """
    resolved = default_kdf(passphrase) if kdf is OPTIONAL else kdf
    raw = seed2bin(seed=seed, nonce=nonce, passphrase=passphrase, kdf=resolved)
    if resolved == KDF_YUBTC:
        return PrivateKey(bin2privkey(raw))
    return PrivateKey(raw)


@require_kwargs_only
def privkey2privwif(privkey: PrivateKey = NotNone) -> str:
    from yubtc.base58check import base58CheckEncode
    # https://github.com/bitcoinbook/bitcoinbook/blob/develop/ch04.asciidoc#comp_priv
    return base58CheckEncode(
        bytes([PREFIX_PRIVKEY]) + privkey.secret + bytes([SUFFIX_PRIVKEY_COMPRESSED]))


def privwif2privkey(privwif: str) -> PrivateKey:
    from yubtc.base58check import base58CheckDecode
    decoded = base58CheckDecode(privwif)
    if decoded[0] != PREFIX_PRIVKEY:
        raise ValueError('prefix mismatch')
    body = decoded[1:]
    # Compressed WIFs are 33 bytes with the 0x01 suffix; uncompressed WIFs
    # are 32 bytes. Only compressed is supported.
    if len(body) != 33 or body[-1] != SUFFIX_PRIVKEY_COMPRESSED:
        raise ValueError('uncompressed wif not supported')
    return PrivateKey(body[:-1])


def privkey2pubkey(privkey: PrivateKey) -> bytes:
    # 33-byte compressed form: PREFIX_PUBKEY || X. The low bit of the prefix
    # carries the parity of y, so the receiving side can recover the full
    # point on the curve from X alone.
    return privkey.public_key.format(compressed=True)


@require_kwargs_only
def sign_hash(privkey: PrivateKey = NotNone, datahash: bytes = NotNone) -> bytes:
    # hasher=None: sign the 32-byte digest directly. libsecp256k1 already
    # produces DER-encoded, low-s signatures by default.
    return privkey.sign(datahash, hasher=None)


@require_kwargs_only
def sign_data(privkey: PrivateKey = NotNone, data: bytes = NotNone) -> bytes:
    from yubtc.hash import sha256
    # Bitcoin transaction-hash: double-SHA256, then ECDSA.
    return privkey.sign(sha256(sha256(data)), hasher=None)


@require_kwargs_only
def pubkey2addr(pubkey: bytes = NotNone) -> bytes:
    from yubtc.base58check import base58CheckEncode
    from yubtc.hash import hash160
    return base58CheckEncode(bytes([PREFIX_P2PKH]) + hash160(pubkey))


@require_kwargs_only
def privkey2addr(privkey: PrivateKey = NotNone) -> bytes:
    return pubkey2addr(pubkey=privkey2pubkey(privkey))


"""
>>> p = 115792089237316195423570985008687907853269984665640564039457584007908834671663
>>> x = 55066263022277343669578718895168534326250603453777594175500187360389116729240
>>> y = 32670510020758816978083085130507043184471273380659243275938904335757337482424
>>> (x ** 3 + 7) % p == y**2 % p
"""


def make_lock_script(address: TAddress) -> 'CScript':
    from yubtc.script import CScript, OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG, OP_EQUAL
    from yubtc.crypto import PREFIX_P2PKH, PREFIX_P2SH
    from yubtc.misc import unpack_address
    prefix, dsthash = unpack_address(address)
    if prefix == PREFIX_P2PKH:
        return CScript([OP_DUP, OP_HASH160, dsthash, OP_EQUALVERIFY, OP_CHECKSIG])
    elif prefix == PREFIX_P2SH:
        return CScript([OP_HASH160, dsthash, OP_EQUAL])
    else:
        raise ValueError('address not supported')


class VoutResult(NamedTuple):
    """Output of `make_vout`: the vout list plus the satoshi amounts.

    `cashback` is 0 in the drain branch (no change output) and the
    genuine cashback value otherwise. `amount` is what leaves the wallet
    for `dst` (the requested amount, or the drained input minus fee in
    drain mode).
    """
    vout: list
    cashback: TSatoshi
    amount: TSatoshi


@require_kwargs_only
def make_vout(src: TAddress = NotNone, dst: TAddress = NotNone,
              in_amount: TSatoshi = NotNone, amount: TSatoshi = None,
              fee: TSatoshi = NotNone) -> VoutResult:
    from yubtc.transaction import COut
    if in_amount < fee:
        # Drain (`amount is None`) lands in the branch below and would
        # compute `amount = in_amount - fee < 0`. Bail out with a message
        # that names both numbers so the operator can see the gap.
        raise ValueError('input does not cover fee')
    if amount is not None and amount + fee > in_amount:
        # Non-drain branch: this is the check that keeps cashback from
        # going negative. The drain branch is gated by the check above.
        raise ValueError('amount + fee exceeds input')
    vout_script = make_lock_script(dst)
    if amount is None or (amount + fee == in_amount):
        amount = in_amount - fee
        return VoutResult(vout=[COut(amount=amount, script=vout_script)],
                          cashback=0, amount=amount)
    else:
        cashback = in_amount - amount - fee
        cashback_lock_script = make_lock_script(src)
        return VoutResult(
            vout=[COut(amount=cashback, script=cashback_lock_script),
                  COut(amount=amount, script=vout_script)],
            cashback=cashback, amount=amount)
