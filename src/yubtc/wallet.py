from typing import NamedTuple

from yubtc.fwd import (TNonce, TSatoshi, TBTC, TSeed, TAddress, TPassphrase,
                       MIN_RELAY_TX_FEE, AddrType, ADDR_TYPES)
from yubtc.transaction import CTransaction, SpendInput
from yubtc.util import NotNone, OPTIONAL, require_kwargs_only


class TxResult(NamedTuple):
    """Output of `make_transaction`: the signed tx plus the satoshi amounts.

    `cashback` is 0 when there's no change output (drain). `fee` is the
    actual satoshi amount used for the fee -- in the feekb-driven branch
    it may differ from the caller's input `fee` because the loop
    recomputes until the fee matches the tx size.
    """
    tx: CTransaction
    cashback: TSatoshi
    amount: TSatoshi
    fee: TSatoshi


@require_kwargs_only
def validate_utxo_script(script: bytes = NotNone) -> str:
    """Classify a UTXO `scriptPubKey` by its canonical shape (mirrors
    `wallet.rs::validate_utxo_script`, extended per the Phase 13 spec
    with the witness forms).

    Returns `'p2pkh'` (25 bytes), `'p2sh'` (23 bytes), `'p2wpkh'`
    (22 bytes, `00 14 <20>`), or `'p2tr'` (34 bytes, `51 20 <32>`);
    anything else raises `ValueError('unsupported utxo script')` --
    a backend mismatch the wallet doesn't know how to spend."""
    from yubtc.script import extract_p2tr_output_key, extract_p2wpkh_hash
    script = bytes(script)
    size = len(script)
    if size == 25:
        from yubtc.transaction import script2pkh
        script2pkh(script)
        return 'p2pkh'
    if size == 23:
        # P2SH: OP_HASH160 <20B> OP_EQUAL.
        if script[0] != 0xa9 or script[1] != 0x14 or script[22] != 0x87:
            raise ValueError('unsupported utxo script')
        return 'p2sh'
    if size == 22:
        extract_p2wpkh_hash(script=script)
        return 'p2wpkh'
    if size == 34:
        extract_p2tr_output_key(script=script)
        return 'p2tr'
    raise ValueError('unsupported utxo script')


def _announce_tx(backend: 'NetworkBackend', result: TxResult, dst: TAddress,
                 broadcast: bool, yes: bool = NotNone) -> None:
    """Print the signed tx dump and (optionally) push it to the network.

    Used by both `Wallet.send` and the interactive CLI path so they
    surface the same id + amount summary + rawtx and prompt identically
    before broadcasting. The broadcast goes through `backend`
    explicitly (backend injection: no module global) -- tests that
    want to intercept the call can pass a stub backend or monkeypatch
    `broadcastTx`.

    `yes=True` skips the broadcast confirmation prompt and broadcasts
    immediately; useful for scripts and CI where the prompt is unwanted.
    """
    from yubtc.misc import satoshi2btc, yesno
    from yubtc.net import broadcastTx
    cashback_btc = satoshi2btc(result.cashback)
    amount_btc = satoshi2btc(result.amount)
    fee_btc = satoshi2btc(result.fee)
    # The broadcast hex is the **wire** serialization: for witness
    # transactions it carries the marker/flag and witness stacks
    # (without them the inputs would be unspendable); for legacy
    # transactions it is byte-identical to the v0.1 `serialize()`.
    rawtx = result.tx.serialize_wire()
    # Phase 13: both size units are reported -- the wire byte size and
    # the vsize the fee loop actually bills (they coincide for
    # legacy-only transactions).
    print('id: {id}'.format(id=result.tx.id().hex()))
    print('send {amount:0.08f} BTC to {dst} (cashback={cashback:0.08f}, fee={fee:0.08f}, '
          'txsize={txsize}, vsize={vsize})'.format(
              amount=amount_btc, dst=dst, cashback=cashback_btc, fee=fee_btc,
              txsize=len(rawtx), vsize=result.tx.vsize()))
    print('rawtx: {rawtx}'.format(rawtx=rawtx.hex()))
    if broadcast:
        if yes or yesno('broadcast? '):
            broadcastTx(backend, rawtx)
    else:
        # No --broadcast: the tx is fully signed and shown above, but
        # never reaches the network. Print a clear note so the
        # operator doesn't mistake the raw tx for a sent one.
        print('Not broadcast: pass --broadcast (or run broadcastTx manually) '
              'to push this transaction to the network.')


def _pick_best_fee_loop_candidate(by_size, feekb, min_relay_per_kb=MIN_RELAY_TX_FEE):
    """Pick the best fee-loop candidate (mirrors the Rust port).

    `by_size` maps tx size -> list of `(fee, vout_result, stx)`
    candidates accumulated by the loop in `Wallet.make_transaction`.

    Rule 1 (validity): fee >= size * feekb / 1000 AND
    fee >= size * min_relay_per_kb / 1000 -- the relay floor from
    Bitcoin Core's DEFAULT_MIN_RELAY_TX_FEE. A sub-floor candidate is
    dropped even when its size is the smallest: no mempool would
    relay such a tx.
    Rule 2 (preference): smallest size; tie-break -- smallest fee for
    the same size.
    Fallback: when nothing satisfies rule 1 (pathological feekb), the
    smallest size ever produced wins -- "pays some fee" still beats
    "relay rejected", and the tx stays structurally valid.
    """
    best = None
    for size in sorted(by_size):
        needed = size * feekb // 1000
        relay_floor = size * min_relay_per_kb // 1000
        for fee, vout_result, stx in by_size[size]:
            if fee < needed or fee < relay_floor:
                continue
            if best is None or size < best[0] or (size == best[0] and fee < best[1]):
                best = (size, fee, vout_result, stx)
    if best is not None:
        return best[0], (best[1], best[2], best[3])
    smallest = min(by_size)
    return smallest, by_size[smallest][0]


class TPrivKey(object):
    @require_kwargs_only
    def __init__(
            self,
            seed: TSeed = NotNone,
            nonce: TNonce = NotNone,
            passphrase: TPassphrase = '',
            backend: 'NetworkBackend' = None,
            addr_type: str = OPTIONAL):
        """Derive a single key. `backend` is the network backend this
        key's `get_info`/`get_unspent` calls go through (backend
        injection: no module-global backend exists; mirrors the Rust
        port). `None` resolves the default `blockchain.info` via
        `get_backend()` so ad-hoc call sites stay terse.

        `addr_type` (Phase 13) selects the derivation per the spec's
        nonce->path mapping: for the pbkdf2 KDF the BIP-32 purpose is
        44 (legacy) / 84 (native, BIP-84) / 86 (taproot, BIP-86); for
        the non-BIP-32 KDFs variant A applies -- the same key for
        every type, only the address encoding differs. Omitted means
        `legacy`, keeping every v0.1 derivation byte-for-byte (the
        multi-form scan that would make `native` the safe default
        lands with the wallet stage-2 integration, as on the Rust
        side)."""
        from yubtc.crypto import seed2privkey
        from yubtc.fwd import AddrType
        from yubtc.net import get_backend
        if not seed:
            raise ValueError('seed cannot be empty')
        resolved_addr_type = AddrType.LEGACY if addr_type is OPTIONAL else addr_type
        if resolved_addr_type not in ADDR_TYPES:
            raise ValueError(f'unknown addr type: {resolved_addr_type!r}')
        self._addr_type = resolved_addr_type
        self.privkey = seed2privkey(seed=seed, nonce=nonce, passphrase=passphrase,
                                    addr_type=resolved_addr_type)
        self.nonce = nonce
        self._backend = backend if backend is not None else get_backend()
        self._info = None

    def get_privwif(self) -> str:
        from yubtc.crypto import privkey2privwif
        return privkey2privwif(privkey=self.privkey)

    def get_p2pkh_address(self) -> bytes:
        """The legacy P2PKH address (bytes, v0.1 surface). Kept as the
        legacy shortcut mirroring the Rust `p2pkh_address()`; the
        type-aware entry point is `address_of`."""
        from yubtc.crypto import privkey2addr
        return privkey2addr(privkey=self.privkey)

    @require_kwargs_only
    def address_of(self, addr_type: str = OPTIONAL) -> str:
        """Encode this key's address per `addr_type` (mirrors the
        Phase 13 `TPrivKey::address_of`): `legacy` -> P2PKH
        (`1...`), `native` -> P2WPKH (`bc1q...`), `taproot` -> P2TR
        (`bc1p...`). Omitted resolves to the type this key was
        derived for. The result is a `str` for every form.

        Note (spec ОВ-2): for the non-BIP-32 KDFs all three forms
        encode the same key; for pbkdf2 only the type this key was
        derived with (m/44'/84'/86') matches external wallets at this
        nonce."""
        from yubtc.crypto import privkey2pubkey, pubkey2addr
        from yubtc.crypto import pubkey2segwit_addr, pubkey2taproot_addr
        resolved = self._addr_type if addr_type is OPTIONAL else addr_type
        if resolved not in ADDR_TYPES:
            raise ValueError(f'unknown addr type: {resolved!r}')
        pubkey = privkey2pubkey(privkey=self.privkey)
        if resolved == AddrType.NATIVE:
            return pubkey2segwit_addr(pubkey=pubkey)
        if resolved == AddrType.TAPROOT:
            return pubkey2taproot_addr(pubkey=pubkey)
        return pubkey2addr(pubkey=pubkey).decode('ascii')

    def get_info(self) -> dict:
        from yubtc.net import get_address_info
        if not self._info:
            self._info = get_address_info(self._backend, self.get_p2pkh_address())
        return self._info

    def is_unused(self) -> bool:
        total_received = self.get_info()['total_received']
        return total_received == 0

    @require_kwargs_only
    def get_unspent(self, confirmations: int = NotNone) -> list:
        from yubtc.net import get_address_unspent
        result = list()
        for x in get_address_unspent(self._backend, self.get_p2pkh_address()):
            if x['confirmations'] >= confirmations:
                result.append({
                    'tx': x['tx_hash'], 'out_n': x['tx_output_n'],
                    'amount': x['value'], 'script': x['script'],
                    'confirmations': x['confirmations'],
                })
        return result


class Wallet(object):
    @require_kwargs_only
    def __init__(
            self,
            seed: TSeed = NotNone,
            nonce: TNonce = NotNone,
            new_addresses: int = NotNone,
            passphrase: TPassphrase = '',
            backend: 'NetworkBackend' = None,
            addr_type: str = OPTIONAL):
        """Open a wallet. `backend` is the network backend every scan
        and broadcast goes through (backend injection: no module
        global; mirrors the Rust port). `None` resolves the default
        `blockchain.info`.

        `addr_type` threads the Phase 13 address-type selection into
        every derived key (see `TPrivKey`): pbkdf2 walks the matching
        BIP-32 purpose path, non-BIP-32 KDFs re-encode the same key.
        Omitted means `legacy` -- the scan-compatible v0.1 behaviour
        until the multi-form scan (spec ОВ-4) lands with the wallet
        stage-2 integration."""
        from yubtc.fwd import AddrType
        from yubtc.net import get_backend
        if not seed:
            raise ValueError('seed cannot be empty')
        self._seed = seed
        self._backend = backend if backend is not None else get_backend()
        # Stash the passphrase so the gap scan below derives each
        # subsequent nonce with the same secret. Without this, every
        # new TPrivKey would default to an empty passphrase and the
        # scan would build an inconsistent wallet.
        self._passphrase = passphrase
        resolved_addr_type = AddrType.LEGACY if addr_type is OPTIONAL else addr_type
        if resolved_addr_type not in ADDR_TYPES:
            raise ValueError(f'unknown addr type: {resolved_addr_type!r}')
        self._addr_type = resolved_addr_type
        self.privkeys = []
        while True:
            privkey = TPrivKey(seed=seed, nonce=nonce, passphrase=passphrase,
                               backend=self._backend, addr_type=resolved_addr_type)
            if privkey.is_unused():
                break
            self.privkeys.append(privkey)
            nonce = nonce + 1
        for i in range(new_addresses):
            privkey = TPrivKey(seed=seed, nonce=nonce, passphrase=passphrase,
                               backend=self._backend, addr_type=resolved_addr_type)
            self.privkeys.append(privkey)
            nonce = nonce + 1

    @require_kwargs_only
    def send(
            self,
            dst: TAddress = NotNone,
            amount: TBTC = None,
            feekb: TSatoshi = NotNone,
            fee: TBTC = NotNone,
            confirmations: int = NotNone,
            broadcast: bool = NotNone,
            scan: bool = NotNone,
            on_address: object = None,
            yes: bool = NotNone) -> None:
        from yubtc.misc import btc2satoshi
        # amount=None is a "drain" sentinel passed through to make_transaction.
        converted_amount = None if amount is None else btc2satoshi(amount)
        satoshi_fee = btc2satoshi(fee)
        result = self.make_transaction(
            dst=dst, amount=converted_amount, feekb=feekb, fee=satoshi_fee,
            confirmations=confirmations, scan=scan,
            sources=None, cashback_addr=None, on_address=on_address)
        _announce_tx(backend=self._backend, result=result, dst=dst,
                     broadcast=broadcast, yes=yes)

    @require_kwargs_only
    def _make_vin(self, sources: list = NotNone) -> tuple:
        """Build CIn entries from one or more addresses' UTXOs.

        `sources` is a list of `(TPrivKey, unspent_list)` tuples. Each
        UTXO is validated against its privkey's pubkey per its script
        form (`validate_utxo_script`: P2PKH/P2WPKH match the
        hash160, P2TR matches the tweaked output key, P2SH is
        receiver-only and never spent by this wallet) and a
        `(privkey, pubkey)` signer pair is appended for every input.
        Single-address callers pass a one-element list; multi-address
        callers (e.g. from `_scan_inputs`) pass one entry per address
        that contributed UTXOs.

        Returns `(vin, in_amount, signers, spend)` -- the same shape
        regardless of how many addresses contribute, so the caller
        doesn't branch on single vs. multi. `spend` is the
        `SpendContext` (one `SpendInput` per input, parallel to `vin`)
        that BIP-143/BIP-341 signing needs.
        """
        from yubtc.crypto import privkey2pubkey, taproot_output_key
        from yubtc.hash import hash160
        from yubtc.script import extract_p2tr_output_key, extract_p2wpkh_hash
        from yubtc.transaction import script2pkh, CIn
        vin = list()
        in_amount = 0
        signers = list()
        spend = list()
        for tp, unspent in sources:
            pubkey = privkey2pubkey(tp.privkey)
            pubhash = hash160(pubkey)
            xonly = pubkey[1:33]
            for u in unspent:
                in_amount += u['amount']
                tx_lock_script = bytes.fromhex(u['script'])
                form = validate_utxo_script(script=tx_lock_script)
                if form == 'p2sh':
                    # P2SH is a receiving-only form for this wallet: it
                    # never creates P2SH outputs of its own, so it
                    # cannot own the redeem script needed to spend one.
                    raise ValueError('p2sh utxo cannot be spent by the wallet')
                if form == 'p2tr':
                    required_key = extract_p2tr_output_key(script=tx_lock_script)
                    if required_key != taproot_output_key(internal_xonly=xonly):
                        raise ValueError('unknown pubkey required')
                else:
                    if form == 'p2wpkh':
                        required_hash = extract_p2wpkh_hash(script=tx_lock_script)
                    else:  # 'p2pkh'
                        required_hash = script2pkh(tx_lock_script)
                    if required_hash != pubhash:
                        raise ValueError('unknown pubkey required')
                txhash = bytes.fromhex(u['tx'])
                vin.append(CIn(
                    txhash=txhash, n=u['out_n'],
                    script=tx_lock_script, sequence=0xffffffff,
                ))
                signers.append((tp.privkey, pubkey))
                spend.append(SpendInput(amount=u['amount'],
                                        script_pubkey=tx_lock_script))
        return vin, in_amount, signers, spend

    @require_kwargs_only
    def _scan_inputs(
            self,
            target: TSatoshi = None,
            confirmations: int = NotNone,
            on_address: object = None) -> tuple:
        """Walk forward from nonce 0 collecting addresses' UTXOs.

        Stops when either:
        - the running total of satoshis >= `target` (when target is not None), or
        - an address that has never received funds AND currently has no
          UTXOs is found (the BIP-44 gap limit).

        `on_address`, if provided, is invoked as `on_address(tp, unspent)`
        for every address that contributes a UTXO. The gap-limit stop and
        target-met stop are *not* reported -- only the addresses that
        actually fed inputs. Callers can use this to print progress as the
        scan runs (e.g. mirroring `balance`'s per-address line).

        Returns (sources, cashback_addr) where sources is a list of
        (TPrivKey, unspent) tuples in scan order and cashback_addr is the
        address to send any change to:
        - if the scan stopped due to the gap limit, cashback_addr is the
          unused address itself (the wallet's next address, which is
          hidden in the gap and ready to receive change);
        - otherwise cashback_addr is the last sourced address.

        Note on gap detection: an address that *was* paid to but has
        since been fully spent returns [] from get_unspent() yet is not
        unused by the wallet-init definition (which checks
        total_received). Treating that as a gap would truncate the scan
        and miss later addresses with fresh UTXOs.
        """
        sources = []
        total = 0
        nonce = 0
        cashback_addr = None
        while True:
            pk = TPrivKey(seed=self._seed, nonce=nonce, passphrase=self._passphrase,
                          backend=self._backend)
            unspent = pk.get_unspent(confirmations=confirmations)
            if pk.is_unused() and not unspent:
                # True gap: this address has never received anything and
                # has nothing to spend. Cashback goes here.
                cashback_addr = pk.get_p2pkh_address()
                break
            if unspent:
                sources.append((pk, unspent))
                for u in unspent:
                    total += u['amount']
                if on_address is not None:
                    on_address(pk, unspent)
            if target is not None and total >= target:
                # Target met: cashback goes to the last sourced address.
                cashback_addr = pk.get_p2pkh_address()
                break
            nonce += 1
        return sources, cashback_addr

    @require_kwargs_only
    def _select_inputs(
            self,
            sources: list = None,
            amount: TSatoshi = None,
            scan: bool = NotNone,
            confirmations: int = NotNone,
            cashback_addr: TAddress = None,
            on_address: object = None) -> tuple:
        """Pick `(vin_sources, src)` for the next transaction.

        Three input modes:
        - `sources` provided: caller has already selected inputs (e.g.
          via the interactive TUI). `cashback_addr` is the destination
          for any change; the scan is skipped.
        - `scan=True`: walk the seed forward collecting UTXOs until
          `amount` is met or the gap limit is hit. Cashback goes to the
          last sourced address, or to the gap-limit unused address.
        - otherwise: use the wallet's primary address's UTXOs only;
          cashback goes back to the same address.

        `amount` is consulted only in scan mode (as the stop target).
        Returns `(vin_sources, src)`: a list of `(TPrivKey, unspent)`
        pairs ready to feed into `_make_vin`, and the address to send
        any change output to.
        """
        if sources is not None:
            # Caller pre-selected (e.g. the interactive UI). The cashback
            # address is whatever the caller picked -- normally the gap-
            # limit unused address so a fresh receive slot gets the change.
            if cashback_addr is None:
                raise TypeError('cashback_addr not set')
            return sources, cashback_addr
        if scan:
            # When scanning, fetch UTXOs from every address starting at
            # nonce 0 until either the target amount is met or an unused
            # address is hit. Cashback goes to the last input or to the
            # unused address (when the scan halted via gap limit).
            return self._scan_inputs(
                target=amount, confirmations=confirmations,
                on_address=on_address)
        # Default: just the primary address's UTXOs.
        from yubtc.crypto import privkey2pubkey, pubkey2addr
        pubkey = privkey2pubkey(self.privkeys[0].privkey)
        src = pubkey2addr(pubkey=pubkey)
        unspent = self.privkeys[0].get_unspent(confirmations=confirmations)
        return [(self.privkeys[0], unspent)], src

    @require_kwargs_only
    def make_transaction(
            self,
            dst: TAddress = NotNone,
            amount: TBTC = None,
            feekb: TSatoshi = NotNone,
            fee: TSatoshi = NotNone,
            confirmations: int = NotNone,
            scan: bool = NotNone,
            sources: list = None,
            cashback_addr: TAddress = None,
            on_address: object = None) -> TxResult:
        """Build and sign a transaction.

        Input selection is delegated to `_select_inputs`; this method
        handles only the build/sign/fee-tune loop and the TxResult
        assembly. Signing dispatches per input scheme
        (`sign_segwit`): legacy UTXOs sign exactly as v0.1, witness
        UTXOs (P2WPKH/P2TR) produce the BIP-143/BIP-341 witness.
        """
        from yubtc.crypto import make_vout
        vin_sources, src = self._select_inputs(
            sources=sources, amount=amount, scan=scan,
            confirmations=confirmations, cashback_addr=cashback_addr,
            on_address=on_address)
        vin, in_amount, signers, spend = self._make_vin(sources=vin_sources)
        if fee:
            vout_result = make_vout(src=src, dst=dst, in_amount=in_amount,
                                    amount=amount, fee=fee)
            tx = CTransaction(vin=vin, vout=vout_result.vout, locktime=0)
            stx = tx.sign_segwit(signers=signers, spend=spend)
            return TxResult(tx=stx, cashback=vout_result.cashback,
                            amount=vout_result.amount, fee=fee)

        # Fee loop, mirroring the Rust port: accumulate per-size
        # candidates and terminate by cycle detection on the tx size.
        # The size is a pure function of (inputs, fee), so a repeated
        # size means the iteration entered a cycle and no new candidate
        # can appear. (The old `_fee == newfee` fixed-point break could
        # oscillate forever between two values on digit-boundary sizes;
        # there is deliberately no iteration cap -- decision C3.)
        # Phase 13: the loop's size unit is the vsize (BIP-141), so
        # witness inputs pay their discounted weight; for transactions
        # without witness vsize == bytes and every result is identical
        # to v0.1.
        by_size = {}
        seen_sizes = set()
        current_fee = 0
        while True:
            vout_result = make_vout(src=src, dst=dst, in_amount=in_amount,
                                    amount=amount, fee=current_fee)
            tx = CTransaction(vin=vin, vout=vout_result.vout, locktime=0)
            stx = tx.sign_segwit(signers=signers, spend=spend)
            txsize = stx.vsize()
            newfee = int(txsize * feekb / 1000)
            by_size.setdefault(txsize, []).append((current_fee, vout_result, stx))
            if txsize in seen_sizes:
                break
            seen_sizes.add(txsize)
            current_fee = newfee

        _, (best_fee, best_vout, best_stx) = _pick_best_fee_loop_candidate(
            by_size=by_size, feekb=feekb)
        return TxResult(tx=best_stx, cashback=best_vout.cashback,
                        amount=best_vout.amount, fee=best_fee)
