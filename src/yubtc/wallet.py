from typing import TYPE_CHECKING, NamedTuple

from yubtc.fwd import (TNonce, TSatoshi, TBTC, TSeed, TAddress, TPassphrase,
                       MIN_RELAY_TX_FEE, AddrType, ADDR_TYPES)
from yubtc.transaction import CTransaction, SpendInput
from yubtc.util import NotNone, OPTIONAL, require_kwargs_only

if TYPE_CHECKING:
    # Type hints only: importing these at runtime would create a cycle
    # (net -> wallet) and pull coincurve into annotation-only call sites.
    from coincurve import PrivateKey
    from yubtc.net import NetworkBackend


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
        every type, only the address encoding differs.

        Omitted means `legacy` -- the v0.1 constructor, kept
        bit-for-bit (mirroring the Rust split where `TPrivKey::new`
        pins `AddrType::Legacy` while the CLI/FFI surface passes its
        own default, `DEFAULT_ADDR_TYPE` = native). The multi-form
        scan (spec ОВ-4) makes every form of every nonce visible
        regardless of this type: it affects only the key's own
        receiving/cashback encoding, never what a scan can see."""
        from yubtc.crypto import default_kdf, seed2privkey
        from yubtc.fwd import AddrType
        from yubtc.net import get_backend
        if not seed:
            raise ValueError('seed cannot be empty')
        resolved_addr_type = AddrType.LEGACY if addr_type is OPTIONAL else addr_type
        if resolved_addr_type not in ADDR_TYPES:
            raise ValueError(f'unknown addr type: {resolved_addr_type!r}')
        self._addr_type = resolved_addr_type
        # The KDF this key was derived with (mirrors the Rust `kdf`
        # field). Python routes the KDF on the passphrase, so the
        # resolved name is exactly what `seed2privkey` used below.
        self.kdf = default_kdf(passphrase)
        self.privkey = seed2privkey(seed=seed, nonce=nonce, passphrase=passphrase,
                                    addr_type=resolved_addr_type)
        self.nonce = nonce
        # This key's own-form address (str for every type), cached at
        # construction like the Rust `address` field: the cached
        # network methods query it, so a native-typed key asks the
        # backend about its `bc1q...` address, not the legacy one.
        self.address = _address_for_key(privkey=self.privkey,
                                        addr_type=resolved_addr_type)
        self._backend = backend if backend is not None else get_backend()
        self._info = None

    def get_privwif(self) -> str:
        from yubtc.crypto import privkey2privwif
        return privkey2privwif(privkey=self.privkey)

    def get_p2pkh_address(self):
        """v0.1 name, kept for call-site compatibility (mirrors the
        Rust `TPrivKey::get_p2pkh_address` alias): returns the key's
        own-form address -- the legacy P2PKH bytes for a legacy key,
        the SegWit/Taproot encoding (str) for witness keys. The
        type-aware entry point is `address_of`."""
        if self._addr_type == AddrType.LEGACY:
            from yubtc.crypto import privkey2addr
            return privkey2addr(privkey=self.privkey)
        return self.address

    @require_kwargs_only
    def address_of(self, addr_type: str = OPTIONAL) -> str:
        """Encode this key's address per `addr_type` (mirrors the
        Phase 13 `TPrivKey::address_of`): `legacy` -> P2PKH
        (`1...`), `native` -> P2WPKH (`bc1q...`), `taproot` -> P2TR
        (`bc1p...`). Omitted resolves to the type this key was
        derived for. The result is a `str` for every form.

        Allowed in two cases:
        - the key's own type (trivially -- the cached address);
        - a variant-A key (non-pbkdf2 KDF), which is the *same*
          secret for every type and therefore re-encodes freely.

        A pbkdf2 key asked for a *different* type is an error (mirrors
        the Rust purpose guard): its leaves are disjoint BIP-32
        subtrees, so re-encoding would hand back an address no
        external BIP-84/86 wallet would agree with. Derive the right
        key with `TPrivKey(addr_type=...)` instead."""
        resolved = self._addr_type if addr_type is OPTIONAL else addr_type
        if resolved not in ADDR_TYPES:
            raise ValueError(f'unknown addr type: {resolved!r}')
        if resolved == self._addr_type:
            return self.address
        from yubtc.crypto import KDF_PBKDF2
        if self.kdf == KDF_PBKDF2:
            raise ValueError(
                'pbkdf2 keys are purpose-bound: this key addresses {own}, '
                'not {other} (derive the key via TPrivKey(addr_type=...))'.format(
                    own=self._addr_type, other=resolved))
        return _address_for_key(privkey=self.privkey, addr_type=resolved)

    def get_info(self) -> dict:
        from yubtc.net import get_address_info
        if not self._info:
            self._info = get_address_info(self._backend, self.address)
        return self._info

    def is_unused(self) -> bool:
        total_received = self.get_info()['total_received']
        return total_received == 0

    @require_kwargs_only
    def get_unspent(self, confirmations: int = NotNone) -> list:
        from yubtc.net import get_address_unspent
        result = list()
        for x in get_address_unspent(self._backend, self.address):
            if x['confirmations'] >= confirmations:
                result.append({
                    'tx': x['tx_hash'], 'out_n': x['tx_output_n'],
                    'amount': x['value'], 'script': x['script'],
                    'confirmations': x['confirmations'],
                })
        return result


@require_kwargs_only
def _address_for_key(privkey: 'PrivateKey' = NotNone,
                     addr_type: str = NotNone) -> str:
    """Address of `privkey` in the given encoding (mirrors
    `wallet.rs::address_for_key`): `legacy` -> P2PKH (`1...`),
    `native` -> P2WPKH bech32 (`bc1q...`), `taproot` -> P2TR bech32m
    (`bc1p...`, through the BIP-86 TapTweak). Always a `str`."""
    from yubtc.crypto import (privkey2pubkey, pubkey2addr,
                              pubkey2segwit_addr, pubkey2taproot_addr)
    pubkey = privkey2pubkey(privkey=privkey)
    if addr_type == AddrType.NATIVE:
        return pubkey2segwit_addr(pubkey=pubkey)
    if addr_type == AddrType.TAPROOT:
        return pubkey2taproot_addr(pubkey=pubkey)
    return pubkey2addr(pubkey=pubkey).decode('ascii')


class AddressForm(NamedTuple):
    """One queryable address form at a nonce (mirrors
    `wallet.rs::AddressForm`): the type, the key that spends that
    form, and the address to ask the backend about.

    For the BIP-39-standard pbkdf2 KDF each form carries a *distinct*
    key (the m/44'/84'/86' leaves); for the non-BIP-32 KDFs (вариант
    A, spec ОВ-2) all three forms share the same secret, re-encoded.
    Each form gets its own `TPrivKey` view: the cached network methods
    (`get_info`/`get_unspent`) always query the key's own `address`,
    so the per-form queries land on the right addresses."""
    addr_type: str
    privkey: 'TPrivKey'
    address: str


@require_kwargs_only
def nonce_address_forms(seed: TSeed = NotNone, nonce: TNonce = NotNone,
                        passphrase: TPassphrase = NotNone,
                        backend: 'NetworkBackend' = NotNone) -> list:
    """Every address form the wallet can own at `nonce`, in canonical
    scan order P2PKH -> P2WPKH -> P2TR (mirrors
    `wallet.rs::nonce_address_forms`).

    - pbkdf2 (non-empty passphrase): three distinct keys, derived at
      `m/44'...` (legacy), `m/84'...` (BIP-84, native) and `m/86'...`
      (BIP-86, taproot);
    - yubtc cascade (вариант A / empty passphrase): one secret,
      encoded three ways -- the WIF is identical across the forms.

    P2SH is deliberately absent -- the wallet never creates P2SH for
    itself (it only ever *receives* to P2SH via external request)."""
    forms = []
    for addr_type in ADDR_TYPES:
        pk = TPrivKey(seed=seed, nonce=nonce, passphrase=passphrase,
                      backend=backend, addr_type=addr_type)
        forms.append(AddressForm(addr_type=addr_type, privkey=pk,
                                 address=pk.address))
    return forms


@require_kwargs_only
def _nonce_is_used(forms: list = NotNone) -> bool:
    """Whether any form of the nonce has ever received funds (mirrors
    `wallet.rs::nonce_is_used`): the gap rule generalised to nonces --
    a nonce is "used" when at least one form was ever paid.
    `total_received > 0` is the v0.1 `is_unused` sentinel, kept
    bit-for-bit."""
    for form in forms:
        if form.privkey.get_info()['total_received'] > 0:
            return True
    return False


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
        Omitted means `legacy` -- the v0.1 constructor, kept
        bit-for-bit (the CLI passes its own default,
        `DEFAULT_ADDR_TYPE` = native, explicitly).

        The gap walk spans all three address forms per nonce (spec
        ОВ-4): a nonce counts as used when ANY of its forms ever
        received funds, so a wallet opened as `legacy` still sees a
        nonce that only ever held a `bc1...` UTXO, and the keys it
        keeps are the wallet's own receive type."""
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
            forms = nonce_address_forms(seed=seed, nonce=nonce,
                                        passphrase=passphrase,
                                        backend=self._backend)
            if not _nonce_is_used(forms=forms):
                break
            # `nonce_address_forms` always emits every `AddrType` --
            # including the wallet's receive type -- so the mapping
            # cannot miss (documented invariant).
            form_by_type = {form.addr_type: form.privkey for form in forms}
            self.privkeys.append(form_by_type[resolved_addr_type])
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
        """Walk forward from nonce 0 collecting every form's UTXOs
        (multi-form scan, spec ОВ-4; mirrors the Rust
        `scan_inputs_until`).

        On each nonce ALL THREE forms (P2PKH + P2WPKH + P2TR) are
        queried. The walk stops when either:
        - the running total of satoshis >= `target` (when target is
          not None), or
        - a nonce where NO form has ever received funds is found (the
          gap rule generalised to nonces: a nonce whose every form is
          unused hides nothing newer).

        Returns `(sources, cashback_addr)`:
        - one source `(TPrivKey, unspent)` per contributing
          `(nonce, form)`, with the key that spends that form;
        - `cashback_addr` is the address to send any change to:
          - gap stop: the gap nonce's address in the wallet's own
            receive type (`_addr_type`) -- the v0.1 "unused address
            gets the change" rule, generalised to forms;
          - target met: the address of the LAST contributing
            `(nonce, form)` -- the same `(nonce, form)` the last
            source came from, NOT the wallet's receive type.

        `on_address`, if provided, is invoked as `on_address(tp,
        unspent)` for every contributing source (in scan order). The
        gap stop and target-met stop are not reported.

        Note on `confirmations`: accepted for API stability but not
        applied at the scan layer (mirrors the Rust
        `scan_inputs_until`): the scan returns every UTXO found at
        contributing addresses so callers can re-filter. The default
        non-scan path (`_select_inputs` without `scan`) filters by
        `confirmations` as before.

        Note on gap detection: a form that *was* paid to but has since
        been fully spent returns [] from get_unspent() yet counts as
        used (`total_received > 0`), so the walk continues past it --
        treating it as a gap would truncate the scan and miss later
        addresses with fresh UTXOs.
        """
        sources = []
        total = 0
        nonce = 0
        cashback_addr = None
        while True:
            forms = nonce_address_forms(seed=self._seed, nonce=nonce,
                                        passphrase=self._passphrase,
                                        backend=self._backend)
            if not _nonce_is_used(forms=forms):
                # True gap: no form of this nonce ever received
                # anything. Cashback goes here, in the wallet's own
                # receive encoding (the address is hidden in the gap
                # and ready to receive change).
                addr_by_type = {form.addr_type: form.address for form in forms}
                cashback_addr = addr_by_type[self._addr_type]
                break
            # Fetch the UTXOs of every used form (an unused form never
            # received anything, so it cannot hold UTXOs -- the
            # `get_unspent` round-trip is skipped for it).
            contributed = False
            last_addr = None
            for form in forms:
                if form.privkey.get_info()['total_received'] == 0:
                    continue
                unspent = form.privkey.get_unspent(confirmations=0)
                if not unspent:
                    # Used form, but everything was spent.
                    continue
                for u in unspent:
                    total += u['amount']
                sources.append((form.privkey, unspent))
                contributed = True
                last_addr = form.address
                if on_address is not None:
                    on_address(form.privkey, unspent)
            if contributed and target is not None and total >= target:
                # Target met: cashback goes to the same (nonce, form)
                # the last source came from.
                cashback_addr = last_addr
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
            on_address: object = None,
            fee: TSatoshi = NotNone) -> tuple:
        """Pick `(vin_sources, src)` for the next transaction.

        Three input modes:
        - `sources` provided: caller has already selected inputs (e.g.
          via the interactive TUI). `cashback_addr` is the destination
          for any change; the scan is skipped.
        - `scan=True`: walk the seed forward over every address form
          collecting UTXOs until `amount + fee` is met or the gap
          limit is hit (the Rust CLI's target: the collected inputs
          must cover the payment AND the fee). Cashback goes to the
          last contributing `(nonce, form)`, or to the gap nonce's
          address in the wallet's receive type.
        - otherwise: use the wallet's primary address's UTXOs only;
          cashback goes back to the same address (in the key's own
          form).

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
            # When scanning, fetch UTXOs from every address form
            # starting at nonce 0 until either the target (amount +
            # fee, so the inputs cover the payment and the fee) is met
            # or an unused nonce is hit. Drain (`amount=None`) never
            # early-terminates: it walks to the gap limit.
            target = None if amount is None else amount + fee
            return self._scan_inputs(
                target=target, confirmations=confirmations,
                on_address=on_address)
        # Default: just the primary address's UTXOs, cashback to the
        # same address in its own encoding.
        src = self.privkeys[0].address_of()
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
            on_address=on_address, fee=fee)
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
