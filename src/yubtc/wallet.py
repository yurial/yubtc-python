from typing import Optional

from coincurve import PrivateKey

from yubtc.fwd import TNonce, TSatoshi, TBTC, TSeed, TAddress


class TPrivKey(object):
    def __init__(
            self,
            *args,
            privkey: Optional[bytes] = None,
            seed: Optional[TSeed] = None,
            nonce: Optional[TNonce] = None):
        from yubtc.crypto import seed2privkey
        if args:
            raise Exception('only kwargs allowed')
        if privkey is not None:
            # accept either raw 32 bytes or an already-wrapped PrivateKey
            self.privkey = privkey if isinstance(privkey, PrivateKey) else PrivateKey(privkey)
        else:
            if seed is None:
                raise Exception('seed not set')
            if not seed:
                raise Exception('seed cannot be empty')
            if nonce is None:
                raise Exception('nonce not set')
            self.privkey = seed2privkey(seed=seed, nonce=nonce)
        self.nonce = nonce
        self._info = None

    def get_privwif(self) -> str:
        from yubtc.crypto import privkey2privwif
        return privkey2privwif(privkey=self.privkey)

    def get_p2pkh_address(self) -> bytes:
        from yubtc.crypto import privkey2addr
        return privkey2addr(privkey=self.privkey)

    def get_info(self) -> dict:
        from yubtc.net import get_address_info
        if not self._info:
            self._info = get_address_info(self.get_p2pkh_address())
        return self._info

    def is_unused(self) -> bool:
        total_received = self.get_info()['total_received']
        return total_received == 0

    def get_unspent(self, confirmations: Optional[int] = None) -> list:
        from yubtc.net import get_address_unspent
        if confirmations is None:
            raise Exception('confirmations not set')
        result = list()
        for x in get_address_unspent(self.get_p2pkh_address()):
            if x['confirmations'] >= confirmations:
                result.append({
                    'tx': x['tx_hash'], 'out_n': x['tx_output_n'],
                    'amount': x['value'], 'script': x['script'],
                })
        return result


class Wallet(object):
    def __init__(
            self,
            *args,
            seed: Optional[TSeed] = None,
            nonce: Optional[TNonce] = None,
            new_addresses: Optional[int] = None):
        if args:
            raise Exception('only kwargs allowed')
        if seed is None:
            raise Exception('seed not set')
        if not seed:
            raise Exception('seed cannot be empty')
        if new_addresses is None:
            raise Exception('new_addresses not set')
        self._seed = seed
        self.privkeys = []
        while True:
            privkey = TPrivKey(seed=seed, nonce=nonce)
            if privkey.is_unused():
                break
            self.privkeys.append(privkey)
            nonce = nonce + 1
        for i in range(new_addresses):
            privkey = TPrivKey(seed=seed, nonce=nonce)
            self.privkeys.append(privkey)
            nonce = nonce + 1

    def send(
            self,
            *args,
            dst: Optional[TAddress] = None,
            amount: Optional[TBTC] = None,
            feekb: Optional[TSatoshi] = None,
            fee: Optional[TBTC] = None,
            confirmations: Optional[int] = None,
            broadcast: Optional[bool] = None,
            scan: Optional[bool] = None,
            on_address: Optional[object] = None) -> None:
        from yubtc.misc import yesno, satoshi2btc, btc2satoshi
        from yubtc.net import sendTx
        if args:
            raise Exception('only kwargs allowed')
        if dst is None:
            raise Exception('dst not set')
        # amount=None is a "drain" sentinel passed through to make_transaction.
        if amount is None:
            converted_amount = None
        else:
            converted_amount = btc2satoshi(amount)
        if fee is None:
            raise Exception('fee not set')
        satoshi_fee = btc2satoshi(fee)
        if feekb is None:
            raise Exception('feekb not set')
        if confirmations is None:
            raise Exception('confirmations not set')
        if broadcast is None:
            raise Exception('broadcast not set')
        if scan is None:
            raise Exception('scan not set')
        tx, satoshi_cashback, satoshi_amount, satoshi_fee_used = self.make_transaction(
            dst=dst, amount=converted_amount, feekb=feekb, fee=satoshi_fee,
            confirmations=confirmations, scan=scan, on_address=on_address)
        cashback_btc = satoshi2btc(satoshi_cashback)
        amount_btc = satoshi2btc(satoshi_amount)
        fee_btc = satoshi2btc(satoshi_fee_used)
        rawtx = tx.serialize()
        print('id: {id}'.format(id=tx.id().hex()))
        print('send {amount:0.08f} BTC to {dst} (cashback={cashback:0.08f}, fee={fee:0.08f}, txsize={txsize})'.format(
            amount=amount_btc,
            dst=dst,
            cashback=cashback_btc,
            fee=fee_btc,
            txsize=len(rawtx)))
        print('rawtx: {rawtx}'.format(rawtx=rawtx.hex()))
        if broadcast:
            if yesno('broadcast? '):
                sendTx(rawtx)

    def _make_vin(self, *args, pubhash: Optional[bytes] = None, unspent: Optional[list] = None) -> tuple:
        if args:
            raise Exception('only kwargs allowed')
        if pubhash is None:
            raise Exception('pubhash not set')
        if unspent is None:
            raise Exception('unspent not set')
        from yubtc.transaction import script2pkh, CIn
        vin = list()
        in_amount = 0
        for u in unspent:
            in_amount += u['amount']
            tx_lock_script = bytes.fromhex(u['script'])
            required_hash = script2pkh(tx_lock_script)
            if required_hash != pubhash:
                raise Exception('unknown pubkey required')
            txhash = bytes.fromhex(u['tx'])
            vin.append(CIn(
                txhash=txhash, n=u['out_n'],
                script=tx_lock_script, sequence=0xffffffff,
            ))
        return vin, in_amount

    def _make_vin_multi(
            self,
            *args,
            sources: Optional[list] = None) -> tuple:
        """Build CIn entries from multiple addresses' UTXOs.

        `sources` is a list of (TPrivKey, unspent) tuples. The lock
        script of each UTXO is validated against the corresponding
        privkey's pubhash. Returns (vin, in_amount, signers) where
        signers is a list of (PrivateKey, pubwif) pairs, one per input.
        """
        if args:
            raise Exception('only kwargs allowed')
        if sources is None:
            raise Exception('sources not set')
        from yubtc.hash import hash160
        from yubtc.crypto import privkey2pubkey
        from yubtc.transaction import script2pkh, CIn
        vin = list()
        in_amount = 0
        signers = list()
        for tp, unspent in sources:
            pubkey = privkey2pubkey(tp.privkey)
            pubhash = hash160(pubkey)
            for u in unspent:
                in_amount += u['amount']
                tx_lock_script = bytes.fromhex(u['script'])
                required_hash = script2pkh(tx_lock_script)
                if required_hash != pubhash:
                    raise Exception('unknown pubkey required')
                txhash = bytes.fromhex(u['tx'])
                vin.append(CIn(
                    txhash=txhash, n=u['out_n'],
                    script=tx_lock_script, sequence=0xffffffff,
                ))
                signers.append((tp.privkey, pubkey))
        return vin, in_amount, signers

    def _scan_inputs(
            self,
            *args,
            target: Optional[TSatoshi] = None,
            confirmations: Optional[int] = None,
            on_address: Optional[object] = None) -> tuple:
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
        if args:
            raise Exception('only kwargs allowed')
        if confirmations is None:
            raise Exception('confirmations not set')
        sources = []
        total = 0
        nonce = 0
        cashback_addr = None
        while True:
            pk = TPrivKey(seed=self._seed, nonce=nonce)
            unspent = pk.get_unspent(confirmations=confirmations)
            if pk.is_unused() and not unspent:
                # True gap: this address has never received anything and
                # has nothing to spend. Retback goes here.
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

    def make_transaction(
            self,
            *args,
            dst: Optional[TAddress] = None,
            amount: Optional[TBTC] = None,
            feekb: Optional[TSatoshi] = None,
            fee: Optional[TSatoshi] = None,
            confirmations: Optional[int] = None,
            scan: Optional[bool] = None,
            on_address: Optional[object] = None) -> tuple:
        if args:
            raise Exception('only kwargs allowed')
        if dst is None:
            raise Exception('dst not set')
        from yubtc.crypto import privkey2pubkey, pubkey2addr, make_vout
        from yubtc.transaction import CTransaction
        if confirmations is None:
            raise Exception('confirmations not set')
        if feekb is None:
            raise Exception('feekb not set')
        if scan is None:
            raise Exception('scan not set')
        pubkey = privkey2pubkey(self.privkeys[0].privkey)
        if scan:
            # When scanning, fetch UTXOs from every address starting at
            # nonce 0 until either the target amount is met or an unused
            # address is hit. Retback goes to the last input or to the
            # unused address (when the scan halted via gap limit).
            sources, src = self._scan_inputs(
                target=amount, confirmations=confirmations,
                on_address=on_address)
            vin, in_amount, signers = self._make_vin_multi(sources=sources)
        else:
            src = pubkey2addr(pubkey=pubkey)
            unspent = self.privkeys[0].get_unspent(confirmations=confirmations)
            from yubtc.hash import hash160
            pubhash = hash160(pubkey)
            vin, in_amount = self._make_vin(pubhash=pubhash, unspent=unspent)
            signers = [(self.privkeys[0].privkey, pubkey)]
        _fee = fee
        while True:
            vout, _cashback, _amount = make_vout(src=src, dst=dst, in_amount=in_amount, amount=amount, fee=_fee)
            tx = CTransaction(vin=vin, vout=vout, locktime=0)
            stx = tx.sign(signers=signers)
            if fee:
                break
            txsize = len(stx.serialize())
            newfee = int(txsize * feekb / 1000)
            if _fee == newfee:
                break
            _fee = newfee

        return stx, _cashback, _amount, _fee
