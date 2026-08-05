from typing import Optional

from coincurve import PrivateKey

from yubtc.fwd import TNonce, TSatoshi, TBTC, TSeed, TAddress


class TPrivKey(object):
    def __init__(
            self,
            *args,
            privkey: Optional[bytes] = None,
            seed: Optional[TSeed] = None,
            nonce: Optional[TNonce] = None,
            compressed: Optional[bool] = None):
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
        if compressed is None:
            raise Exception('compressed not set')
        self.nonce = nonce
        self.compressed = compressed
        self._info = None

    def get_privwif(self, compressed: Optional[bool] = None) -> str:
        from yubtc.crypto import privkey2privwif
        if compressed is None:
            compressed = self.compressed
        return privkey2privwif(privkey=self.privkey, compressed=compressed)

    def get_p2pkh_address(self, compressed: Optional[bool] = None) -> bytes:
        from yubtc.crypto import privkey2addr
        if compressed is None:
            compressed = self.compressed
        return privkey2addr(privkey=self.privkey, compressed=compressed)

    def get_info(self) -> dict:
        from yubtc.net import get_address_info
        if not self._info:
            self._info = get_address_info(self.get_p2pkh_address(self.compressed))
        return self._info

    def is_unused(self) -> bool:
        total_received = self.get_info()['total_received']
        return total_received == 0

    def get_unspent(self, confirmations: Optional[int] = None) -> list:
        from yubtc.net import get_address_unspent
        if confirmations is None:
            raise Exception('confirmations not set')
        result = list()
        for x in get_address_unspent(self.get_p2pkh_address(self.compressed)):
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
            privkey: Optional[bytes] = None,
            privwif: Optional[str] = None,
            seed: Optional[TSeed] = None,
            compressed: Optional[bool] = None,
            nonce: Optional[TNonce] = None,
            new_addresses: Optional[int] = None):
        from yubtc.crypto import privwif2privkey
        if args:
            raise Exception('only kwargs allowed')
        self.privkeys = None
        self._seed = None
        if privkey is not None:
            if compressed is None:
                raise Exception('compressed not set')
            self.compressed = compressed
            self.privkeys = [TPrivKey(privkey=privkey, compressed=compressed)]
        elif privwif is not None:
            privkey, compressed = privwif2privkey(privwif)
            self.compressed = compressed
            self.privkeys = [TPrivKey(privkey=privkey, compressed=compressed)]
        elif seed is not None:
            if not seed:
                raise Exception('seed cannot be empty')
            if compressed is None:
                raise Exception('compressed not set')
            if new_addresses is None:
                raise Exception('new_addresses not set')
            self.compressed = compressed
            self._seed = seed
            self.privkeys = []
            while True:
                privkey = TPrivKey(seed=seed, nonce=nonce, compressed=compressed)
                if privkey.is_unused():
                    break
                self.privkeys.append(privkey)
                nonce = nonce + 1
            for i in range(new_addresses):
                privkey = TPrivKey(seed=seed, nonce=nonce, compressed=compressed)
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
            scan: Optional[bool] = None) -> None:
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
            confirmations=confirmations, scan=scan)
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
        from yubtc.crypto import privkey2pubkey, pubkey2pubwif
        from yubtc.transaction import script2pkh, CIn
        vin = list()
        in_amount = 0
        signers = list()
        for tp, unspent in sources:
            pubkey = privkey2pubkey(tp.privkey)
            pubwif = pubkey2pubwif(pubkey=pubkey, compressed=self.compressed)
            pubhash = hash160(pubwif)
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
                signers.append((tp.privkey, pubwif))
        return vin, in_amount, signers

    def _scan_inputs(
            self,
            *args,
            target: Optional[TSatoshi] = None,
            confirmations: Optional[int] = None) -> list:
        """Walk forward from nonce 0 collecting addresses' UTXOs.

        Stops when either:
        - the running total of satoshis >= `target` (when target is not None), or
        - an address with no UTXOs is found (gap limit).

        Returns a list of (privkey, unspent) tuples in scan order.
        """
        if args:
            raise Exception('only kwargs allowed')
        if confirmations is None:
            raise Exception('confirmations not set')
        sources = []
        total = 0
        nonce = 0
        while True:
            pk = TPrivKey(seed=self._seed, nonce=nonce, compressed=self.compressed)
            unspent = pk.get_unspent(confirmations=confirmations)
            if not unspent:
                break
            sources.append((pk, unspent))
            for u in unspent:
                total += u['amount']
            if target is not None and total >= target:
                break
            nonce += 1
        return sources

    def make_transaction(
            self,
            *args,
            dst: Optional[TAddress] = None,
            amount: Optional[TBTC] = None,
            feekb: Optional[TSatoshi] = None,
            fee: Optional[TSatoshi] = None,
            confirmations: Optional[int] = None,
            scan: Optional[bool] = None) -> tuple:
        if args:
            raise Exception('only kwargs allowed')
        if dst is None:
            raise Exception('dst not set')
        from yubtc.crypto import privkey2pubkey, pubkey2pubwif, pubkey2addr, make_vout
        from yubtc.transaction import CTransaction
        if confirmations is None:
            raise Exception('confirmations not set')
        if feekb is None:
            raise Exception('feekb not set')
        if scan is None:
            raise Exception('scan not set')
        pubkey = privkey2pubkey(self.privkeys[0].privkey)
        src = pubkey2addr(pubkey=pubkey, compressed=self.compressed)
        pubwif = pubkey2pubwif(pubkey=pubkey, compressed=self.compressed)
        if scan:
            # When scanning, fetch UTXOs from every address starting at
            # nonce 0 until either the target amount is met or an unused
            # address is hit. Change still goes back to the primary address.
            if self._seed is None:
                raise Exception('scan not available without seed')
            sources = self._scan_inputs(
                target=amount, confirmations=confirmations)
            vin, in_amount, signers = self._make_vin_multi(sources=sources)
        else:
            unspent = self.privkeys[0].get_unspent(confirmations=confirmations)
            from yubtc.hash import hash160
            pubhash = hash160(pubwif)
            vin, in_amount = self._make_vin(pubhash=pubhash, unspent=unspent)
            signers = [(self.privkeys[0].privkey, pubwif)]
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
