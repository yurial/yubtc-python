from yubtc.util import NotNone, require_kwargs_only


def script2pkh(script: bytes) -> bytes:
    from yubtc.script import OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG
    if (len(script) != 25
        or script[0] != OP_DUP
        or script[1] != OP_HASH160
        or script[2] != 20
        or script[-2] != OP_EQUALVERIFY
            or script[-1] != OP_CHECKSIG):
        raise Exception('invalid script')
    return script[3:-2]


def toVarInt(value: int) -> bytes:
    """Pack `value` into varint bytes"""
    from struct import pack
    if value < 0:
        raise ValueError('toVarInt value must be non-negative')
    buf = b''
    while True:
        towrite = value & 0x7f
        value >>= 7
        if value:
            buf += pack(b'B', towrite | 0x80)
        else:
            buf += pack(b'B', towrite)
            break
    return buf


class CIn(object):
    @require_kwargs_only
    def __init__(self, txhash: bytes = NotNone, n: int = NotNone,
                 script: bytes = b'', sequence: int = NotNone):
        if len(txhash) != 32:
            raise Exception('txhash should be 32 bytes length')
        if n < 0:
            raise Exception('n should be non-negative')
        if n > 0xffffffff:
            raise Exception('n should be less or equal than 0xffffffff')
        if sequence < 0:
            raise Exception('sequence should be non-negative')
        if sequence > 0xffffffff:
            raise Exception('sequence should be less or equal than 0xffffffff')
        self.txhash = bytes(txhash)
        self.n = n
        self.script = script
        self.sequence = sequence

    def serialize(self) -> bytes:
        """
        32  hash                char[32]    The hash of the referenced transaction.
        4   index               uint32_t    The index of the specific output in the transaction.
                                             The first output is 0, etc.
        1+  script length       var_int     The length of the signature script
        ?   signature script    uchar[]     Computational Script for confirming transaction authorization
        4   sequence            uint32_t    Transaction version as defined by the sender. Intended
                                             for "replacement" of transactions when information is
                                             updated before inclusion into a block.
        """
        from struct import pack
        result = self.txhash
        result += pack(b"<L", self.n)
        result += toVarInt(len(self.script))
        result += self.script
        result += pack(b"<L", self.sequence)
        return result


class COut(object):
    @require_kwargs_only
    def __init__(self, amount: int = NotNone, script: bytes = b''):
        if amount < 0:
            raise Exception('amount should be non-negative')
        if amount > 0xffffffffffffffff:
            raise Exception('amount should be less or equal than 0xffffffffffffffff')
        self.amount = amount
        self.script = script

    def serialize(self) -> bytes:
        """
        8   value               int64_t     Transaction Value
        1+  pk_script length    var_int     Length of the pk_script
        ?   pk_script           uchar[]     Usually contains the public key as a Bitcoin script
                                             setting up conditions to claim this output.
        """
        from struct import pack
        result = pack(b"<Q", self.amount)
        result += toVarInt(len(self.script))
        result += self.script
        return result


class CTransaction(object):
    @require_kwargs_only
    def __init__(self, vin: list = NotNone, vout: list = NotNone,
                 locktime: int = NotNone):
        self.version = 2
        self.vin = vin
        self.vout = vout
        self.locktime = locktime

    def serialize(self) -> bytes:
        """
        4       version         int32_t     Transaction data format version (note, this is signed)
        0 or 2  flag            uint8_t[2]  Optional. If present, always 0001, and indicates
                                           the presence of witness data.
        1+      tx_in count     var_int     Number of Transaction inputs (never zero)
        41+     tx_in           tx_in[]     A list of 1 or more transaction inputs or sources for coins
        1+      tx_out count    var_int     Number of Transaction outputs
        9+      tx_out          tx_out[]    A list of 1 or more transaction outputs or destinations for coins
        0+      tx_witnesses    tx_wit[]    A list of witnesses, one for each input;
                                           omitted if flag is omitted above.
        4       lock_time       uint32_t    The block number or timestamp at which this transaction is unlocked.
        """
        from struct import pack
        result = pack(b"<l", self.version)
        result += toVarInt(len(self.vin))
        for i in self.vin:
            result += i.serialize()
        result += toVarInt(len(self.vout))
        for o in self.vout:
            result += o.serialize()
        result += pack(b"<L", self.locktime)
        return result

    @require_kwargs_only
    def sign(self, signers: list = NotNone) -> 'CTransaction':
        if len(signers) != len(self.vin):
            raise Exception('signers length must match vin length')
        from copy import deepcopy
        from yubtc.crypto import sign_data
        from yubtc.script import CScript
        from struct import pack
        tx = deepcopy(self)
        scripts = list()
        SIGHASH_ALL = 0x01
        for i in range(len(tx.vin)):
            k, w = signers[i]
            for z in range(len(tx.vin)):
                tx.vin[z].script = b''
            tx.vin[i] = deepcopy(self.vin[i])
            sigdata = tx.serialize() + pack(b'<L', SIGHASH_ALL)
            signature = sign_data(privkey=k, data=sigdata) + pack(b'<B', SIGHASH_ALL)
            scripts.append(CScript([signature, w]))
        for i in range(len(tx.vin)):
            tx.vin[i].script = scripts[i]
        return tx

    def id(self) -> bytes:
        from yubtc.hash import sha256
        return sha256(sha256(self.serialize()))[::-1]
