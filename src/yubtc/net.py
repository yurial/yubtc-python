"""Network calls used by the wallet.

Two read-only paths (UTXO lookup and address stats) hit blockchain.info via
`requests`. The third, `sendTx`, is a stub: the wallet prints the raw tx
hex so the user can paste it into a block explorer to broadcast.
"""
from yubtc.fwd import TAddress, DEFAULT_TIMEOUT_HTTP


def get_address_unspent(address: TAddress) -> list:
    import requests
    from json.decoder import JSONDecodeError
    address = address.decode('ascii')
    try:
        url = 'https://blockchain.info/unspent?active={address}'.format(address=address)
        return requests.get(url, timeout=DEFAULT_TIMEOUT_HTTP).json()['unspent_outputs']
    except JSONDecodeError:
        return []


def get_address_info(address: TAddress) -> dict:
    import requests
    from json.decoder import JSONDecodeError
    address = address.decode('ascii')
    try:
        url = 'https://blockchain.info/balance?active={address}'.format(address=address)
        response = requests.get(url, timeout=DEFAULT_TIMEOUT_HTTP)
        return response.json()[address]
    except JSONDecodeError:
        return {'total_received': 0}


def sendTx(rawtxdata: bytes) -> None:
    """Stub for broadcasting a transaction to the Bitcoin network.

    The actual broadcast endpoint is not wired up here. The wallet's
    `send` command already prints the rawtx hex when this is not called,
    which is enough for now: paste the hex into a block explorer to
    broadcast.
    """
    raise NotImplementedError(
        'sendTx is a stub. Broadcast the raw tx via a block explorer.'
    )
