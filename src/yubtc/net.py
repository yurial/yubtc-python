"""Network calls used by the wallet.

`get_address_unspent` and `get_address_info` are read-only GETs to
blockchain.info. `sendTx` POSTs a signed raw transaction to
blockchain.info/pushtx; the response is form-encoded text and the
wallet on success is silent.
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
    """Broadcast a signed raw transaction via blockchain.info/pushtx.

    The endpoint accepts the raw tx hex as a form-encoded `tx` field and
    returns a 200 with the body "Transaction Submitted" on success. Any
    non-2xx response is treated as a failure (the wallet has already
    printed the tx id, so surfacing the error is the right move).
    """
    import requests
    url = 'https://blockchain.info/pushtx'
    response = requests.post(url, data={'tx': rawtxdata.hex()}, timeout=DEFAULT_TIMEOUT_HTTP)
    if not response.ok:
        raise Exception(
            'broadcast failed: status={status} body={body}'.format(
                status=response.status_code, body=response.text))
