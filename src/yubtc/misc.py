from yubtc.fwd import TAddress, TSatoshi, TBTC, DEFAULT_TIMEOUT_HTTP

raw_input = input

# Returns byte string value, not hex string


def varint(n: int) -> bytes:
    from struct import pack
    if n < 0xfd:
        return pack('<B', n)
    elif n < 0xffff:
        return pack('<cH', b'\xfd', n)
    elif n < 0xffffffff:
        return pack('<cL', b'\xfe', n)
    else:
        return pack('<cQ', b'\xff', n)

# Takes and returns byte string value, not hex string


def varstr(s: bytes) -> bytes:
    return varint(len(s)) + s


def yesno(question: str) -> bool:
    while True:
        choice = raw_input(question).lower()
        if choice[:1] == 'y':
            return True
        elif choice[:1] == 'n':
            return False
        else:
            print("Please respond with 'Yes' or 'No'\n")


def satoshi2btc(satoshi: TSatoshi) -> TBTC:
    return TBTC(satoshi) * TBTC((0, (1,), -8))


def btc2satoshi(btc: TBTC) -> TSatoshi:
    return TSatoshi(btc * TBTC((0, (1,), 8)))


def unpack_address(address: TAddress) -> tuple:
    from yubtc.base58check import base58CheckDecode
    data = base58CheckDecode(address)
    prefix = data[0]
    dsthash = data[1:]
    return prefix, dsthash


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
