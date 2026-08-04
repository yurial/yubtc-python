def base58CheckEncode(payload):
    from base58 import b58encode
    from yubtc.hash import sha256
    # b58encode preserves leading zero bytes as '1' characters, so no
    # manual prefix counting is needed.
    checksum = sha256(sha256(payload))[0:4]
    return b58encode(payload + checksum)


def base58CheckDecode(payload):
    from base58 import b58decode
    from yubtc.hash import sha256
    # b58decode maps each leading '1' to a 0x00 byte; the last 4 bytes
    # are the checksum from the encoder.
    decoded = b58decode(payload)
    checksum = decoded[-4:]
    payload = decoded[:-4]
    if sha256(sha256(payload))[:4] != checksum:
        raise Exception('ivalid checksum')
    return payload
