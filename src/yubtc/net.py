"""Broadcast a signed transaction to the Bitcoin network.

Stub: the real broadcast path (HTTP POST to a public block-explorer endpoint)
is not implemented here. The wallet prints the raw tx hex so the user can
submit it manually via a block explorer.
"""


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
