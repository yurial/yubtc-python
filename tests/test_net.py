"""Tests for net.py: sendTx is a stub.

The real broadcast endpoint is not wired up. The test pins the current
behaviour: raising NotImplementedError -- so a future implementation has
to actively change this test rather than silently extending the stub.
"""
import pytest


def test_sendTx_is_a_stub():
    """sendTx raises NotImplementedError on any call."""
    from yubtc.net import sendTx
    with pytest.raises(NotImplementedError):
        sendTx(b'\x00' * 100)


def test_sendTx_does_not_touch_the_network():
    """The stub must not import or use requests -- it has no network call."""
    # If this import succeeded before the test, the next assertion is meaningful.
    import yubtc.net as net
    assert not hasattr(net, 'requests')


def test_sendTx_message_mentions_block_explorer():
    """The error message tells the user how to actually broadcast."""
    from yubtc.net import sendTx
    with pytest.raises(NotImplementedError) as info:
        sendTx(b'\x00')
    assert 'block explorer' in str(info.value).lower()
