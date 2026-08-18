"""Fee-loop picker tests (mirror of the Rust port's picker tests).

Covers `_pick_best_fee_loop_candidate` in `yubtc.wallet`: the relay
floor from Bitcoin Core's DEFAULT_MIN_RELAY_TX_FEE, the
smallest-size/smallest-fee preference, and the sub-floor fallback.
The function is pure (no crypto imports), so these tests run without
coincurve installed.
"""
from yubtc.fwd import MIN_RELAY_TX_FEE
from yubtc.wallet import _pick_best_fee_loop_candidate


def _cand(fee):
    """Fake (vout_result, stx) pair -- only the fee is read."""
    return (fee, object(), object())


def test_min_relay_tx_fee_constant_is_bitcoin_core_default():
    """Relay floor is 1000 sat/kvB == 1 sat/vB (policy.h)."""
    assert MIN_RELAY_TX_FEE == 1000


def test_fee_loop_respects_min_relay_tx_fee():
    """A sub-floor candidate is dropped even when its size is smallest."""
    by_size = {
        100: [_cand(50)],   # >= needed (feekb 100 -> 10) but < floor (100)
        300: [_cand(300)],  # >= needed (30) and >= floor (300)
    }
    size, entry = _pick_best_fee_loop_candidate(by_size=by_size, feekb=100)
    assert size == 300
    assert entry[0] == 300


def test_fee_loop_picks_smallest_size():
    """Among rate-paying candidates the smallest size wins."""
    by_size = {
        200: [_cand(200)],
        220: [_cand(300)],
    }
    size, _ = _pick_best_fee_loop_candidate(by_size=by_size, feekb=1000)
    assert size == 200


def test_fee_loop_same_size_prefers_smaller_fee():
    """Tie-break at equal size: the later, cheaper entry replaces."""
    by_size = {
        200: [_cand(300), _cand(200)],
    }
    _, entry = _pick_best_fee_loop_candidate(by_size=by_size, feekb=1000)
    assert entry[0] == 200


def test_fee_loop_all_below_floor_falls_back_to_smallest_size():
    """Nobody pays the floor -> fallback: smallest size ever produced."""
    by_size = {
        400: [_cand(10)],
        500: [_cand(20)],
    }
    size, entry = _pick_best_fee_loop_candidate(by_size=by_size, feekb=100)
    assert size == 400
    assert entry[0] == 10
