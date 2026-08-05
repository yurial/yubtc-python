from yubtc.select import default_selection, selection_to_sources


def _fake_pk(nonce):
    """Build a fake TPrivKey for tests; only `.nonce` is read by selection."""
    class FakePk:
        pass
    p = FakePk()
    p.nonce = nonce
    return p


def test_default_selection_drains_when_target_is_none():
    """target=None selects every UTXO (drain mode)."""
    sources = [
        (_fake_pk(0), [{'out_n': 0, 'amount': 1000}, {'out_n': 1, 'amount': 2000}]),
        (_fake_pk(1), [{'out_n': 0, 'amount': 3000}]),
    ]
    selected = default_selection(sources, target=None)
    assert selected == {(0, 0), (0, 1), (1, 0)}


def test_default_selection_picks_minimum_from_earliest_addresses():
    """Greedy: smallest set from earliest addresses that meets target."""
    sources = [
        (_fake_pk(0), [{'out_n': 0, 'amount': 1000}]),
        (_fake_pk(1), [{'out_n': 0, 'amount': 4000}]),
        (_fake_pk(2), [{'out_n': 0, 'amount': 1000}]),
    ]
    # target=4500: needs nonce 0 (1k) + nonce 1 (4k) = 5k
    selected = default_selection(sources, target=4500)
    assert selected == {(0, 0), (1, 0)}


def test_default_selection_target_met_by_single_input():
    """If a single input covers target, that's all that's selected."""
    sources = [
        (_fake_pk(0), [{'out_n': 0, 'amount': 5000}]),
        (_fake_pk(1), [{'out_n': 0, 'amount': 1000}]),
    ]
    selected = default_selection(sources, target=4000)
    assert selected == {(0, 0)}


def test_default_selection_target_unmet_takes_everything():
    """If target is unreachable, all UTXOs are selected (insufficient)."""
    sources = [
        (_fake_pk(0), [{'out_n': 0, 'amount': 1000}]),
        (_fake_pk(1), [{'out_n': 0, 'amount': 1000}]),
    ]
    selected = default_selection(sources, target=10_000)
    assert selected == {(0, 0), (1, 0)}


def test_default_selection_empty_sources():
    """Empty sources produce an empty selection regardless of target."""
    assert default_selection([], target=1000) == set()
    assert default_selection([], target=None) == set()


def test_default_selection_walks_utxos_within_address_in_order():
    """Within an address, UTXOs are walked in their list order."""
    sources = [
        (_fake_pk(0), [
            {'out_n': 0, 'amount': 100},
            {'out_n': 1, 'amount': 5000},
            {'out_n': 2, 'amount': 100},
        ]),
    ]
    # target=5000: nonce 0 alone is enough but only if we walk into out_n 1.
    selected = default_selection(sources, target=4500)
    assert selected == {(0, 0), (0, 1)}


def test_selection_to_sources_groups_by_pk_preserving_order():
    """selected_flat -> grouped sources, first appearance wins for order."""
    pk_a = _fake_pk(0)
    pk_b = _fake_pk(1)
    # Same pk object (pk_a) appears twice for nonce 0; pk_b appears once.
    u0 = {'out_n': 0, 'amount': 100}
    u1 = {'out_n': 1, 'amount': 200}
    u2 = {'out_n': 0, 'amount': 300}
    flat = [(pk_a, u0), (pk_b, u2), (pk_a, u1)]
    grouped = selection_to_sources(flat)
    assert len(grouped) == 2
    p0, utxos0 = grouped[0]
    p1, utxos1 = grouped[1]
    # First-seen order: pk_a (nonce 0) then pk_b (nonce 1).
    assert p0 is pk_a
    assert p1 is pk_b
    # pk_a's UTXOs come in their original flat order: [u0, u1].
    assert utxos0 == [u0, u1]
    assert utxos1 == [u2]


def test_selection_to_sources_empty_input():
    """Empty flat list -> empty grouped list."""
    assert selection_to_sources([]) == []
