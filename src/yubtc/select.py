from yubtc.fwd import TSatoshi


def default_selection(sources, target: TSatoshi = None) -> set:
    """Greedy default: smallest set from earliest addresses that meets target.

    `sources`: list of (TPrivKey, unspent_list) tuples in scan order.
    `target`: total satoshi amount needed, or None to drain all.

    Returns a set of (nonce, out_n) tuples marking the selected UTXOs.
    Sources and UTXOs are walked in scan/insertion order, so the selection
    is deterministic and biased toward the earliest addresses.
    """
    selected = set()
    if not sources:
        return selected
    total = 0
    for pk, unspent in sources:
        if target is not None and total >= target:
            break
        for u in unspent:
            selected.add((pk.nonce, u['out_n']))
            total += u['amount']
            if target is not None and total >= target:
                break
    return selected


def selection_to_sources(selected_flat) -> list:
    """Group a flat list of (pk, utxo) by pk, preserving original order.

    Returns: list of (pk, [utxo]) matching the order of first appearance.
    """
    pk_to_utxos = {}
    pk_order = []
    for pk, u in selected_flat:
        if id(pk) not in pk_to_utxos:
            pk_to_utxos[id(pk)] = []
            pk_order.append(pk)
        pk_to_utxos[id(pk)].append(u)
    return [(pk, pk_to_utxos[id(pk)]) for pk in pk_order]
