# distinguisher.py
#
# 5-round Boomeyong distinguisher for mCrypton.
#
# This module is responsible ONLY for finding valid boomeyong quartets.
# No key-recovery conditions are checked here.
#

from utils import (
    state_diff,
    nu_rows,
    swap_words,
    generate_plaintext_structure,
)

# One active plaintext row
EXPECTED_ZDP = (0, 1, 1, 1)

# Swap only row 3
SWAP_VECTOR = (1, 1, 1, 0)


def find_quartet(oracle_enc, oracle_dec, n=4096):
    """
    Search one plaintext structure for a valid boomeyong quartet.

    Returns

        (
            p1,p2,
            p1p,p2p,
            c1,c2,
            c1p,c2p
        )

    or None.
    """

    plaintexts = generate_plaintext_structure(n)

    ciphertexts = [oracle_enc(p) for p in plaintexts]

    for i in range(n):

        p1 = plaintexts[i]
        c1 = ciphertexts[i]

        for j in range(i + 1, n):

            p2 = plaintexts[j]
            c2 = ciphertexts[j]

            #
            # Input difference:
            # exactly one active row
            #
            if nu_rows(state_diff(p1, p2)) != EXPECTED_ZDP:
                continue

            #
            # Perform yoyo row swapping
            #
            c1p, c2p = swap_words(c1, c2, SWAP_VECTOR)

            #
            # Decrypt swapped ciphertexts
            #
            p1p = oracle_dec(c1p)
            p2p = oracle_dec(c2p)

            #
            # Check boomeyong property
            #
            if nu_rows(state_diff(p1p, p2p)) != EXPECTED_ZDP:
                continue

            return (
                p1,
                p2,
                p1p,
                p2p,
                c1,
                c2,
                c1p,
                c2p,
            )

    return None


def collect_quartets(
    oracle_enc,
    oracle_dec,
    number=8,
    structure_size=4096,
):
    """
    Collect multiple independent quartets.

    Returns
        list of quartets.
    """

    quartets = []

    while len(quartets) < number:

        q = find_quartet(
            oracle_enc,
            oracle_dec,
            structure_size,
        )

        if q is None:
            break

        quartets.append(q)

    return quartets


def distinguish(
    oracle_enc,
    oracle_dec,
    n=4096,
):
    """
    Return True if a boomeyong quartet exists.
    """

    return find_quartet(
        oracle_enc,
        oracle_dec,
        n,
    ) is not None
