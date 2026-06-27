# key_recovery.py
#
# Key recovery for the 5-round Boomeyong attack on mCrypton.
#
# This module recovers the last-round key row-by-row from
# a collection of valid Boomeyong quartets.
#

from itertools import product

from mcrypton import gamma_inv, tau, pi_inv


# ------------------------------------------------------------
# Utilities
# ------------------------------------------------------------

def xor_row(state, row_idx, row_key):
    """
    Apply σ^{-1} (AddRoundKey) to one row.

    Since σ is XOR, σ^{-1}=σ.
    """

    s = [r[:] for r in state]

    for c in range(4):
        s[row_idx][c] ^= row_key[c]

    return s


def state_diff(a, b):
    """
    XOR difference of two states.
    """

    return [
        [a[r][c] ^ b[r][c] for c in range(4)]
        for r in range(4)
    ]


def valid16(diff):
    """
    Check the 16-difference property.

    Valid output:

        * 0 0 0
        0 0 0 0
        0 0 0 0
        0 0 0 0

    where * may be any NONZERO nibble.
    """

    #
    # Active nibble
    #
    if diff[0][0] == 0:
        return False

    #
    # Every other nibble must be zero
    #
    for r in range(4):
        for c in range(4):

            if r == 0 and c == 0:
                continue

            if diff[r][c] != 0:
                return False

    return True


# ------------------------------------------------------------
# Precomputation
# ------------------------------------------------------------

def preprocess_quartets(quartets):
    """
    Compute γ^{-1}(C1) and γ^{-1}(C1')
    once for every quartet.
    """

    processed = []

    for q in quartets:

        c1 = q[4]
        c1p = q[6]

        processed.append(

            (
                gamma_inv(c1),
                gamma_inv(c1p)
            )

        )

    return processed


# ------------------------------------------------------------
# Recover one row
# ------------------------------------------------------------

def filter_row_candidates(quartets, row_idx):
    """
    Recover one row of the last-round key.

    Returns
        set(tuple)
    """

    processed = preprocess_quartets(quartets)

    candidates = set()

    #
    # 16-bit exhaustive search
    #
    for guess in range(1 << 16):

        row_key = [

            (guess >> 12) & 0xF,
            (guess >> 8) & 0xF,
            (guess >> 4) & 0xF,
            guess & 0xF,

        ]

        survives = True

        #
        # Every quartet must satisfy
        # the 16-difference property.
        #
        for z1, z2 in processed:

            #
            # σ^{-1}
            #
            s1 = xor_row(z1, row_idx, row_key)
            s2 = xor_row(z2, row_idx, row_key)

            #
            # τ^{-1}
            #
            s1 = tau(s1)
            s2 = tau(s2)

            #
            # π^{-1}
            #
            s1 = pi_inv(s1)
            s2 = pi_inv(s2)

            #
            # Difference AFTER inverse round
            #
            diff = state_diff(s1, s2)

            #
            # Check the 16 differences.
            #
            if not valid16(diff):

                survives = False
                break

        if survives:
            candidates.add(tuple(row_key))

    return candidates


# ------------------------------------------------------------
# Recover complete last-round key
# ------------------------------------------------------------

def recover_round_key(quartets):
    """
    Recover candidate last-round keys.

    Returns
        list of 4x4 matrices.
    """

    row_candidates = []

    for row in range(4):

        cand = filter_row_candidates(

            quartets,
            row

        )

        print(
            f"Row {row}: "
            f"{len(cand)} candidates"
        )

        row_candidates.append(sorted(cand))

    #
    # Cartesian product
    #
    keys = []

    for rows in product(*row_candidates):

        key = [

            list(rows[0]),
            list(rows[1]),
            list(rows[2]),
            list(rows[3])

        ]

        keys.append(key)

    return keys


# ------------------------------------------------------------
# Candidate verification
# ------------------------------------------------------------

def exhaustive_search(
    full_candidates,
    known_plain,
    known_cipher,
    intermediate_4r,
):
    """
    Keep the original verification routine.

    NOTE
    ----
    This is NOT part of the attack.
    It is only used to verify the recovered key
    during experiments.
    """

    from mcrypton import sigma

    for key in full_candidates:

        state = sigma(

            known_cipher,
            key

        )

        state = tau(state)
        state = pi_inv(state)
        state = gamma_inv(state)

        if state == intermediate_4r:
            return key

    return None
