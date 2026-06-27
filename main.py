# main.py
#
# Demonstration of the 5-round Boomeyong key recovery attack
# on mCrypton.
#

import random

from mcrypton import (
    encrypt,
    decrypt,
    key_schedule_enc,
    round_enc,
)

from utils import (
    state_to_int,
    int_to_state,
)

from distinguisher import find_quartet
from key_recovery import (
    recover_round_key,
    exhaustive_search,
)


# ------------------------------------------------------------
# Collect quartets
# ------------------------------------------------------------

def collect_quartets(
    oracle_enc,
    oracle_dec,
    num_quartets=4,
    structure_size=4096,
    max_attempts=50,
):
    """
    Collect valid Boomeyong quartets.
    """

    quartets = []

    attempts = 0

    while (
        len(quartets) < num_quartets
        and attempts < max_attempts
    ):

        attempts += 1

        print(
            f"Searching structure "
            f"{attempts}..."
        )

        q = find_quartet(
            oracle_enc,
            oracle_dec,
            structure_size,
        )

        if q is None:

            continue

        quartets.append(q)

        print(
            f"Collected quartet "
            f"{len(quartets)}/{num_quartets}"
        )

    return quartets


# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

def main():

    random.seed(0xDEADBEEF)

    master_key = random.getrandbits(64)

    print(
        f"Master key : "
        f"{master_key:016X}"
    )

    #
    # Round keys
    #
    round_keys = key_schedule_enc(master_key)

    actual_last_round_key = round_keys[4]

    print("\nActual last-round key:")

    for row in actual_last_round_key:

        print(
            " ".join(
                f"{x:X}" for x in row
            )
        )

    #
    # Encryption oracle
    #
    def oracle_enc(state):

        pt = state_to_int(state)

        ct = encrypt(
            pt,
            master_key,
            rounds=5,
            final_phi=False,
        )

        return int_to_state(ct)

    #
    # Decryption oracle
    #
    def oracle_dec(state):

        ct = state_to_int(state)

        pt = decrypt(
            ct,
            master_key,
            rounds=5,
            final_phi=False,
        )

        return int_to_state(pt)

    #
    # --------------------------------------------------------
    # Distinguishing phase
    # --------------------------------------------------------
    #
    print("\nCollecting quartets...\n")

    quartets = collect_quartets(
        oracle_enc,
        oracle_dec,
        num_quartets=4,
        structure_size=4096,
    )

    if len(quartets) == 0:

        print("No valid quartets found.")

        return

    print()

    print(
        f"Collected "
        f"{len(quartets)} quartets."
    )

    #
    # --------------------------------------------------------
    # Key recovery
    # --------------------------------------------------------
    #
    print("\nRecovering last-round key...\n")

    candidates = recover_round_key(quartets)

    print()

    print(
        f"Recovered "
        f"{len(candidates)} "
        f"candidate keys."
    )

    if len(candidates) == 0:

        print("Recovery failed.")

        return

    #
    # --------------------------------------------------------
    # Experimental verification
    #
    # This part is NOT part of the attack.
    # It is only used to verify that one of the
    # recovered candidates is the correct one.
    # --------------------------------------------------------
    #

    known_plain = quartets[0][0]

    state = known_plain

    for r in range(4):

        state = round_enc(
            state,
            round_keys[r],
        )

    intermediate_4r = state

    known_cipher = oracle_enc(
        known_plain
    )

    recovered = exhaustive_search(

        candidates,

        known_plain,

        known_cipher,

        intermediate_4r,

    )

    print()

    if recovered is None:

        print(
            "Correct last-round key "
            "was not recovered."
        )

        return

    print(
        "Recovered last-round key:\n"
    )

    for row in recovered:

        print(
            " ".join(
                f"{x:X}" for x in row
            )
        )

    print()

    print(
        "Verification successful."
    )


# ------------------------------------------------------------

if __name__ == "__main__":

    main()
