# mcrypton.py
# mCrypton-64 block cipher implementation
# Supports 64-bit key, 5-round variant used in the boomeyong attack.

from constants import (
    S_BOXES, INV_S_BOXES, MASKS, GF16_POLY,
    MUL_CONSTANTS, ROUND_CONSTANTS
)

# ---------- Helper functions ----------

def gf16_mul(a, b):
    """Multiply two nibbles in GF(2^4) with irreducible polynomial x⁴+x+1."""
    res = 0
    for _ in range(4):
        if b & 1:
            res ^= a
        a <<= 1
        if a & 0x10:
            a ^= GF16_POLY
        b >>= 1
    return res & 0xF

def split_16bit_to_nibbles(w):
    """Split a 16-bit word into 4 nibbles (most significant first)."""
    return [(w >> 12) & 0xF, (w >> 8) & 0xF, (w >> 4) & 0xF, w & 0xF]

def combine_nibbles_to_16bit(nibs):
    """Combine 4 nibbles into a 16-bit word."""
    return (nibs[0] << 12) | (nibs[1] << 8) | (nibs[2] << 4) | nibs[3]

def state_to_int(state):
    """Convert a 4x4 nibble state to a 64-bit integer."""
    val = 0
    for r in range(4):
        for c in range(4):
            val = (val << 4) | (state[r][c] & 0xF)
    return val

def int_to_state(val):
    """Convert a 64-bit integer to a 4x4 nibble state (row-major)."""
    state = [[0]*4 for _ in range(4)]
    for r in range(4):
        for c in range(4):
            state[r][c] = (val >> (60 - 4*(r*4+c))) & 0xF
    return state

# ---------- Core cipher operations ----------

def gamma(state):
    """
    Non-linear substitution layer.
    state: 4x4 list of nibbles (rows then columns).
    Applies S-box S_r to row r, with cyclic shift of S-boxes.
    """
    new_state = [[0]*4 for _ in range(4)]
    for r in range(4):
        row = state[r]
        for c in range(4):
            sbox_idx = (r + c) % 4
            new_state[r][c] = S_BOXES[sbox_idx][row[c]]
    return new_state

def gamma_inv(state):
    """Inverse of gamma."""
    new_state = [[0]*4 for _ in range(4)]
    for r in range(4):
        row = state[r]
        for c in range(4):
            sbox_idx = (r + c) % 4
            new_state[r][c] = INV_S_BOXES[sbox_idx][row[c]]
    return new_state

# Precompute pi inverse tables for each column index
def _build_pi_inv_tables():
    """
    For each column index i (0..3), compute a mapping from
    16-bit input (4 nibbles concatenated) to 16-bit output (4 nibbles)
    for the inverse of the π permutation.
    """
    def pi_forward(i, a):
        # a: list of 4 nibbles (input column)
        b = [0]*4
        for j in range(4):
            val = 0
            for k in range(4):
                mask = MASKS[(i + j + k) % 4]
                val ^= (mask & a[k])
            b[j] = val
        return b

    tables = []
    for i in range(4):
        # Build forward lookup for all 16-bit inputs
        forward = {}
        for inp in range(1 << 16):
            a = split_16bit_to_nibbles(inp)
            b = pi_forward(i, a)
            out = combine_nibbles_to_16bit(b)
            forward[out] = inp  # output -> input mapping (inverse)
        tables.append(forward)
    return tables

PI_INV_TABLES = _build_pi_inv_tables()

def pi(state):
    """
    Bit permutation layer.
    Applies column-wise transformation using masks.
    """
    new_state = [[0]*4 for _ in range(4)]
    for c in range(4):  # each column
        col = [state[r][c] for r in range(4)]
        new_col = [0]*4
        for j in range(4):
            val = 0
            for k in range(4):
                mask = MASKS[(c + j + k) % 4]
                val ^= (mask & col[k])
            new_col[j] = val
        for r in range(4):
            new_state[r][c] = new_col[r]
    return new_state

def pi_inv(state):
    """
    Inverse of π using precomputed tables.
    """
    new_state = [[0]*4 for _ in range(4)]
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        inp = combine_nibbles_to_16bit(col)
        out_nibs = split_16bit_to_nibbles(PI_INV_TABLES[c][inp])
        for r in range(4):
            new_state[r][c] = out_nibs[r]
    return new_state

def tau(state):
    """Matrix transposition (self-inverse)."""
    return [list(row) for row in zip(*state)]

def sigma(state, round_key):
    """
    Key addition: XOR state with round_key (4x4 nibbles).
    """
    new_state = [[0]*4 for _ in range(4)]
    for r in range(4):
        for c in range(4):
            new_state[r][c] = state[r][c] ^ round_key[r][c]
    return new_state

def round_enc(state, round_key):
    """One encryption round: σ ∘ τ ∘ π ∘ γ applied as gamma, pi, tau, sigma."""
    state = gamma(state)
    state = pi(state)
    state = tau(state)
    state = sigma(state, round_key)
    return state

def round_dec(state, round_key):
    """One decryption round: γ^{-1} ∘ π^{-1} ∘ τ ∘ σ (applied as sigma, tau, pi_inv, gamma_inv)."""
    state = sigma(state, round_key)   # σ is its own inverse
    state = tau(state)
    state = pi_inv(state)
    state = gamma_inv(state)
    return state

# ---------- Key schedule for 64-bit key ----------

def key_schedule_enc(master_key):
    """
    Generate round keys for encryption.
    master_key: 64-bit integer.
    Returns a list of round keys (each a 4x4 nibble matrix) for rounds 0..12.
    """
    U = [(master_key >> (48 - 16*i)) & 0xFFFF for i in range(4)]
    round_keys = []
    for r in range(13):
        # T = S(U[0]) ⊕ C[r]
        u0_nibs = split_16bit_to_nibbles(U[0])
        s_u0 = [S_BOXES[0][nib] for nib in u0_nibs]   # apply S0 to each nibble
        T = combine_nibbles_to_16bit(s_u0)
        c = ROUND_CONSTANTS[r]
        T ^= (c | (c << 4) | (c << 8) | (c << 12))   # XOR constant to all nibbles

        T_nibs = split_16bit_to_nibbles(T)
        T_words = []
        for i in range(4):
            mul = MUL_CONSTANTS[i]
            mul_nibs = [gf16_mul(nib, mul) for nib in T_nibs]
            T_words.append(combine_nibbles_to_16bit(mul_nibs))

        # Round key words: (U[1]⊕T0, U[2]⊕T1, U[3]⊕T2, U[0]⊕T3)
        round_key_words = [
            U[1] ^ T_words[0],
            U[2] ^ T_words[1],
            U[3] ^ T_words[2],
            U[0] ^ T_words[3]
        ]

        # Convert to 4x4 matrix: each word is a column
        round_key_matrix = [[0]*4 for _ in range(4)]
        for col in range(4):
            col_nibs = split_16bit_to_nibbles(round_key_words[col])
            for r in range(4):
                round_key_matrix[r][col] = col_nibs[r]
        round_keys.append(round_key_matrix)

        # Update U: U ← (U[1], U[2], U[3], U[0] <<< 3)
        U = [U[1], U[2], U[3], ((U[0] << 3) | (U[0] >> 13)) & 0xFFFF]
    return round_keys

# ---------- Full cipher encryption/decryption ----------

def encrypt(plain, key, rounds=5, final_phi=False):
    """
    Encrypt a 64-bit plaintext block.
    plain: 64-bit integer.
    key: 64-bit integer (master key).
    rounds: number of rounds (default 5).
    final_phi: if True, apply output transformation φ = τ ∘ π ∘ τ after last round.
    Returns 64-bit ciphertext integer.
    """
    state = int_to_state(plain)
    round_keys = key_schedule_enc(key)[:rounds]
    for r in range(rounds):
        state = round_enc(state, round_keys[r])
    if final_phi:
        state = tau(state)
        state = pi(state)
        state = tau(state)
    return state_to_int(state)

def decrypt(cipher, key, rounds=5, final_phi=False):
    """
    Decrypt a 64-bit ciphertext block.
    """
    state = int_to_state(cipher)
    round_keys = key_schedule_enc(key)[:rounds]
    if final_phi:
        # φ^{-1} = τ ∘ π^{-1} ∘ τ
        state = tau(state)
        state = pi_inv(state)
        state = tau(state)
    for r in range(rounds-1, -1, -1):
        state = round_dec(state, round_keys[r])
    return state_to_int(state)

# ---------- Additional utility for getting a specific round key ----------

def get_round_key(master_key, round_number):
    """
    Return the round key for a given round (0-indexed) as a 4x4 nibble matrix.
    """
    keys = key_schedule_enc(master_key)
    if round_number < len(keys):
        return keys[round_number]
    else:
        raise ValueError("Round number out of range for 64-bit key schedule (max 12)")
