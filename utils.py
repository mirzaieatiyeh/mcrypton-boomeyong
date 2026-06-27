# utils.py
# Helper functions for the mCrypton boomeyong attack.
# Provides utilities for state manipulation, Zero Difference Patterns (ZDP),
# row/column operations, and the word-swapping mechanism used in the attack.

# ---------- State utility functions ----------

def state_from_int(val):
    """Convert 64-bit integer to 4x4 nibble state (row-major)."""
    state = [[0] * 4 for _ in range(4)]
    for r in range(4):
        for c in range(4):
            state[r][c] = (val >> (60 - 4 * (r * 4 + c))) & 0xF
    return state

def state_to_int(state):
    """Convert 4x4 nibble state to 64-bit integer."""
    val = 0
    for r in range(4):
        for c in range(4):
            val = (val << 4) | (state[r][c] & 0xF)
    return val

def state_diff(s1, s2):
    """Element-wise XOR of two states."""
    return [[s1[r][c] ^ s2[r][c] for c in range(4)] for r in range(4)]

def is_zero_state(state):
    """Check if all nibbles are zero."""
    return all(state[r][c] == 0 for r in range(4) for c in range(4))

# ---------- Zero Difference Pattern (ZDP) for rows and columns ----------

def nu_rows(diff_state):
    """
    Compute the Zero Difference Pattern for rows.
    Returns a tuple of 4 bits (z0, z1, z2, z3) where z_i = 1 if row i is all-zero, else 0.
    """
    return tuple(1 if all(diff_state[r][c] == 0 for c in range(4)) else 0 for r in range(4))

def nu_cols(diff_state):
    """
    Compute the Zero Difference Pattern for columns.
    Returns a tuple of 4 bits (z0, z1, z2, z3) where z_i = 1 if column i is all-zero, else 0.
    """
    return tuple(1 if all(diff_state[r][c] == 0 for r in range(4)) else 0 for c in range(4))

def wt_nu(nu):
    """
    Hamming weight of a ZDP tuple.
    For a row ZDP, this gives the number of zero rows.
    But the paper's wt(ν) is the number of active rows = 4 - weight(zero rows).
    We'll provide both: weight_zero = sum(nu) (number of zero rows/cols).
    """
    return sum(nu)

def active_rows(nu):
    """Number of active rows = number of zeros in nu."""
    return 4 - sum(nu)

def active_cols(nu):
    """Number of active columns = number of zeros in nu."""
    return 4 - sum(nu)

# ---------- Row/Column subset extraction (Definitions 3 and 4) ----------

def get_rows(state, row_indices):
    """
    Extract rows from state as a list of row lists.
    row_indices: list/tuple of row indices.
    Returns a list of rows (each row is a list of 4 nibbles).
    """
    return [state[r][:] for r in row_indices]

def get_cols(state, col_indices):
    """
    Extract columns from state as a list of column lists.
    col_indices: list/tuple of column indices.
    Returns a list of columns (each column is a list of 4 nibbles).
    """
    return [[state[r][c] for r in range(4)] for c in col_indices]

def set_rows(state, row_indices, rows):
    """
    Set specific rows in the state.
    row_indices: list/tuple of row indices.
    rows: list of rows (each row is a list of 4 nibbles) of the same length.
    """
    for i, r in enumerate(row_indices):
        state[r] = rows[i][:]

def set_cols(state, col_indices, cols):
    """
    Set specific columns in the state.
    col_indices: list/tuple of column indices.
    cols: list of columns (each column is a list of 4 nibbles) of the same length.
    """
    for i, c in enumerate(col_indices):
        for r in range(4):
            state[r][c] = cols[i][r]

# ---------- τ_v operation (Definition 5) ----------

def tau_v(alpha, v):
    """
    Definition 5: Zero out rows i where v[i] == 1, keep rows where v[i] == 0.
    Input:
        alpha: a 4x4 state (difference, typically)
        v: a tuple/list of 4 bits (v[0..3])
    Returns:
        A new state with rows where v[i]==1 set to zero, others unchanged.
    """
    result = [[0]*4 for _ in range(4)]
    for r in range(4):
        if v[r] == 0:
            result[r] = alpha[r][:]
        else:
            result[r] = [0, 0, 0, 0]
    return result

def swap_words(c1, c2, v):
    """
    Implements the word swapping as used in the boomeyong attack.
    Given two ciphertexts c1, c2 (states) and a selection vector v,
    compute:
        c1' = c1 ⊕ τ_v(c1 ⊕ c2)
        c2' = c2 ⊕ τ_v(c2 ⊕ c1)   # same as c2 ⊕ τ_v(c1 ⊕ c2)
    Returns (c1_prime, c2_prime).
    """
    diff = state_diff(c1, c2)
    tau_diff = tau_v(diff, v)
    c1_prime = state_diff(c1, tau_diff)
    c2_prime = state_diff(c2, tau_diff)
    return c1_prime, c2_prime

# ---------- ZDP-based verification functions ----------

def zdp_eq_row(state1, state2):
    """
    Check if two states have the same row Zero Difference Pattern.
    i.e., nu_rows(state1) == nu_rows(state2).
    """
    return nu_rows(state1) == nu_rows(state2)

def zdp_eq_col(state1, state2):
    """
    Check if two states have the same column Zero Difference Pattern.
    """
    return nu_cols(state1) == nu_cols(state2)

def zdp_match_expected(diff_state, expected_nu):
    """
    Check if the ZDP of diff_state equals expected_nu (a tuple of 4 bits).
    """
    return nu_rows(diff_state) == expected_nu

# ---------- Utility for generating plaintext structures ----------

def generate_plaintext_structure(n=2**12, fixed_rows=(1,2,3), fixed_value=0):
    """
    Generate a set of plaintexts where all rows except row 0 are fixed to a constant.
    Row 0 varies with distinct 4-nibble values.
    Returns a list of n plaintext states (4x4 matrices).
    The standard structure uses n = 4096, row 0 varied, other rows zero.
    """
    plaintexts = []
    # Number of possible 16-bit values = 2^16 = 65536, we only need n <= 4096.
    # For reproducibility, we can iterate in order.
    # We'll produce the first n distinct values for row 0.
    for idx in range(n):
        # Generate a distinct 4-nibble combination for row 0.
        # Simple: use idx as a 16-bit value, split into nibbles.
        row0 = [(idx >> 12) & 0xF, (idx >> 8) & 0xF, (idx >> 4) & 0xF, idx & 0xF]
        state = [[fixed_value]*4 for _ in range(4)]
        state[0] = row0
        # Keep other rows fixed.
        # We can optionally set fixed rows to some constant (0 by default).
        plaintexts.append(state)
    return plaintexts

# ---------- Complement function for v (used in attack) ----------

def complement_v(v):
    """Return the bitwise complement of a 4-bit vector (tuple/list)."""
    return tuple(1 - b for b in v)

# ---------- Print/debug functions ----------

def print_state(state):
    """Print a 4x4 state in hex format."""
    for r in range(4):
        print(' '.join(f'{state[r][c]:x}' for c in range(4)))

def print_diff_zdp(state1, state2):
    """Print the ZDP of the difference between two states."""
    diff = state_diff(state1, state2)
    print("Row ZDP:", nu_rows(diff))
    print("Col ZDP:", nu_cols(diff))


# Alias for compatibility with code that expects int_to_state
int_to_state = state_from_int
