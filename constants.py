# constants.py
# Fixed parameters for the mCrypton-64 block cipher
# as used in the 5-round boomeyong attack.

# ---------------------
# S-boxes and inverses
# ---------------------

# S0 and S1 as defined in the mCrypton specification.
# S2 = S0^{-1}, S3 = S1^{-1}.
S0 = [
    4, 10, 9, 2, 13, 8, 0, 14,
    6, 11, 1, 12, 7, 15, 5, 3
]

S1 = [
    14, 11, 4, 12, 6, 13, 15, 10,
    2, 3, 8, 1, 0, 7, 5, 9
]

# Compute the inverses (S0^{-1} and S1^{-1}) by finding indices.
def invert_sbox(sbox):
    inv = [0] * 16
    for i, v in enumerate(sbox):
        inv[v] = i
    return inv

invS0 = invert_sbox(S0)
invS1 = invert_sbox(S1)

# The four S-boxes used in the cipher:
# S0, S1, S2 = invS0, S3 = invS1
S_BOXES = [S0, S1, invS0, invS1]

# Their inverses in the same order.
INV_S_BOXES = [invS0, invS1, S0, S1]   # because inv(invS0)=S0, etc.

# ---------------------
# Mask nibbles for the π permutation
# ---------------------
# m0 = 1110₂ = 0xE, m1 = 1101₂ = 0xD,
# m2 = 1011₂ = 0xB, m3 = 0111₂ = 0x7
MASKS = (0xE, 0xD, 0xB, 0x7)

# ---------------------
# Round constants for the 64‑bit key schedule
# ---------------------
# 13 constants C[0] … C[12] (used in encryption and decryption key schedules)
ROUND_CONSTANTS = [
    0x1, 0x2, 0x4, 0x8, 0x3, 0x6, 0xC,
    0xB, 0x5, 0xA, 0x7, 0xE, 0xF
]

# ---------------------
# Multiplication constants for key schedule (M0 … M3)
# ---------------------
# These are used in the step T_i ← T · M_i (i = 0..3).
# In mCrypton, M0 = 1, M1 = 2, M2 = 4, M3 = 8 (in GF(2⁴)).
MUL_CONSTANTS = (1, 2, 4, 8)

# ---------------------
# GF(2⁴) irreducible polynomial for multiplication
# ---------------------
# mCrypton uses the polynomial x⁴ + x + 1 (0x13).
GF16_POLY = 0x13

# ---------------------
# (Optional) φ permutations for decryption key schedule
# ---------------------
# These are not strictly needed for the 5‑round attack,
# but they are kept here for completeness.
# φ_i are 4‑bit permutations (nibble → nibble) as defined in the cipher.
# For mCrypton they are:
#   φ_0 = identity
#   φ_1(x) = left rotate by 1
#   φ_2(x) = left rotate by 2
#   φ_3(x) = left rotate by 3
def rotl4(x, n):
    n &= 3
    return ((x << n) | (x >> (4 - n))) & 0xF

PHI = [
    lambda x: x & 0xF,                     # φ0
    lambda x: rotl4(x, 1),                # φ1
    lambda x: rotl4(x, 2),                # φ2
    lambda x: rotl4(x, 3)                 # φ3
]

# Also provide the inverse of φ (right rotations) if needed.
def rotr4(x, n):
    n &= 3
    return ((x >> n) | (x << (4 - n))) & 0xF

PHI_INV = [
    lambda x: x & 0xF,
    lambda x: rotr4(x, 1),
    lambda x: rotr4(x, 2),
    lambda x: rotr4(x, 3)
]
