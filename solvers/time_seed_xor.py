import random
import time
import sys

# ============================================================================
# Time-seeded PRNG XOR solver
#
# The challenge encrypts with:
#     random.seed(int(time.time()))
#     key = <bytes generated from random>
#     ciphertext = plaintext XOR key
#
# Because the seed is just a Unix epoch timestamp, we brute-force a window
# around the approximate time the ciphertext was produced. For each seed we
# reproduce the *exact* random key and decrypt; we confirm a hit by looking
# for a known plaintext marker (flag{ / ctf{).
# ============================================================================

# --- CONFIG: adjust these to your challenge --------------------------------
CIPHERTEXT = bytes.fromhex(
    "deadbeef..."  # <-- replace with your challenge ciphertext (hex)
)

# Approximate time the server was run / cipher was generated (epoch seconds).
# If you don't know it, default to "now" and widen the window below.
APPROX_TS = int(time.time())

#