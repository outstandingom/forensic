import random, time, sys

CIPHER = bytes.fromhex("00000000")  # <-- hex ciphertext
APPROX = int(time.time())          # <-- epoch when it was generated
WID