# TD02 — Wallet management (BIP 39 / BIP 32)

Command-line Python program that generates and imports a mnemonic phrase (BIP 39),
without any Bitcoin library.

BIP 32 key derivation is not implemented yet.

## Running the program

Requirements: Python 3.9+, no external dependency.

```bash
python3 main.py
```

`english.txt` is the official BIP 39 English wordlist (2048 words), committed so
the program runs offline.

## Report

### Step 1 — Interactive program
Looping menu: generate a mnemonic, import a mnemonic, quit.

### Step 2 — Safe seed
The entropy comes from `secrets.token_bytes(16)` — 128 random bits, read as a
128-bit integer.
`secrets` draws from the OS CSPRNG, so the output cannot be replayed.
`random` would not do: its Mersenne Twister state can be recovered from its own
output, which would let anyone rebuild the wallet.

### Step 3 — Representations and lots of 11 bits
The entropy is shown in binary, bytes and hex.
128 is not divisible by 11, so BIP 39 appends a checksum of `ENT / 32 = 4` bits,
taken from the start of `SHA-256(entropy)`. That gives `128 + 4 = 132 = 12 x 11`
bits, so exactly 12 lots.

### Step 4 — Mnemonic
Each lot of 11 bits is an index between 0 and 2047, read as a word in
`english.txt`. The 12 words are the mnemonic phrase.

### Step 5 — Import
`mnemonic_to_entropy` does the reverse: words to indexes, indexes to bits, then
the bits are cut back into entropy and checksum (`33` bits per `32` bits of
entropy, so any length among 12/15/18/21/24 words works).
Three cases are rejected: a wrong number of words, a word absent from the list
(the offending word is named), and a checksum that does not match the entropy.

### Step 6 — Verification
Checked against the official BIP 39 test vectors:

| entropy | mnemonic |
| --- | --- |
| `00000000000000000000000000000000` | `abandon` x11 + `about` |
| `ffffffffffffffffffffffffffffffff` | `zoo` x11 + `wrong` |
| `80808080808080808080808080808080` | `letter advice cage absurd amount doctor acoustic avoid letter advice cage above` |

To confirm on <https://iancoleman.io/bip39/>: paste the hex printed by the program
into the *Entropy* field (type Hex, leave the passphrase empty); the mnemonic shown
by the site must be the same as ours.
