# TD02 — Wallet management (BIP 39 / BIP 32)

Command-line Python program that generates and imports a mnemonic phrase (BIP 39)
and derives the keys of an HD wallet (BIP 32), without any Bitcoin library.
secp256k1 and Base58Check are implemented by hand in `bip32.py`.

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

### Step 7 — Master private key and chain code
The mnemonic is stretched into a 64-byte seed with PBKDF2-HMAC-SHA512
(2048 iterations, salt `"mnemonic" + passphrase`). Careful: PBKDF2 takes the
*sentence of words*, not the entropy bytes.
Then `I = HMAC-SHA512(key="Bitcoin seed", msg=seed)`: `I[:32]` is the master
private key, `I[32:]` is the chain code.

### Step 8 — Master public key
`K = k * G` on secp256k1 (point addition, doubling and double-and-add written by
hand in `bip32.py`). The key is serialized compressed: `02` or `03` depending on
the parity of `y`, then `x` on 32 bytes.

### Step 9 — Child key
`CKDpriv` : `I = HMAC-SHA512(key=chain_code, msg=data)` where `data` is
`serP(K_parent) || index` for a normal child, and `0x00 || k_parent || index`
for a hardened one (`index >= 2^31`, noted `'`).
The child key is `(I[:32] + k_parent) mod n`, the new chain code is `I[32:]`.

### Step 10 — Child key at index N
Same function called with the chosen index: path `m/N`.

### Step 11 — Child key at index N at level M
`derive()` walks the path left to right, so level M means M calls to `CKDpriv`.
The menu builds `m/0/0/.../N` with M levels and prints the path and the depth.
Option 8 accepts any path, for instance `m/44'/0'/0'/0/0`.

### Verification of BIP 32
Checked against the four official BIP 32 test vectors (seed to xprv/xpub at
`m`, `m/0'`, `m/0'/1`, `m/0'/1/2'`, `m/0'/1/2'/2/1000000000`, …) and against the
24 BIP 39 vectors of `trezor/python-mnemonic`, which give the seed and the root
xprv for each mnemonic.

On <https://iancoleman.io/bip39/>: paste the mnemonic, leave the passphrase
empty, and compare with the **BIP32 Root Key** field. For a child key, use the
**BIP32** tab and type the path in *BIP32 Derivation Path*.
