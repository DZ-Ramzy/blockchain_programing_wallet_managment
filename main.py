import hashlib
import os
import secrets

import bip32

ENTROPY_BITS = 128
WORDLIST_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "english.txt")

VALID_WORD_COUNTS = (12, 15, 18, 21, 24)

MNEMONIC = []


def load_wordlist():
    with open(WORDLIST_FILE, encoding="utf-8") as f:
        words = f.read().split()

    return words


WORDLIST = load_wordlist()
WORD_INDEX = {word: i for i, word in enumerate(WORDLIST)}


def checksum_bits(entropy_bytes):
    digest = hashlib.sha256(entropy_bytes).digest()
    digest_bits = "".join(format(b, "08b") for b in digest)
    return digest_bits[: len(entropy_bytes) * 8 // 32]


def split_11(bits):
    return [bits[i : i + 11] for i in range(0, len(bits), 11)]


def entropy_to_mnemonic(entropy_bytes):
    entropy_bits = "".join(format(b, "08b") for b in entropy_bytes)
    full_bits = entropy_bits + checksum_bits(entropy_bytes)
    return [WORDLIST[int(lot, 2)] for lot in split_11(full_bits)]


def mnemonic_to_entropy(words):
    if len(words) not in VALID_WORD_COUNTS:
        raise ValueError(
            f"a mnemonic holds {VALID_WORD_COUNTS} words, got {len(words)}"
        )

    for word in words:
        if word not in WORD_INDEX:
            raise ValueError(f"'{word}' is not in the BIP 39 list")

    full_bits = "".join(format(WORD_INDEX[word], "011b") for word in words)

    entropy_length = len(full_bits) * 32 // 33
    entropy_bits = full_bits[:entropy_length]
    given_checksum = full_bits[entropy_length:]

    entropy_bytes = int(entropy_bits, 2).to_bytes(entropy_length // 8, "big")

    if checksum_bits(entropy_bytes) != given_checksum:
        raise ValueError("invalid checksum : the mnemonic is corrupted or mistyped")

    return entropy_bytes


def show_entropy(entropy_bytes):
    entropy = int.from_bytes(entropy_bytes, "big")
    bits = len(entropy_bytes) * 8

    print("binary :", format(entropy, f"0{bits}b"))
    print("bytes  :", entropy_bytes)
    print("hex    :", format(entropy, f"0{bits // 4}x"))


def show_lots(entropy_bytes):
    entropy_bits = "".join(format(b, "08b") for b in entropy_bytes)
    check = checksum_bits(entropy_bytes)

    print(f"checksum ({len(check)} bits) :", check)
    print("lots of 11 bits :")

    for i, lot in enumerate(split_11(entropy_bits + check), start=1):
        index = int(lot, 2)
        print(f"  {i:2d}. {lot}  ->  {index:4d}  ->  {WORDLIST[index]}")


def generate():
    global MNEMONIC

    entropy_bytes = secrets.token_bytes(ENTROPY_BITS // 8)
    MNEMONIC = entropy_to_mnemonic(entropy_bytes)

    show_entropy(entropy_bytes)
    print()
    show_lots(entropy_bytes)
    print()
    print("mnemonic :", " ".join(MNEMONIC))


def import_phrase():
    global MNEMONIC

    words = input("mnemonic > ").lower().split()

    try:
        entropy_bytes = mnemonic_to_entropy(words)
    except ValueError as error:
        print("error :", error)
        return

    MNEMONIC = words
    print(f"valid mnemonic ({len(words)} words)")
    show_entropy(entropy_bytes)


def current_seed():
    if not MNEMONIC:
        print("generate or import a mnemonic first")
        return None

    return bip32.seed_from_mnemonic(MNEMONIC)


def ask_int(label):
    try:
        return int(input(f"{label} > "))
    except ValueError:
        print("error : not a number")
        return None


def show_key(key, path):
    print("path        :", path)
    print("depth       :", key.depth)
    print("index       :", key.child_number)
    print("private key :", key.key.hex())
    print("chain code  :", key.chain_code.hex())
    print("public key  :", key.public_key().hex())
    print("xprv        :", key.xprv())
    print("xpub        :", key.xpub())


def derive_and_show(path):
    seed = current_seed()
    if seed is None:
        return

    try:
        key = bip32.derive(seed, path)
    except ValueError as error:
        print("error :", error)
        return

    show_key(key, path)


def master():
    seed = current_seed()
    if seed is None:
        return

    print("bip39 seed  :", seed.hex())
    show_key(bip32.master_key(seed), "m")


def master_public():
    seed = current_seed()
    if seed is None:
        return

    key = bip32.master_key(seed)
    print("public key  :", key.public_key().hex())
    print("xpub        :", key.xpub())


def child():
    derive_and_show("m/0")


def child_at_index():
    index = ask_int("index N")
    if index is not None:
        derive_and_show(f"m/{index}")


def child_at_index_and_level():
    level = ask_int("level M")
    if level is None:
        return

    index = ask_int("index N")
    if index is None:
        return

    if level < 1:
        print("error : level must be at least 1")
        return

    derive_and_show("m" + "/0" * (level - 1) + f"/{index}")


def custom_path():
    derive_and_show(input("path (ex: m/44'/0'/0'/0/0) > "))


def main():
    while True:
        print("1) Generate mnemonic")
        print("2) Import mnemonic")
        print("3) Master private key and chain code")
        print("4) Master public key")
        print("5) Child key (m/0)")
        print("6) Child key at index N")
        print("7) Child key at index N, level M")
        print("8) Custom derivation path")
        print("q) Quit")
        choice = input("> ")

        if choice == "1":
            generate()
        elif choice == "2":
            import_phrase()
        elif choice == "3":
            master()
        elif choice == "4":
            master_public()
        elif choice == "5":
            child()
        elif choice == "6":
            child_at_index()
        elif choice == "7":
            child_at_index_and_level()
        elif choice == "8":
            custom_path()
        elif choice == "q":
            break
        else:
            print("Invalid choice")


main()
