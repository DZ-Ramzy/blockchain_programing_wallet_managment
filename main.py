import hashlib
import os
import secrets

ENTROPY_BITS = 128
WORDLIST_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "english.txt")

VALID_WORD_COUNTS = (12, 15, 18, 21, 24)


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
    entropy_bytes = secrets.token_bytes(ENTROPY_BITS // 8)

    show_entropy(entropy_bytes)
    print()
    show_lots(entropy_bytes)
    print()
    print("mnemonic :", " ".join(entropy_to_mnemonic(entropy_bytes)))


def import_phrase():
    words = input("mnemonic > ").lower().split()

    try:
        entropy_bytes = mnemonic_to_entropy(words)
    except ValueError as error:
        print("error :", error)
        return

    print(f"valid mnemonic ({len(words)} words)")
    show_entropy(entropy_bytes)


def main():
    while True:
        print("1) Generate")
        print("2) Import")
        print("q) Quit")
        choice = input("> ")

        if choice == "1":
            generate()
        elif choice == "2":
            import_phrase()
        elif choice == "q":
            break
        else:
            print("Invalid choice")


main()
