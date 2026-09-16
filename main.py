import secrets

ENTROPY_BITS = 128


def import_phrase():
    print("TODO: import")


def generate():
    entropy = secrets.randbits(ENTROPY_BITS)

    entropy_bits = format(entropy, f"0{ENTROPY_BITS}b")
    entropy_bytes = entropy.to_bytes(ENTROPY_BITS // 8, "big")
    entropy_hex = format(entropy, f"0{ENTROPY_BITS // 4}x")

    print("binary :", entropy_bits)
    print("bytes  :", entropy_bytes)
    print("hex    :", entropy_hex)



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
