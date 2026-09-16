def generate():
    print("TODO: generate a phrase")

def import_phrase():
    print("TODO: import")

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
