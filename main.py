def generer():
    print("A faire : générer une phrase")

def importer():
    print("A faire : importer")

def main():
    while True:
        print("1) Générer")
        print("2) Importer")
        print("q) Quitter")
        choix = input("> ")

        if choix == "1":
            generer()
        elif choix == "2":
            importer()
        elif choix == "q":
            break
        else:
            print("Choix invalide")

main()