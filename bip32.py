import hashlib
import hmac
import unicodedata

# secp256k1
CURVE_P = 2**256 - 2**32 - 977
CURVE_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)

HARDENED = 2**31

XPRV_VERSION = bytes.fromhex("0488ADE4")
XPUB_VERSION = bytes.fromhex("0488B21E")

BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def point_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % CURVE_P == 0:
        return None

    if p == q:
        slope = 3 * p[0] * p[0] * pow(2 * p[1], -1, CURVE_P) % CURVE_P
    else:
        slope = (q[1] - p[1]) * pow(q[0] - p[0], -1, CURVE_P) % CURVE_P

    x = (slope * slope - p[0] - q[0]) % CURVE_P
    y = (slope * (p[0] - x) - p[1]) % CURVE_P
    return (x, y)


def point_mul(k, point=G):
    result = None

    while k:
        if k & 1:
            result = point_add(result, point)
        point = point_add(point, point)
        k >>= 1

    return result


def public_key(private_key):
    x, y = point_mul(int.from_bytes(private_key, "big"))
    return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")


def hash160(data):
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()


def base58check(payload):
    data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]

    number = int.from_bytes(data, "big")
    encoded = ""
    while number:
        number, rest = divmod(number, 58)
        encoded = BASE58[rest] + encoded

    leading_zeros = len(data) - len(data.lstrip(b"\x00"))
    return "1" * leading_zeros + encoded


class ExtendedKey:
    def __init__(self, key, chain_code, depth=0, parent_fingerprint=b"\x00" * 4, child_number=0):
        self.key = key
        self.chain_code = chain_code
        self.depth = depth
        self.parent_fingerprint = parent_fingerprint
        self.child_number = child_number

    def public_key(self):
        return public_key(self.key)

    def fingerprint(self):
        return hash160(self.public_key())[:4]

    def serialize(self, private):
        version = XPRV_VERSION if private else XPUB_VERSION
        key = b"\x00" + self.key if private else self.public_key()

        return base58check(
            version
            + bytes([self.depth])
            + self.parent_fingerprint
            + self.child_number.to_bytes(4, "big")
            + self.chain_code
            + key
        )

    def xprv(self):
        return self.serialize(private=True)

    def xpub(self):
        return self.serialize(private=False)

    def child(self, index):
        if index >= HARDENED:
            data = b"\x00" + self.key + index.to_bytes(4, "big")
        else:
            data = self.public_key() + index.to_bytes(4, "big")

        digest = hmac.new(self.chain_code, data, hashlib.sha512).digest()
        offset = int.from_bytes(digest[:32], "big")
        child_key = (offset + int.from_bytes(self.key, "big")) % CURVE_N

        if offset >= CURVE_N or child_key == 0:
            raise ValueError(f"index {index} is invalid, use the next one")

        return ExtendedKey(
            child_key.to_bytes(32, "big"),
            digest[32:],
            self.depth + 1,
            self.fingerprint(),
            index,
        )


def seed_from_mnemonic(words, passphrase=""):
    sentence = unicodedata.normalize("NFKD", " ".join(words))
    salt = unicodedata.normalize("NFKD", "mnemonic" + passphrase)

    return hashlib.pbkdf2_hmac("sha512", sentence.encode(), salt.encode(), 2048)


def master_key(seed):
    digest = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    return ExtendedKey(digest[:32], digest[32:])


def parse_path(path):
    parts = path.strip().split("/")

    if parts[0] in ("m", "M"):
        parts = parts[1:]

    indexes = []
    for part in parts:
        if part.endswith(("'", "h", "H")):
            indexes.append(int(part[:-1]) + HARDENED)
        else:
            indexes.append(int(part))

    return indexes


def derive(seed, path):
    key = master_key(seed)

    for index in parse_path(path):
        key = key.child(index)

    return key
