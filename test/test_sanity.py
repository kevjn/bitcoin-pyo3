import bitcoin
import common

def test_ecc_mul():
    G1 = bitcoin.Point(
        x = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        y = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
    )

    G2 = common.Point(
        x = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        y = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
    )

    G1 = G1 * 1337
    G2 = G2 * 1337

    G1 = common.Point(G1.x, G1.y)
    assert G1 == G2

def test_encode_small_point():
    G1 = bitcoin.Point(
        x = 5,
        y = 6
    )

    G2 = common.Point(
        x = 5,
        y = 6
    )

    assert len(G1.encode()) == len(G2.encode())
    assert G1.encode() == G2.encode()

def test_encode_big_point():
    G1 = bitcoin.Point(
        x = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        y = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
    )

    G2 = common.Point(
        x = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        y = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
    )

    assert len(G1.encode()) == len(G2.encode())
    assert G1.encode() == G2.encode()


def test_generate_bitcoin_addr():
    secret_key = int.from_bytes(b'Hello world', 'big')
    # Generator point
    G = bitcoin.Point(
        x = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        y = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
    )
    public_key = G * secret_key

    # Generate our bitcoin address
    address = public_key.address()

    assert address == 'mtuFXC3oACRqVMMqN32L5VG7ZCbaE7aZxi'
